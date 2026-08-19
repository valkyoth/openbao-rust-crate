//! System backend helpers.

use core::{fmt, marker::PhantomData};
#[cfg(feature = "monitor-stream")]
use core::{
    pin::Pin,
    task::{Context, Poll},
};
use std::collections::BTreeMap;
#[cfg(feature = "dev-bootstrap")]
use std::net::IpAddr;

#[cfg(any(feature = "monitor-stream", feature = "raft-stream"))]
use bytes::Bytes;
#[cfg(any(feature = "monitor-stream", feature = "raft-stream"))]
use futures_core::Stream;

use reqwest::{
    Method, StatusCode, Url,
    header::{CONTENT_TYPE, HeaderName, HeaderValue},
};
use sanitization::SecretVec;
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, Error as DeError, IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser::Error as SerError,
};
use serde_json::value::RawValue;

use crate::{
    Authenticated, Client, Error, JsonValue, Result, Unauthenticated,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        BoundedJsonValue, Empty, ListEntries, MAX_RESPONSE_STRINGS, ResponseEnvelope, WrapInfo,
        deserialize_bounded_secret_string_vec, deserialize_bounded_string_map,
        deserialize_bounded_string_map_or_default, deserialize_bounded_string_vec,
        deserialize_optional_bounded_string_map, deserialize_optional_bounded_string_vec,
    },
};

const MAX_SYS_RANDOM_BYTES: u64 = 1_048_576;
const MAX_WORKFLOW_DEFINITION_BYTES: usize = 1024 * 1024;
const MAX_WORKFLOW_DATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_RAFT_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(feature = "monitor-stream")]
const DEFAULT_MONITOR_FRAME_BYTES: usize = 64 * 1024;
#[cfg(feature = "monitor-stream")]
const MAX_MONITOR_FRAME_BYTES: usize = 1024 * 1024;
#[cfg(feature = "monitor-stream")]
const MAX_MONITOR_TRANSPORT_CHUNK_BYTES: usize = 1024 * 1024;
#[cfg(feature = "monitor-stream")]
const MAX_MONITOR_CHUNKS_PER_POLL: usize = 64;
#[cfg(feature = "operator-ops")]
const MAX_SYS_PPROF_SECONDS: u16 = 300;
#[cfg(feature = "operator-ops")]
const MAX_NAMESPACE_KEY_SHARES: usize = 255;
#[cfg(feature = "operator-ops")]
const MAX_NAMESPACE_PGP_KEY_BYTES: usize = 64 * 1024;
#[cfg(feature = "operator-ops")]
const MAX_NAMESPACE_KEY_SHARE_BYTES: usize = 64 * 1024;
#[cfg(feature = "operator-ops")]
const MAX_NAMESPACE_UNSEAL_KEY_BYTES: usize = 4096;

/// System backend handle.
#[derive(Debug)]
pub struct Sys<'a, State> {
    client: &'a Client<State>,
}

/// Minimum OpenBao log severity included by [`Sys::monitor`].
#[cfg(feature = "monitor-stream")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum MonitorLogLevel {
    /// Trace, debug, informational, warning, and error messages.
    Trace,
    /// Debug, informational, warning, and error messages.
    Debug,
    /// Informational, warning, and error messages.
    #[default]
    Info,
    /// Warning and error messages.
    Warn,
    /// Error messages only.
    Error,
}

#[cfg(feature = "monitor-stream")]
impl MonitorLogLevel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Wire format returned by [`Sys::monitor`].
#[cfg(feature = "monitor-stream")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum MonitorLogFormat {
    /// OpenBao's human-readable standard log format.
    #[default]
    Standard,
    /// One server-controlled JSON value per frame.
    Json,
}

#[cfg(feature = "monitor-stream")]
impl MonitorLogFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Json => "json",
        }
    }
}

/// Bounded options for the OpenBao system-log monitor stream.
#[cfg(feature = "monitor-stream")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorOptions {
    log_level: MonitorLogLevel,
    log_format: MonitorLogFormat,
    max_frame_bytes: usize,
}

#[cfg(feature = "monitor-stream")]
impl Default for MonitorOptions {
    fn default() -> Self {
        Self {
            log_level: MonitorLogLevel::Info,
            log_format: MonitorLogFormat::Standard,
            max_frame_bytes: DEFAULT_MONITOR_FRAME_BYTES,
        }
    }
}

#[cfg(feature = "monitor-stream")]
impl MonitorOptions {
    /// Selects the minimum emitted log severity.
    #[must_use]
    pub const fn with_log_level(mut self, log_level: MonitorLogLevel) -> Self {
        self.log_level = log_level;
        self
    }

    /// Selects standard text or JSON log frames.
    #[must_use]
    pub const fn with_log_format(mut self, log_format: MonitorLogFormat) -> Self {
        self.log_format = log_format;
        self
    }

    /// Sets the per-frame byte limit.
    ///
    /// The accepted range is 1 byte through 1 MiB. This limit applies before
    /// callers inspect or decode the server-controlled frame.
    pub fn with_max_frame_bytes(mut self, max_frame_bytes: usize) -> Result<Self> {
        if !(1..=MAX_MONITOR_FRAME_BYTES).contains(&max_frame_bytes) {
            return Err(Error::InvalidParameter(
                "monitor frame limit must be between 1 byte and 1 MiB".into(),
            ));
        }
        self.max_frame_bytes = max_frame_bytes;
        Ok(self)
    }
}

/// One bounded, sanitizing OpenBao monitor frame.
///
/// Frame contents are operationally sensitive and are therefore omitted from
/// `Debug`. The bytes exclude the trailing line-feed delimiter. JSON frames
/// remain raw bytes so this crate does not allocate an attacker-selected JSON
/// object graph or assume that server log data is trustworthy.
#[cfg(feature = "monitor-stream")]
pub struct MonitorFrame {
    format: MonitorLogFormat,
    contents: SecretVec,
}

#[cfg(feature = "monitor-stream")]
impl MonitorFrame {
    /// Returns the selected wire format.
    #[must_use]
    pub const fn format(&self) -> MonitorLogFormat {
        self.format
    }

    /// Returns the frame length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.contents.len()
    }

    /// Returns whether this frame is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    /// Inspects the bounded frame bytes without making another plaintext copy.
    pub fn with_bytes<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> R {
        self.contents.with_secret(inspect)
    }

    /// Inspects a UTF-8 frame without retaining invalid bytes in the error.
    pub fn with_str<R>(&self, inspect: impl FnOnce(&str) -> R) -> Result<R> {
        self.contents.with_secret(|bytes| {
            let text = core::str::from_utf8(bytes)
                .map_err(|_| Error::Decode("OpenBao monitor frame is not valid UTF-8".into()))?;
            Ok(inspect(text))
        })
    }
}

#[cfg(feature = "monitor-stream")]
impl fmt::Debug for MonitorFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonitorFrame")
            .field("format", &self.format)
            .field("len", &self.contents.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

/// Lazy, bounded stream returned by [`Sys::monitor`].
///
/// The HTTP body is polled only when the consumer polls this stream. No
/// producer task or queue is created, so a slow consumer applies back-pressure
/// directly to the transport. Dropping the stream drops the response body and
/// cancels the request.
#[cfg(feature = "monitor-stream")]
pub struct MonitorStream {
    body: Pin<Box<dyn Stream<Item = core::result::Result<Bytes, reqwest::Error>> + Send>>,
    chunk: Option<Bytes>,
    chunk_offset: usize,
    pending: SecretVec,
    format: MonitorLogFormat,
    max_frame_bytes: usize,
    terminal: bool,
}

#[cfg(feature = "monitor-stream")]
impl fmt::Debug for MonitorStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonitorStream")
            .field("format", &self.format)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .field("buffered_bytes", &self.pending.len())
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "monitor-stream")]
impl MonitorStream {
    fn new(response: reqwest::Response, options: MonitorOptions) -> Self {
        Self {
            body: Box::pin(response.bytes_stream()),
            chunk: None,
            chunk_offset: 0,
            // Allocate the declared public bound once. SecretVec then never
            // needs a geometric growth allocation that could exceed it.
            pending: SecretVec::with_capacity(options.max_frame_bytes),
            format: options.log_format,
            max_frame_bytes: options.max_frame_bytes,
            terminal: false,
        }
    }

    fn finish_frame(&mut self, suffix: &[u8]) -> MonitorFrame {
        let mut contents = SecretVec::with_capacity(self.pending.len() + suffix.len());
        self.pending
            .with_secret(|pending| contents.extend_from_slice(pending));
        contents.extend_from_slice(suffix);
        self.pending.clear_secret();
        MonitorFrame {
            format: self.format,
            contents,
        }
    }

    fn frame_too_large(&mut self) -> Poll<Option<Result<MonitorFrame>>> {
        self.terminal = true;
        self.chunk = None;
        self.pending.clear_secret();
        Poll::Ready(Some(Err(Error::Decode(
            "OpenBao monitor frame exceeds configured limit".into(),
        ))))
    }
}

#[cfg(feature = "monitor-stream")]
impl Stream for MonitorStream {
    type Item = Result<MonitorFrame>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.terminal {
            return Poll::Ready(None);
        }

        let mut chunks_polled = 0_usize;
        loop {
            if let Some(chunk) = this.chunk.take() {
                let remaining = &chunk[this.chunk_offset..];
                if let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') {
                    if this.pending.len().saturating_add(newline) > this.max_frame_bytes {
                        return this.frame_too_large();
                    }
                    let frame = this.finish_frame(&remaining[..newline]);
                    this.chunk_offset += newline + 1;
                    if this.chunk_offset < chunk.len() {
                        this.chunk = Some(chunk);
                    } else {
                        this.chunk_offset = 0;
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                if this.pending.len().saturating_add(remaining.len()) > this.max_frame_bytes {
                    return this.frame_too_large();
                }
                this.pending.extend_from_slice(remaining);
                this.chunk_offset = 0;
            }

            if chunks_polled >= MAX_MONITOR_CHUNKS_PER_POLL {
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            chunks_polled += 1;

            match this.body.as_mut().poll_next(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) if chunk.is_empty() => {}
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.len() > MAX_MONITOR_TRANSPORT_CHUNK_BYTES {
                        this.terminal = true;
                        this.pending.clear_secret();
                        return Poll::Ready(Some(Err(Error::Decode(
                            "OpenBao monitor transport chunk exceeds internal limit".into(),
                        ))));
                    }
                    this.chunk = Some(chunk);
                }
                Poll::Ready(Some(Err(error))) => {
                    this.terminal = true;
                    return Poll::Ready(Some(Err(crate::error::http_transport_error(error))));
                }
                Poll::Ready(None) => {
                    this.terminal = true;
                    if this.pending.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(this.finish_frame(&[]))));
                }
            }
        }
    }
}

/// OpenBao health response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Health {
    /// Whether the node is initialized.
    pub initialized: bool,
    /// Whether the node is sealed.
    pub sealed: bool,
    /// Whether the node is standby.
    #[serde(default)]
    pub standby: bool,
    /// Server version.
    pub version: String,
    /// Cluster name.
    #[serde(default)]
    pub cluster_name: Option<String>,
    /// Cluster identifier.
    #[serde(default)]
    pub cluster_id: Option<String>,
}

/// OpenBao initialization status returned by `/sys/init`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct InitStatus {
    /// Whether the node has already been initialized.
    pub initialized: bool,
}

/// High Availability leader status returned by `/sys/leader`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LeaderStatus {
    /// Whether HA mode is enabled.
    #[serde(default)]
    pub ha_enabled: bool,
    /// Whether this node is the active leader.
    #[serde(default)]
    pub is_self: bool,
    /// Active leader API address.
    #[serde(default)]
    pub leader_address: Option<String>,
    /// Active leader cluster address.
    #[serde(default)]
    pub leader_cluster_address: Option<String>,
    /// Whether this node is a performance standby.
    #[serde(default)]
    pub performance_standby: bool,
    /// Last remote WAL observed by a performance standby.
    #[serde(default)]
    pub performance_standby_last_remote_wal: Option<u64>,
}

/// HA cluster status returned by `/sys/ha-status`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HaStatus {
    /// Known HA nodes.
    #[serde(
        default,
        alias = "Nodes",
        deserialize_with = "deserialize_bounded_ha_node_vec"
    )]
    pub nodes: Vec<HaNode>,
}

/// One node in HA status output.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HaNode {
    /// Node hostname.
    #[serde(default)]
    pub hostname: String,
    /// API address advertised by this node.
    #[serde(default)]
    pub api_address: String,
    /// Cluster address advertised by this node.
    #[serde(default)]
    pub cluster_address: String,
    /// Whether this node is active.
    #[serde(default)]
    pub active_node: bool,
    /// Last echo timestamp, when known.
    #[serde(default)]
    pub last_echo: Option<String>,
    /// OpenBao version running on the node.
    #[serde(default)]
    pub version: String,
}

/// Barrier encryption key status returned by `/sys/key-status`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KeyStatus {
    /// Sequential barrier key number.
    #[serde(default)]
    pub term: u64,
    /// Time the current barrier key was installed.
    #[serde(default)]
    pub install_time: Option<String>,
    /// Estimated encryptions performed with the current barrier key.
    #[serde(default)]
    pub encryptions: u64,
}

/// Raw storage value encoding for `/sys/raw`.
///
/// Raw storage APIs are available only with `operator-ops`. OpenBao documents
/// `/sys/raw` as disabled by default and as addressing the underlying storage
/// backend path rather than logical secret paths.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub enum RawEncoding {
    /// Do not ask OpenBao to encode or decode the raw value.
    #[default]
    #[serde(rename = "")]
    None,
    /// Ask OpenBao to use standard base64 text for the raw value.
    #[serde(rename = "base64")]
    Base64,
}

#[cfg(feature = "operator-ops")]
impl RawEncoding {
    fn as_query_value(self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Base64 => Some("base64".to_owned()),
        }
    }

    fn is_none(value: &Self) -> bool {
        matches!(value, Self::None)
    }
}

/// Raw storage write compression mode for `/sys/raw`.
///
/// `None` serializes to an empty string, which asks OpenBao to write without
/// compression. Leave the request field unset to let OpenBao keep the existing
/// key's compression behavior where the server supports that.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RawCompression {
    /// Explicitly write without compression.
    #[serde(rename = "")]
    None,
    /// Ask OpenBao to gzip-compress the stored value.
    #[serde(rename = "gzip")]
    Gzip,
    /// Ask OpenBao to snappy-compress the stored value.
    #[serde(rename = "snappy")]
    Snappy,
}

/// Read options for `/sys/raw/:path`.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawReadOptions {
    /// Whether OpenBao should attempt to decompress the returned value.
    pub compressed: bool,
    /// Optional value encoding requested from OpenBao.
    pub encoding: RawEncoding,
}

#[cfg(feature = "operator-ops")]
impl Default for RawReadOptions {
    fn default() -> Self {
        Self {
            compressed: true,
            encoding: RawEncoding::None,
        }
    }
}

#[cfg(feature = "operator-ops")]
impl RawReadOptions {
    /// Creates default raw read options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Controls OpenBao's server-side decompression attempt.
    #[must_use]
    pub fn with_compressed(mut self, compressed: bool) -> Self {
        self.compressed = compressed;
        self
    }

    /// Requests a specific response value encoding.
    #[must_use]
    pub fn with_encoding(mut self, encoding: RawEncoding) -> Self {
        self.encoding = encoding;
        self
    }
}

/// Raw storage write request for `/sys/raw/:path`.
#[cfg(feature = "operator-ops")]
#[derive(Clone)]
pub struct RawWriteRequest {
    /// Raw value to write. Treat as sensitive storage material.
    pub value: SecretString,
    /// Optional compression mode for the stored value.
    pub compression_type: Option<RawCompression>,
    /// Optional value encoding.
    pub encoding: RawEncoding,
}

#[cfg(feature = "operator-ops")]
impl RawWriteRequest {
    /// Creates a raw write request with the required value.
    #[must_use]
    pub fn new(value: SecretString) -> Self {
        Self {
            value,
            compression_type: None,
            encoding: RawEncoding::None,
        }
    }

    /// Sets the storage compression behavior.
    #[must_use]
    pub fn with_compression(mut self, compression: RawCompression) -> Self {
        self.compression_type = Some(compression);
        self
    }

    /// Sets the value encoding used for the request.
    #[must_use]
    pub fn with_encoding(mut self, encoding: RawEncoding) -> Self {
        self.encoding = encoding;
        self
    }
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for RawWriteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawWriteRequest")
            .field("value", &"<redacted>")
            .field("compression_type", &self.compression_type)
            .field("encoding", &self.encoding)
            .finish()
    }
}

/// Raw storage value returned by `/sys/raw/:path`.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct RawReadResponse {
    /// Raw value returned by OpenBao. Treat as sensitive storage material.
    pub value: SecretString,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for RawReadResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawReadResponse")
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Raw storage key list returned by `/sys/raw/:prefix?list=true`.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RawList {
    /// Raw storage keys under the requested prefix.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// Runtime profile exposed by `/sys/pprof`.
///
/// Pprof helpers are available only with `operator-ops`. Profile payloads can
/// contain stack traces, command-line arguments, or other diagnostic material,
/// so they are returned as sanitizing byte buffers instead of strings.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PprofProfile {
    /// Historical allocation profile from `/sys/pprof/allocs`.
    Allocs,
    /// Blocking profile from `/sys/pprof/block`.
    Block,
    /// Process command line from `/sys/pprof/cmdline`.
    Cmdline,
    /// Current goroutine profile from `/sys/pprof/goroutine`.
    Goroutine,
    /// Live heap profile from `/sys/pprof/heap`.
    Heap,
    /// Mutex profile from `/sys/pprof/mutex`.
    Mutex,
    /// CPU profile from `/sys/pprof/profile`.
    Profile,
    /// Program counter symbol lookup from `/sys/pprof/symbol`.
    Symbol,
    /// Thread creation profile from `/sys/pprof/threadcreate`.
    Threadcreate,
    /// Execution trace from `/sys/pprof/trace`.
    Trace,
}

#[cfg(feature = "operator-ops")]
impl PprofProfile {
    fn as_path_segment(self) -> &'static str {
        match self {
            Self::Allocs => "allocs",
            Self::Block => "block",
            Self::Cmdline => "cmdline",
            Self::Goroutine => "goroutine",
            Self::Heap => "heap",
            Self::Mutex => "mutex",
            Self::Profile => "profile",
            Self::Symbol => "symbol",
            Self::Threadcreate => "threadcreate",
            Self::Trace => "trace",
        }
    }
}

/// Query options for `/sys/pprof`.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PprofOptions {
    /// Collection duration for [`PprofProfile::Profile`] and [`PprofProfile::Trace`].
    ///
    /// Values must be between 1 and 300 seconds when set. Leave unset to use
    /// OpenBao's endpoint default.
    pub seconds: Option<u16>,
    /// Debug output mode for [`PprofProfile::Goroutine`].
    ///
    /// OpenBao documents `2` as text stack trace output. Values above `2` are
    /// rejected locally.
    pub debug: Option<u8>,
}

#[cfg(feature = "operator-ops")]
impl PprofOptions {
    /// Creates default pprof query options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the profiling or trace collection duration in seconds.
    #[must_use]
    pub fn with_seconds(mut self, seconds: u16) -> Self {
        self.seconds = Some(seconds);
        self
    }

    /// Sets the goroutine debug output mode.
    #[must_use]
    pub fn with_debug(mut self, debug: u8) -> Self {
        self.debug = Some(debug);
        self
    }
}

/// CORS configuration returned by `/sys/config/cors`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CorsConfig {
    /// Whether CORS configuration is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Origins allowed to make cross-origin requests.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub allowed_origins: Vec<String>,
    /// Additional headers allowed on cross-origin requests.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub allowed_headers: Vec<String>,
}

/// CORS configuration including fields introduced by OpenBao 2.6.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct CorsConfigDetails {
    /// Configuration available across supported OpenBao releases.
    #[serde(flatten)]
    pub config: CorsConfig,
    /// Whether cross-origin requests may include credentials.
    #[serde(default)]
    pub allow_credentials: bool,
}

/// Request for configuring `/sys/config/cors`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CorsConfigRequest {
    /// Origins allowed to make cross-origin requests.
    pub allowed_origins: Vec<String>,
    /// Additional headers allowed on cross-origin requests.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_headers: Vec<String>,
}

#[derive(Serialize)]
struct CorsConfigRequestWithCredentials<'a> {
    #[serde(flatten)]
    request: &'a CorsConfigRequest,
    allow_credentials: bool,
}

impl CorsConfigRequest {
    /// Creates a CORS request with the required allowed origins.
    #[must_use]
    pub fn new<I, S>(allowed_origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed_origins: allowed_origins.into_iter().map(Into::into).collect(),
            allowed_headers: Vec::new(),
        }
    }

    /// Adds one allowed header name.
    #[must_use]
    pub fn with_allowed_header(mut self, header: impl Into<String>) -> Self {
        self.allowed_headers.push(header.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_cors_origins(&self.allowed_origins)?;
        validate_http_header_names(&self.allowed_headers, "CORS allowed header")?;
        Ok(())
    }
}

/// Namespaces returned by `/sys/internal/ui/namespaces`.
///
/// OpenBao documents this endpoint as internal UI support without backwards
/// compatibility guarantees.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UiNamespaces {
    /// Namespaces relevant to the UI.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub namespaces: Vec<String>,
}

/// Enabled UI feature flags returned by OpenBao through `2.4.4`.
///
/// `/sys/internal/ui/feature-flags` was removed in OpenBao `2.5.0`. The
/// version-aware dispatcher rejects this helper locally for newer profiles.
#[cfg(feature = "unstable-internal-ops")]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UiFeatureFlags {
    /// Enabled internal UI feature identifiers.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub feature_flags: Vec<String>,
}

/// Visible mounts returned by `/sys/internal/ui/mounts`.
///
/// OpenBao documents this endpoint as internal UI and CLI preflight support
/// without backwards compatibility guarantees.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UiMounts {
    /// Visible auth method mounts.
    #[serde(default, deserialize_with = "deserialize_bounded_ui_mount_summary_map")]
    pub auth: BTreeMap<String, UiMountSummary>,
    /// Visible secrets engine mounts.
    #[serde(default, deserialize_with = "deserialize_bounded_ui_mount_summary_map")]
    pub secret: BTreeMap<String, UiMountSummary>,
}

/// Summary for one UI-visible mount.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UiMountSummary {
    /// Mount description.
    #[serde(default)]
    pub description: Option<String>,
    /// Backend type, such as `kv`, `pki`, or `github`.
    #[serde(default, rename = "type")]
    pub backend_type: String,
    /// Mount options, when returned.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_map")]
    pub options: Option<BTreeMap<String, String>>,
}

/// Single UI mount details returned by `/sys/internal/ui/mounts/:path`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UiMountDetails {
    /// Mount accessor, when returned. Treat as sensitive metadata.
    #[serde(default)]
    pub accessor: Option<SecretString>,
    /// Backend configuration.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub config: MountConfig,
    /// Human-readable mount description.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether external entropy access is enabled.
    #[serde(default)]
    pub external_entropy_access: bool,
    /// Whether this mount is local to the node.
    #[serde(default)]
    pub local: bool,
    /// Mount options, when returned.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_map")]
    pub options: Option<BTreeMap<String, String>>,
    /// Mount path returned by OpenBao.
    #[serde(default)]
    pub path: String,
    /// Whether this mount is seal wrapped.
    #[serde(default)]
    pub seal_wrap: bool,
    /// Backend type, such as `kv`, `pki`, or `github`.
    #[serde(default, rename = "type")]
    pub backend_type: String,
    /// Mount UUID.
    #[serde(default)]
    pub uuid: Option<String>,
}

/// Runtime logger verbosity accepted by `/sys/loggers`.
///
/// OpenBao documents these changes as transient: they are not persisted and
/// revert to configured log levels when the service reloads or restarts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoggerLevel {
    /// Most verbose logging.
    Trace,
    /// Debug logging.
    Debug,
    /// Informational logging.
    Info,
    /// Warning logging.
    Warn,
    /// Error logging.
    Error,
}

impl LoggerLevel {
    /// Returns the OpenBao logger level value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Logger levels keyed by logger name.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LoggerLevels(
    #[serde(deserialize_with = "deserialize_bounded_logger_level_map")] BTreeMap<String, String>,
);

impl LoggerLevels {
    /// Returns the logger level by logger name.
    #[must_use]
    pub fn get(&self, logger: &str) -> Option<&str> {
        self.0.get(logger).map(String::as_str)
    }

    /// Returns all logger levels.
    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Consumes this wrapper and returns the logger map.
    #[must_use]
    pub fn into_inner(self) -> BTreeMap<String, String> {
        self.0
    }
}

/// OpenBao entropy source accepted by `/sys/tools/random`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SysRandomSource {
    /// Use the platform entropy source.
    Platform,
    /// Mix bytes from all available OpenBao entropy sources.
    All,
}

impl SysRandomSource {
    /// Returns the OpenBao path segment for this random source.
    #[must_use]
    pub const fn as_path_segment(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::All => "all",
        }
    }
}

/// Output encoding accepted by `/sys/tools/random` and `/sys/tools/hash`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum SysToolsOutputFormat {
    /// Hexadecimal output.
    #[serde(rename = "hex")]
    Hex,
    /// Base64 output.
    #[serde(rename = "base64")]
    Base64,
}

/// Hash algorithm accepted by `/sys/tools/hash`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SysHashAlgorithm {
    /// SHA2-224.
    Sha2_224,
    /// SHA2-256.
    Sha2_256,
    /// SHA2-384.
    Sha2_384,
    /// SHA2-512.
    Sha2_512,
    /// SHA3-224. Not FIPS-certified in OpenBao FIPS mode.
    Sha3_224,
    /// SHA3-256. Not FIPS-certified in OpenBao FIPS mode.
    Sha3_256,
    /// SHA3-384. Not FIPS-certified in OpenBao FIPS mode.
    Sha3_384,
    /// SHA3-512. Not FIPS-certified in OpenBao FIPS mode.
    Sha3_512,
}

impl SysHashAlgorithm {
    /// Returns the OpenBao path segment for this hash algorithm.
    #[must_use]
    pub const fn as_path_segment(self) -> &'static str {
        match self {
            Self::Sha2_224 => "sha2-224",
            Self::Sha2_256 => "sha2-256",
            Self::Sha2_384 => "sha2-384",
            Self::Sha2_512 => "sha2-512",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
        }
    }
}

/// Request for `/sys/tools/random`.
#[derive(Clone, Debug, Default)]
pub struct SysRandomRequest {
    /// Number of random bytes to return. OpenBao defaults to 32 when omitted.
    pub bytes: Option<u64>,
    /// Output encoding. OpenBao defaults to base64 when omitted.
    pub format: Option<SysToolsOutputFormat>,
}

impl SysRandomRequest {
    /// Creates a request that uses OpenBao's default byte count and format.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests an explicit byte count.
    ///
    /// The client rejects zero and unusually large values before dispatch.
    #[must_use]
    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }

    /// Requests a specific output encoding.
    #[must_use]
    pub fn with_format(mut self, format: SysToolsOutputFormat) -> Self {
        self.format = Some(format);
        self
    }

    fn validate(&self) -> Result<()> {
        if let Some(bytes) = self.bytes {
            validate_sys_random_bytes(bytes)?;
        }
        Ok(())
    }
}

/// Random bytes returned by `/sys/tools/random`.
#[derive(Clone, Deserialize)]
pub struct SysRandomResponse {
    /// Random bytes in the requested encoding.
    pub random_bytes: SecretString,
}

impl fmt::Debug for SysRandomResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SysRandomResponse")
            .field("random_bytes", &"<redacted>")
            .finish()
    }
}

impl SysRandomResponse {
    /// Decodes base64 random bytes returned with `SysToolsOutputFormat::Base64`.
    #[cfg(feature = "transit-bytes")]
    pub fn random_bytes(&self) -> Result<SecretVec> {
        decode_sys_base64_secret(&self.random_bytes)
    }
}

/// Request for `/sys/tools/hash`.
#[derive(Clone)]
pub struct SysHashRequest {
    /// Base64-encoded input data to hash.
    pub input: SecretString,
    /// Output encoding. OpenBao defaults to hex when omitted.
    pub format: Option<SysToolsOutputFormat>,
}

impl fmt::Debug for SysHashRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SysHashRequest")
            .field("input", &"<redacted>")
            .field("format", &self.format)
            .finish()
    }
}

impl SysHashRequest {
    /// Creates a hash request from base64-encoded input.
    #[must_use]
    pub fn from_base64_input(input: SecretString) -> Self {
        Self {
            input,
            format: None,
        }
    }

    /// Creates a hash request from raw input bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn from_input_bytes(input: &[u8]) -> Result<Self> {
        Ok(Self {
            input: encode_sys_base64_secret(input)?,
            format: None,
        })
    }

    /// Requests a specific output encoding.
    #[must_use]
    pub fn with_format(mut self, format: SysToolsOutputFormat) -> Self {
        self.format = Some(format);
        self
    }
}

/// Hash output returned by `/sys/tools/hash`.
#[derive(Clone, Deserialize)]
pub struct SysHashResponse {
    /// Digest in the requested encoding.
    pub sum: SecretString,
}

impl fmt::Debug for SysHashResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SysHashResponse")
            .field("sum", &"<redacted>")
            .finish()
    }
}

impl SysHashResponse {
    /// Decodes base64 output returned with `SysToolsOutputFormat::Base64`.
    #[cfg(feature = "transit-bytes")]
    pub fn sum_bytes(&self) -> Result<SecretVec> {
        decode_sys_base64_secret(&self.sum)
    }
}

/// Installed OpenBao version history.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VersionHistory {
    /// Installed versions in chronological order.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Version metadata keyed by version string.
    #[serde(default, deserialize_with = "deserialize_bounded_version_history_map")]
    pub key_info: BTreeMap<String, VersionHistoryEntry>,
}

impl ListEntries for VersionHistory {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Metadata for one installed OpenBao version.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VersionHistoryEntry {
    /// Build timestamp, when OpenBao returned one.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub build_date: Option<String>,
    /// Previous installed version, when known.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub previous_version: Option<String>,
    /// Installation timestamp.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub timestamp_installed: Option<String>,
}

/// Installed-version metadata including fields introduced by OpenBao 2.6.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct VersionHistoryEntryDetails {
    /// Metadata available across supported OpenBao releases.
    #[serde(flatten)]
    pub entry: VersionHistoryEntry,
    /// Source commit timestamp.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub commit_date: Option<String>,
}

/// Version history with OpenBao 2.6 metadata.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct VersionHistoryDetails {
    /// Installed version strings.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Detailed version metadata keyed by version string.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_version_history_details_map"
    )]
    pub key_info: BTreeMap<String, VersionHistoryEntryDetails>,
}

impl ListEntries for VersionHistoryDetails {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Namespace metadata returned by `/sys/namespaces`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NamespaceInfo {
    /// Namespace identifier.
    #[serde(default, deserialize_with = "deserialize_safe_metadata_string")]
    pub id: String,
    /// Namespace path.
    #[serde(default, deserialize_with = "deserialize_safe_metadata_string")]
    pub path: String,
    /// Caller-defined namespace metadata.
    #[serde(default, deserialize_with = "deserialize_bounded_safe_metadata_map")]
    pub custom_metadata: BTreeMap<String, String>,
}

/// Namespace list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NamespaceList {
    /// Namespace paths returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Namespace metadata keyed by namespace path.
    #[serde(default, deserialize_with = "deserialize_bounded_namespace_info_map")]
    pub key_info: BTreeMap<String, NamespaceInfo>,
}

impl ListEntries for NamespaceList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request body for namespace create and patch operations.
#[derive(Clone, Debug, Default, Serialize)]
pub struct NamespaceRequest {
    /// Caller-defined namespace metadata.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub custom_metadata: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct NamespaceClearMetadataRequest {
    custom_metadata: Option<BTreeMap<String, String>>,
}

#[cfg(feature = "operator-ops")]
#[derive(Serialize)]
struct SealableNamespacePayload<'a> {
    custom_metadata: &'a BTreeMap<String, String>,
    seal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pgp_keys: Option<&'a [String]>,
}

#[cfg(feature = "operator-ops")]
#[derive(Serialize)]
struct NamespaceUnsealPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reset: Option<bool>,
}

#[cfg(feature = "operator-ops")]
#[derive(Deserialize)]
struct OptionalSealedNamespaceDeletionEnvelope {
    #[serde(default)]
    data: Option<SealedNamespaceDeletionStatus>,
}

impl NamespaceRequest {
    /// Creates an empty namespace request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one metadata entry.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_metadata.insert(key.into(), value.into());
        self
    }
}

/// Request for creating a Shamir-sealed namespace.
///
/// Available only with `operator-ops` and `operator-ops-acknowledged` because
/// a successful response returns the namespace's unseal shares. Sealable
/// namespaces are supported by OpenBao 2.6.0 and newer exact profiles.
#[cfg(feature = "operator-ops")]
#[derive(Clone)]
pub struct SealableNamespaceRequest {
    key_shares: u8,
    key_threshold: u8,
    pgp_keys: Vec<String>,
    custom_metadata: BTreeMap<String, String>,
}

#[cfg(feature = "operator-ops")]
impl SealableNamespaceRequest {
    /// Creates a validated Shamir seal configuration.
    pub fn new(key_shares: u8, key_threshold: u8) -> Result<Self> {
        validate_namespace_key_share_options(key_shares, key_threshold)?;
        Ok(Self {
            key_shares,
            key_threshold,
            pgp_keys: Vec::new(),
            custom_metadata: BTreeMap::new(),
        })
    }

    /// Adds one validated caller-defined namespace metadata entry.
    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self> {
        self.custom_metadata.insert(key.into(), value.into());
        validate_namespace_metadata(&self.custom_metadata)?;
        Ok(self)
    }

    /// Configures base64-encoded OpenPGP public keys for encrypting shares.
    ///
    /// The number of keys must equal `key_shares`. OpenBao returns encrypted
    /// shares when these keys are supplied; the returned values remain secret
    /// operator material even though the input keys are public.
    pub fn with_pgp_keys<I, S>(mut self, keys: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut collected = Vec::new();
        for key in keys {
            if collected.len() >= MAX_NAMESPACE_KEY_SHARES {
                return Err(Error::InvalidParameter(
                    "namespace PGP key list exceeds maximum share count".into(),
                ));
            }
            collected.push(key.into());
        }
        self.pgp_keys = collected;
        validate_sealable_namespace_request(&self)?;
        Ok(self)
    }

    fn seal_document(&self) -> String {
        format!(
            "seal \"shamir\" {{ shares = {} threshold = {} }}",
            self.key_shares, self.key_threshold
        )
    }
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for SealableNamespaceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealableNamespaceRequest")
            .field("key_shares", &self.key_shares)
            .field("key_threshold", &self.key_threshold)
            .field("pgp_keys_count", &self.pgp_keys.len())
            .field("custom_metadata_count", &self.custom_metadata.len())
            .finish()
    }
}

/// Result of creating a Shamir-sealed namespace.
///
/// `key_shares` are the only material capable of unsealing the namespace and
/// must be transferred immediately to separate operator custody.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct SealableNamespaceCreation {
    /// Internal namespace UUID.
    #[serde(default, deserialize_with = "deserialize_safe_metadata_string")]
    pub uuid: String,
    /// Namespace accessor identifier.
    #[serde(default, deserialize_with = "deserialize_safe_metadata_string")]
    pub id: String,
    /// Fully qualified namespace path.
    #[serde(default, deserialize_with = "deserialize_safe_metadata_string")]
    pub path: String,
    /// Whether namespace deletion is in progress.
    #[serde(default)]
    pub tainted: bool,
    /// Whether the namespace API lock is active.
    #[serde(default)]
    pub locked: bool,
    /// Caller-defined metadata returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_safe_metadata_map")]
    pub custom_metadata: BTreeMap<String, String>,
    /// Generated unseal shares. Treat as highly sensitive operator material.
    #[serde(deserialize_with = "deserialize_namespace_key_shares")]
    pub key_shares: Vec<SecretString>,
    /// Number of shares required to unseal the namespace.
    pub key_threshold: u8,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for SealableNamespaceCreation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealableNamespaceCreation")
            .field("uuid", &self.uuid)
            .field("id", &self.id)
            .field("path", &self.path)
            .field("tainted", &self.tainted)
            .field("locked", &self.locked)
            .field("custom_metadata_count", &self.custom_metadata.len())
            .field("key_shares_count", &self.key_shares.len())
            .field("key_threshold", &self.key_threshold)
            .finish()
    }
}

/// Seal status for one OpenBao 2.6+ sealable namespace.
#[derive(Clone, Debug, Deserialize)]
pub struct NamespaceSealStatus {
    /// Namespace seal type. OpenBao 2.6.0 supports `shamir`.
    #[serde(rename = "type", deserialize_with = "deserialize_safe_metadata_string")]
    pub seal_type: String,
    /// Whether the namespace seal has been initialized.
    pub initialized: bool,
    /// Whether the namespace is sealed.
    pub sealed: bool,
    /// Total Shamir share count.
    pub n: u8,
    /// Required Shamir share threshold.
    pub t: u8,
    /// Number of accepted shares in the current unseal attempt.
    pub progress: u8,
    /// Current unseal attempt nonce.
    #[serde(deserialize_with = "deserialize_safe_metadata_string")]
    pub nonce: String,
}

/// Explicit confirmation for physically deleting a sealed namespace.
///
/// Construct this at the call site with [`SealedNamespaceDeletion::confirm`]
/// or [`SealedNamespaceDeletion::confirm_recursive`].
#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedNamespaceDeletion {
    force: bool,
}

#[cfg(feature = "operator-ops")]
impl SealedNamespaceDeletion {
    /// Confirms deletion of one sealed namespace with no children.
    #[must_use]
    pub const fn confirm() -> Self {
        Self { force: false }
    }

    /// Confirms recursive deletion of the namespace, its data, and children.
    #[must_use]
    pub const fn confirm_recursive() -> Self {
        Self { force: true }
    }
}

/// Status returned after scheduling sealed namespace deletion.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Deserialize)]
pub struct SealedNamespaceDeletionStatus {
    /// OpenBao deletion status text.
    #[serde(deserialize_with = "deserialize_safe_metadata_string")]
    pub status: String,
}

/// Global rate-limit quota configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RateLimitQuotaConfig {
    /// Paths exempt from every rate-limit quota.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub rate_limit_exempt_paths: Vec<String>,
    /// Whether rejected quota requests are audit logged.
    #[serde(default)]
    pub enable_rate_limit_audit_logging: bool,
    /// Whether OpenBao adds rate-limit headers to responses.
    #[serde(default)]
    pub enable_rate_limit_response_headers: bool,
}

impl RateLimitQuotaConfig {
    /// Creates an empty rate-limit quota configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one exempt path.
    #[must_use]
    pub fn with_exempt_path(mut self, path: impl Into<String>) -> Self {
        self.rate_limit_exempt_paths.push(path.into());
        self
    }

    /// Adds one exempt path after validating it.
    pub fn try_with_exempt_path(mut self, path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        if path.trim_matches('/').is_empty() {
            return Err(Error::InvalidPath(
                "rate limit exempt path must not be empty".into(),
            ));
        }
        let _validated = validate_endpoint_path(&path)?;
        self.rate_limit_exempt_paths.push(path);
        Ok(self)
    }
}

/// Locked users grouped by namespace.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LockedUsers {
    /// Locked users grouped by namespace.
    #[serde(default, deserialize_with = "deserialize_bounded_locked_namespace_vec")]
    pub by_namespace: Vec<LockedUsersNamespace>,
    /// Total locked users across returned namespaces.
    #[serde(default)]
    pub total: u64,
}

/// Locked user information for one namespace.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LockedUsersNamespace {
    /// Namespace identifier.
    #[serde(default)]
    pub namespace_id: String,
    /// Namespace path.
    #[serde(default)]
    pub namespace_path: String,
    /// Locked user count in this namespace.
    #[serde(default)]
    pub counts: u64,
    /// Locked users grouped by auth mount accessor.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_locked_mount_accessor_vec"
    )]
    pub mount_accessors: Vec<LockedUsersMountAccessor>,
}

/// Locked user information for one auth mount accessor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LockedUsersMountAccessor {
    /// Auth mount accessor.
    #[serde(default)]
    pub mount_accessor: String,
    /// Locked user count for this accessor.
    #[serde(default)]
    pub counts: u64,
    /// User aliases currently locked for this accessor.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub alias_identifiers: Vec<String>,
}

/// Integrated Storage Raft cluster configuration response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RaftConfiguration {
    /// Raft configuration data.
    #[serde(default)]
    pub config: RaftConfigurationData,
}

/// Raft peer configuration data.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RaftConfigurationData {
    /// Raft log index for the configuration.
    #[serde(default)]
    pub index: u64,
    /// Raft servers in the cluster.
    #[serde(default, deserialize_with = "deserialize_bounded_raft_server_vec")]
    pub servers: Vec<RaftServer>,
}

/// One server in the Raft cluster configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RaftServer {
    /// Server address.
    #[serde(default)]
    pub address: String,
    /// Whether this server is the leader.
    #[serde(default)]
    pub leader: bool,
    /// Raft node identifier.
    #[serde(default)]
    pub node_id: String,
    /// Raft protocol version as returned by OpenBao.
    #[serde(default)]
    pub protocol_version: String,
    /// Whether this server participates in quorum voting.
    #[serde(default)]
    pub voter: bool,
}

/// Request for joining a Raft cluster.
#[derive(Clone, Default)]
pub struct RaftJoinRequest {
    /// Leader API address, such as `https://openbao-1.example.com:8200`.
    pub leader_api_addr: String,
    /// Retry joining the Raft cluster after failures.
    pub retry: Option<bool>,
    /// CA certificate used to verify the leader.
    pub leader_ca_cert: Option<String>,
    /// Client certificate presented to the leader.
    pub leader_client_cert: Option<String>,
    /// Client private key presented to the leader.
    pub leader_client_key: Option<SecretString>,
    /// TLS server name used when connecting to the leader.
    pub leader_tls_servername: Option<String>,
    /// Cloud auto-join metadata. Treat as secret because provider metadata can
    /// contain deployment identifiers or credentials.
    pub auto_join: Option<SecretString>,
    /// URI scheme used for auto-join.
    pub auto_join_scheme: Option<String>,
    /// Port used for auto-join.
    pub auto_join_port: Option<u16>,
    /// Join as a non-voting server (OpenBao 2.2+).
    pub non_voter: Option<bool>,
}

impl RaftJoinRequest {
    /// Creates a Raft join request with the required leader API address.
    pub fn new(leader_api_addr: impl Into<String>) -> Self {
        Self {
            leader_api_addr: leader_api_addr.into(),
            ..Self::default()
        }
    }

    /// Sets the leader client key.
    #[must_use]
    pub fn with_leader_client_key(mut self, key: SecretString) -> Self {
        self.leader_client_key = Some(key);
        self
    }

    /// Sets cloud auto-join metadata.
    #[must_use]
    pub fn with_auto_join(mut self, auto_join: SecretString) -> Self {
        self.auto_join = Some(auto_join);
        self
    }

    fn validate(&self) -> Result<()> {
        let leader_url = Url::parse(&self.leader_api_addr).map_err(|_| {
            Error::InvalidParameter("Raft leader_api_addr must be a valid URL".into())
        })?;
        if leader_url.scheme() != "https" {
            return Err(Error::InvalidParameter(
                "Raft leader_api_addr must use https://".into(),
            ));
        }
        if let Some(scheme) = &self.auto_join_scheme
            && scheme != "https"
        {
            return Err(Error::InvalidParameter(
                "Raft auto_join_scheme must be https".into(),
            ));
        }
        if let Some(port) = self.auto_join_port
            && port == 0
        {
            return Err(Error::InvalidParameter(
                "Raft auto_join_port must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for RaftJoinRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RaftJoinRequest")
            .field("leader_api_addr", &self.leader_api_addr)
            .field("retry", &self.retry)
            .field("leader_ca_cert", &self.leader_ca_cert)
            .field("leader_client_cert", &self.leader_client_cert)
            .field(
                "leader_client_key",
                &self.leader_client_key.as_ref().map(|_| "<redacted>"),
            )
            .field("leader_tls_servername", &self.leader_tls_servername)
            .field("auto_join", &self.auto_join.as_ref().map(|_| "<redacted>"))
            .field("auto_join_scheme", &self.auto_join_scheme)
            .field("auto_join_port", &self.auto_join_port)
            .field("non_voter", &self.non_voter)
            .finish()
    }
}

/// Response returned after a Raft join request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RaftJoinResponse {
    /// Whether the join request was accepted.
    #[serde(default)]
    pub joined: bool,
}

/// Request for Raft peer mutation operations.
#[derive(Clone, Default)]
pub struct RaftPeerRequest {
    /// Raft server identifier.
    pub server_id: String,
    /// Disaster recovery operation token, when required.
    pub dr_operation_token: Option<SecretString>,
}

impl RaftPeerRequest {
    /// Creates a peer mutation request with the required server identifier.
    pub fn new(server_id: impl Into<String>) -> Self {
        Self {
            server_id: server_id.into(),
            dr_operation_token: None,
        }
    }

    /// Sets the disaster recovery operation token.
    #[must_use]
    pub fn with_dr_operation_token(mut self, token: SecretString) -> Self {
        self.dr_operation_token = Some(token);
        self
    }

    fn validate(&self) -> Result<()> {
        validate_raft_server_id(&self.server_id)
    }
}

impl fmt::Debug for RaftPeerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RaftPeerRequest")
            .field("server_id", &self.server_id)
            .field(
                "dr_operation_token",
                &self.dr_operation_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Integrated Storage Raft Autopilot configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RaftAutopilotConfig {
    /// Whether Autopilot should remove dead servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_dead_servers: Option<bool>,
    /// Threshold before a server is considered failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_server_last_contact_threshold: Option<String>,
    /// Threshold before a server is considered unhealthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_contact_threshold: Option<String>,
    /// Maximum trailing Raft logs before a server is unhealthy.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_trailing_logs: Option<String>,
    /// Minimum voting quorum before pruning can occur.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_quorum: Option<String>,
    /// Required stable time before adding a server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_stabilization_time: Option<String>,
}

impl RaftAutopilotConfig {
    /// Creates an empty Autopilot config patch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the last-contact threshold.
    #[must_use]
    pub fn with_last_contact_threshold(mut self, threshold: impl Into<String>) -> Self {
        self.last_contact_threshold = Some(threshold.into());
        self
    }

    /// Sets the last-contact threshold after validating it.
    pub fn try_with_last_contact_threshold(mut self, threshold: impl Into<String>) -> Result<Self> {
        let threshold = threshold.into();
        crate::validation::validate_duration_parameter(
            &threshold,
            "raft autopilot last_contact_threshold",
        )?;
        self.last_contact_threshold = Some(threshold);
        Ok(self)
    }

    /// Sets the server stabilization time.
    #[must_use]
    pub fn with_server_stabilization_time(mut self, duration: impl Into<String>) -> Self {
        self.server_stabilization_time = Some(duration.into());
        self
    }

    /// Sets the server stabilization time after validating it.
    pub fn try_with_server_stabilization_time(
        mut self,
        duration: impl Into<String>,
    ) -> Result<Self> {
        let duration = duration.into();
        crate::validation::validate_duration_parameter(
            &duration,
            "raft autopilot server_stabilization_time",
        )?;
        self.server_stabilization_time = Some(duration);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        validate_optional_duration_string(
            &self.dead_server_last_contact_threshold,
            "Raft Autopilot dead_server_last_contact_threshold",
        )?;
        validate_optional_duration_string(
            &self.last_contact_threshold,
            "Raft Autopilot last_contact_threshold",
        )?;
        validate_optional_duration_string(
            &self.server_stabilization_time,
            "Raft Autopilot server_stabilization_time",
        )?;
        validate_optional_positive_integer(
            &self.max_trailing_logs,
            "Raft Autopilot max_trailing_logs",
        )?;
        validate_optional_positive_integer(&self.min_quorum, "Raft Autopilot min_quorum")?;
        Ok(())
    }
}

/// Request for moving a mounted secrets engine or auth method.
#[derive(Clone, Debug, Serialize)]
pub struct RemountRequest {
    /// Existing mount path, optionally including child namespace prefixes.
    pub from: String,
    /// Destination mount path, optionally including child namespace prefixes.
    pub to: String,
}

impl RemountRequest {
    /// Creates a remount request from source and destination mount paths.
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_remount_endpoint_path(&self.from, "remount source")?;
        validate_remount_endpoint_path(&self.to, "remount destination")?;
        if self.from.trim_matches('/') == self.to.trim_matches('/') {
            return Err(Error::InvalidParameter(
                "remount source and destination must differ".into(),
            ));
        }
        Ok(())
    }
}

/// Response returned when OpenBao starts a mount migration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RemountResponse {
    /// Migration identifier used to poll status.
    #[serde(default)]
    pub migration_id: String,
}

/// Mount migration status response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RemountStatus {
    /// Migration identifier.
    #[serde(default)]
    pub migration_id: String,
    /// Migration details.
    #[serde(default)]
    pub migration_info: RemountMigrationInfo,
}

/// Mount migration details.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RemountMigrationInfo {
    /// Original mount path.
    #[serde(default)]
    pub source_mount: String,
    /// Target mount path.
    #[serde(default)]
    pub target_mount: String,
    /// OpenBao status, such as `in-progress`, `success`, or `failure`.
    #[serde(default)]
    pub status: String,
}

/// Rate-limit quota list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RateLimitQuotaList {
    /// Quota names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Quota metadata keyed by quota name, when returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_rate_limit_quota_map")]
    pub key_info: BTreeMap<String, RateLimitQuotaInfo>,
}

impl ListEntries for RateLimitQuotaList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Rate-limit quota information returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RateLimitQuotaInfo {
    /// Quota name.
    #[serde(default)]
    pub name: String,
    /// Path or namespace to which the quota applies.
    #[serde(default)]
    pub path: String,
    /// Requests allowed during the configured interval.
    #[serde(default)]
    pub rate: f64,
    /// Rate-limit interval.
    #[serde(default)]
    pub interval: Option<LeaseDuration>,
    /// Optional blocking duration after the quota is exceeded.
    #[serde(default)]
    pub block_interval: Option<LeaseDuration>,
    /// Auth role restriction, when configured.
    #[serde(default)]
    pub role: Option<String>,
    /// Quota type returned by OpenBao.
    #[serde(default, rename = "type")]
    pub quota_type: Option<String>,
    /// Whether the quota applies to child namespaces (OpenBao 2.3.1+).
    #[serde(default)]
    pub inheritable: Option<bool>,
}

/// Request body for creating or updating a rate-limit quota.
#[derive(Clone, Debug, Serialize)]
pub struct RateLimitQuotaRequest {
    /// Path or namespace to which the quota applies. Empty means the root API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Requests allowed during the configured interval. Must be positive.
    pub rate: f64,
    /// Rate-limit interval, such as `1s` or `2m`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// Optional blocking duration after the quota is exceeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_interval: Option<String>,
    /// Auth role restriction, when the path targets a role-aware auth mount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

impl RateLimitQuotaRequest {
    /// Creates a rate-limit quota request with the required `rate`.
    #[must_use]
    pub fn new(rate: f64) -> Self {
        Self {
            path: None,
            rate,
            interval: None,
            block_interval: None,
            role: None,
        }
    }

    /// Sets the quota path or namespace.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the quota path or namespace after validating it.
    pub fn try_with_path(mut self, path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let _validated = validate_endpoint_path(&path)?;
        self.path = Some(path);
        Ok(self)
    }

    /// Sets the positive rate-limit interval.
    #[must_use]
    pub fn with_interval(mut self, interval: impl Into<String>) -> Self {
        self.interval = Some(interval.into());
        self
    }

    /// Sets the positive rate-limit interval after validating it.
    pub fn try_with_interval(mut self, interval: impl Into<String>) -> Result<Self> {
        let interval = interval.into();
        crate::validation::validate_duration_parameter(&interval, "rate limit interval")?;
        self.interval = Some(interval);
        Ok(self)
    }

    /// Sets the positive blocking interval.
    #[must_use]
    pub fn with_block_interval(mut self, block_interval: impl Into<String>) -> Self {
        self.block_interval = Some(block_interval.into());
        self
    }

    /// Sets the positive blocking interval after validating it.
    pub fn try_with_block_interval(mut self, block_interval: impl Into<String>) -> Result<Self> {
        let block_interval = block_interval.into();
        crate::validation::validate_duration_parameter(
            &block_interval,
            "rate limit block_interval",
        )?;
        self.block_interval = Some(block_interval);
        Ok(self)
    }

    /// Sets the auth role restriction.
    #[must_use]
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }
}

/// OpenBao seal status response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealStatus {
    /// Seal type.
    #[serde(rename = "type", deserialize_with = "deserialize_safe_metadata_string")]
    pub seal_type: String,
    /// Whether the node is initialized.
    pub initialized: bool,
    /// Whether the node is sealed.
    pub sealed: bool,
    /// Key shares configured for Shamir seal.
    #[serde(default)]
    pub n: Option<u64>,
    /// Key threshold configured for Shamir seal.
    #[serde(default)]
    pub t: Option<u64>,
    /// Progress toward unseal threshold.
    #[serde(default)]
    pub progress: Option<u64>,
    /// Server version.
    #[serde(deserialize_with = "deserialize_safe_metadata_string")]
    pub version: String,
}

/// Seal status with build metadata returned by newer OpenBao releases.
#[derive(Clone, Debug, Deserialize)]
pub struct SealStatusDetails {
    /// Seal state available across supported OpenBao releases.
    #[serde(flatten)]
    pub status: SealStatus,
    /// Build timestamp, when returned.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub build_date: Option<String>,
    /// Source commit timestamp, when returned.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub commit_date: Option<String>,
    /// Recovery seal type, when configured.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub recovery_seal_type: Option<String>,
}

/// OpenBao unseal progress response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnsealStatus {
    /// Whether the node is still sealed.
    pub sealed: bool,
    /// Key shares configured for Shamir seal.
    #[serde(default)]
    pub n: Option<u64>,
    /// Key threshold configured for Shamir seal.
    #[serde(default)]
    pub t: Option<u64>,
    /// Progress toward unseal threshold.
    #[serde(default)]
    pub progress: Option<u64>,
    /// Server version.
    #[serde(deserialize_with = "deserialize_safe_metadata_string")]
    pub version: String,
    /// Cluster name when OpenBao is unsealed.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub cluster_name: Option<String>,
    /// Cluster identifier when OpenBao is unsealed.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub cluster_id: Option<String>,
}

/// Unseal progress with build metadata returned by newer OpenBao releases.
#[derive(Clone, Debug, Deserialize)]
pub struct UnsealStatusDetails {
    /// Unseal state available across supported OpenBao releases.
    #[serde(flatten)]
    pub status: UnsealStatus,
    /// Build timestamp, when returned.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub build_date: Option<String>,
    /// Source commit timestamp, when returned.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub commit_date: Option<String>,
}

/// Production initialization request for `/sys/init`.
///
/// This type is available only with the explicit `operator-ops` feature. It can
/// cause OpenBao to return root, unseal, or recovery material. Prefer an
/// operator ceremony and external custody system over application automation.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct OperatorInitRequest {
    /// Number of Shamir unseal key shares to create.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_shares: Option<u8>,
    /// Number of shares required to unseal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_threshold: Option<u8>,
    /// Base64-encoded PGP public keys for unseal share encryption.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pgp_keys: Vec<String>,
    /// Base64-encoded PGP public key for root token encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_token_pgp_key: Option<String>,
    /// Number of recovery shares for auto-unseal deployments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_shares: Option<u8>,
    /// Number of recovery shares required for recovery operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_threshold: Option<u8>,
    /// Base64-encoded PGP public keys for recovery share encryption.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recovery_pgp_keys: Vec<String>,
    /// Number of shares stored by the seal backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_shares: Option<u8>,
}

/// Production initialization response from `/sys/init`.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct OperatorInitResponse {
    /// Unseal key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys: Vec<SecretString>,
    /// Base64-encoded unseal key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys_base64: Vec<SecretString>,
    /// Initial root token. Treat as highly sensitive operator material.
    pub root_token: SecretString,
    /// Recovery key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub recovery_keys: Vec<SecretString>,
    /// Base64-encoded recovery key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub recovery_keys_base64: Vec<SecretString>,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorInitResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorInitResponse")
            .field("keys_count", &self.keys.len())
            .field("keys_base64_count", &self.keys_base64.len())
            .field("root_token", &"<redacted>")
            .field("recovery_keys_count", &self.recovery_keys.len())
            .field(
                "recovery_keys_base64_count",
                &self.recovery_keys_base64.len(),
            )
            .finish()
    }
}

/// Production unseal request for `/sys/unseal`.
#[cfg(feature = "operator-ops")]
#[derive(Clone)]
pub struct OperatorUnsealRequest {
    /// Unseal or recovery key share.
    pub key: SecretString,
    /// Reset unseal progress.
    pub reset: Option<bool>,
    /// Seal migration flag.
    pub migrate: Option<bool>,
}

#[cfg(feature = "operator-ops")]
impl OperatorUnsealRequest {
    /// Creates an unseal request for one key share.
    pub fn new(key: SecretString) -> Self {
        Self {
            key,
            reset: None,
            migrate: None,
        }
    }
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorUnsealRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorUnsealRequest")
            .field("key", &"<redacted>")
            .field("reset", &self.reset)
            .field("migrate", &self.migrate)
            .finish()
    }
}

/// Production rekey/rotation initialization request.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct OperatorKeySharesRequest {
    /// Number of shares to create.
    pub secret_shares: u8,
    /// Number of shares required to reconstruct.
    pub secret_threshold: u8,
    /// Number of shares stored by a seal backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_shares: Option<u8>,
    /// Base64-encoded PGP public keys for share encryption.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pgp_keys: Vec<String>,
    /// Whether PGP-encrypted shares should be backed up in storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<bool>,
    /// Whether new shares must be verified before finalizing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_verification: Option<bool>,
}

#[cfg(feature = "operator-ops")]
impl OperatorKeySharesRequest {
    /// Creates a validated key-share request.
    pub fn new(secret_shares: u8, secret_threshold: u8) -> Result<Self> {
        validate_key_share_options(secret_shares, secret_threshold)?;
        Ok(Self {
            secret_shares,
            secret_threshold,
            ..Self::default()
        })
    }
}

/// Rekey/rotation progress status.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorKeySharesStatus {
    /// Whether an operation has started.
    #[serde(default)]
    pub started: bool,
    /// Operation nonce.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Required threshold.
    #[serde(default)]
    pub t: Option<u64>,
    /// New share count.
    #[serde(default)]
    pub n: Option<u64>,
    /// Current progress count.
    #[serde(default)]
    pub progress: Option<u64>,
    /// Required progress count.
    #[serde(default)]
    pub required: Option<u64>,
    /// PGP fingerprints used for encrypted shares.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub pgp_fingerprints: Vec<String>,
    /// Whether backup is enabled.
    #[serde(default)]
    pub backup: bool,
    /// Whether verification is required.
    #[serde(default)]
    pub verification_required: bool,
}

/// Rekey/rotation update request containing one existing key share.
#[cfg(feature = "operator-ops")]
#[derive(Clone)]
pub struct OperatorKeyShareUpdateRequest {
    /// Existing key share used to authorize progress.
    pub key: SecretString,
    /// Operation nonce.
    pub nonce: String,
}

#[cfg(feature = "operator-ops")]
impl OperatorKeyShareUpdateRequest {
    /// Creates an update request.
    pub fn new(key: SecretString, nonce: impl Into<String>) -> Self {
        Self {
            key,
            nonce: nonce.into(),
        }
    }
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorKeyShareUpdateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorKeyShareUpdateRequest")
            .field("key", &"<redacted>")
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// Rekey/rotation update response.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct OperatorKeyShareUpdateResponse {
    /// Whether the operation completed.
    #[serde(default)]
    pub complete: bool,
    /// Newly generated key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys: Vec<SecretString>,
    /// Newly generated base64 key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys_base64: Vec<SecretString>,
    /// Operation nonce.
    #[serde(default)]
    pub nonce: Option<String>,
    /// PGP fingerprints used for encrypted shares.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub pgp_fingerprints: Vec<String>,
    /// Whether backup is enabled.
    #[serde(default)]
    pub backup: bool,
    /// Whether verification is required.
    #[serde(default)]
    pub verification_required: bool,
    /// Verification nonce when verification is required.
    #[serde(default)]
    pub verification_nonce: Option<String>,
    /// Current progress, when the operation has not completed.
    #[serde(default)]
    pub progress: Option<u64>,
    /// Required progress, when the operation has not completed.
    #[serde(default)]
    pub required: Option<u64>,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorKeyShareUpdateResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorKeyShareUpdateResponse")
            .field("complete", &self.complete)
            .field("keys_count", &self.keys.len())
            .field("keys_base64_count", &self.keys_base64.len())
            .field("nonce", &self.nonce)
            .field("pgp_fingerprints", &self.pgp_fingerprints)
            .field("backup", &self.backup)
            .field("verification_required", &self.verification_required)
            .field("verification_nonce", &self.verification_nonce)
            .field("progress", &self.progress)
            .field("required", &self.required)
            .finish()
    }
}

/// Root or recovery token generation progress.
///
/// Available only with `operator-ops` and `operator-ops-acknowledged`.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct OperatorTokenGenerationStatus {
    /// Whether an attempt has started.
    #[serde(default)]
    pub started: bool,
    /// Operation nonce.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Current key-share progress.
    #[serde(default)]
    pub progress: Option<u64>,
    /// Required key-share threshold.
    #[serde(default)]
    pub required: Option<u64>,
    /// Encoded root or recovery token, present only when complete.
    #[serde(default)]
    pub encoded_token: Option<SecretString>,
    /// PGP fingerprint when a PGP key was used instead of an OTP.
    #[serde(default)]
    pub pgp_fingerprint: Option<String>,
    /// OTP length when OTP encoding is used.
    #[serde(default)]
    pub otp_length: Option<u64>,
    /// Whether the attempt has completed.
    #[serde(default)]
    pub complete: bool,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorTokenGenerationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorTokenGenerationStatus")
            .field("started", &self.started)
            .field("nonce", &self.nonce)
            .field("progress", &self.progress)
            .field("required", &self.required)
            .field("encoded_token", &"<redacted>")
            .field("pgp_fingerprint", &self.pgp_fingerprint)
            .field("otp_length", &self.otp_length)
            .field("complete", &self.complete)
            .finish()
    }
}

/// Request for starting root or recovery token generation.
///
/// The optional PGP key is public material. When omitted, OpenBao returns a
/// one-time password in the start response. Treat that OTP as sensitive
/// operator material.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct OperatorTokenGenerationStartRequest {
    /// Base64-encoded PGP public key used to encrypt the final token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgp_key: Option<String>,
}

#[cfg(feature = "operator-ops")]
impl OperatorTokenGenerationStartRequest {
    /// Creates an OTP-based token generation start request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a PGP-encrypted token generation start request.
    #[must_use]
    pub fn with_pgp_key(mut self, pgp_key: impl Into<String>) -> Self {
        self.pgp_key = Some(pgp_key.into());
        self
    }
}

/// Start response for root or recovery token generation.
///
/// The OTP is returned once by OpenBao. Store it in an operator custody system
/// and never log it.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct OperatorTokenGenerationStart {
    /// Progress status for the started attempt.
    #[serde(flatten)]
    pub status: OperatorTokenGenerationStatus,
    /// One-time password used to decode the final encoded token.
    #[serde(default)]
    pub otp: Option<SecretString>,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorTokenGenerationStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorTokenGenerationStart")
            .field("status", &self.status)
            .field("otp", &"<redacted>")
            .finish()
    }
}

/// Request for locally decoding a generated root or recovery token.
///
/// Both fields are sensitive operator ceremony material.
#[cfg(feature = "operator-ops")]
#[derive(Clone)]
pub struct DecodeTokenRequest {
    /// Encoded token returned by a completed generate-root or
    /// generate-recovery-token operation.
    pub encoded_token: SecretString,
    /// OTP returned when the generation attempt was started.
    pub otp: SecretString,
}

#[cfg(feature = "operator-ops")]
impl DecodeTokenRequest {
    /// Creates a token decode request.
    #[must_use]
    pub fn new(encoded_token: SecretString, otp: SecretString) -> Self {
        Self { encoded_token, otp }
    }
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for DecodeTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodeTokenRequest")
            .field("encoded_token", &"<redacted>")
            .field("otp", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "operator-ops")]
/// Locally decoded root or recovery token.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct DecodeTokenResponse {
    /// Decoded token. Treat as root- or recovery-level credential material.
    pub token: SecretString,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for DecodeTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodeTokenResponse")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// PGP-encrypted recovery-key backup returned by legacy recovery rekey.
///
/// Available only with `operator-ops` and `operator-ops-acknowledged`.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct OperatorRecoveryKeyBackup {
    /// Operation nonce associated with the backup.
    #[serde(default)]
    pub nonce: Option<String>,
    /// PGP key fingerprint to encrypted share material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_map")]
    pub keys: BTreeMap<String, SecretString>,
    /// Base64-formatted encrypted shares, when returned by barrier rekey.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_map")]
    pub keys_base64: BTreeMap<String, SecretString>,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorRecoveryKeyBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorRecoveryKeyBackup")
            .field("nonce", &self.nonce)
            .field("keys_count", &self.keys.len())
            .field("keys_base64_count", &self.keys_base64.len())
            .finish()
    }
}

/// Target for authenticated OpenBao v2.4+ key-share rotation endpoints.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorRotateTarget {
    /// Rotate root key / Shamir unseal key shares.
    Root,
    /// Rotate recovery key shares.
    Recovery,
}

#[cfg(feature = "operator-ops")]
impl OperatorRotateTarget {
    fn path_segment(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Recovery => "recovery",
        }
    }
}

/// Automatic barrier or keyring rotation configuration.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OperatorRotationConfig {
    /// Whether automatic rotation is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Maximum time between rotations (OpenBao 2.4+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<LeaseDuration>,
    /// Maximum cryptographic operations between rotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_operations: Option<u64>,
}

/// UI response-header configuration.
#[cfg(feature = "unstable-internal-ops")]
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UiHeaderConfig {
    /// Header values.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub values: Vec<String>,
    /// Whether OpenBao emits multiple header fields instead of one joined field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multivalue: Option<bool>,
    /// Legacy single-value response field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Internal entity or token counter response.
#[cfg(feature = "unstable-internal-ops")]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct InternalCounters {
    /// Counter groups returned by OpenBao.
    #[serde(default)]
    pub counters: InternalCounterGroups,
}

/// Known internal counter groups.
#[cfg(feature = "unstable-internal-ops")]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct InternalCounterGroups {
    /// Entity count, when requested.
    #[serde(default)]
    pub entities: Option<InternalCounterTotal>,
    /// Service-token count, when requested.
    #[serde(default)]
    pub service_tokens: Option<InternalCounterTotal>,
}

/// Total for one internal counter group.
#[cfg(feature = "unstable-internal-ops")]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct InternalCounterTotal {
    /// Current total.
    #[serde(default)]
    pub total: u64,
}

/// One mount entry returned by internal router inspection.
#[cfg(feature = "unstable-internal-ops")]
#[derive(Clone, Default, Deserialize)]
pub struct InternalRouterMount {
    /// Mount accessor. Treat as sensitive operational metadata.
    #[serde(default)]
    pub accessor: Option<SecretString>,
    /// Mount namespace.
    #[serde(default)]
    pub mount_namespace: Option<SecretString>,
    /// Mount path.
    #[serde(default)]
    pub mount_path: Option<SecretString>,
    /// Mount type.
    #[serde(default)]
    pub mount_type: Option<SecretString>,
    /// Storage prefix, when returned.
    #[serde(default)]
    pub storage_prefix: Option<SecretString>,
    /// Whether the mount is tainted.
    #[serde(default)]
    pub tainted: Option<bool>,
    /// Mount UUID.
    #[serde(default)]
    pub uuid: Option<SecretString>,
}

#[cfg(feature = "unstable-internal-ops")]
impl fmt::Debug for InternalRouterMount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalRouterMount")
            .field("accessor", &"<redacted>")
            .field("mount_namespace", &"<redacted>")
            .field("mount_path", &"<redacted>")
            .field("mount_type", &"<redacted>")
            .field("storage_prefix", &"<redacted>")
            .field("tainted", &self.tainted)
            .field("uuid", &"<redacted>")
            .finish()
    }
}

/// Internal router inspection response.
#[cfg(feature = "unstable-internal-ops")]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct InternalRouterInspection {
    /// Router entries. Only one field is normally populated for a request.
    #[serde(default, deserialize_with = "deserialize_bounded_router_mount_vec")]
    pub root: Vec<InternalRouterMount>,
    /// Storage-prefix router entries.
    #[serde(default, deserialize_with = "deserialize_bounded_router_mount_vec")]
    pub storage: Vec<InternalRouterMount>,
    /// Accessor router entries.
    #[serde(default, deserialize_with = "deserialize_bounded_router_mount_vec")]
    pub accessor: Vec<InternalRouterMount>,
    /// UUID router entries.
    #[serde(default, deserialize_with = "deserialize_bounded_router_mount_vec")]
    pub uuid: Vec<InternalRouterMount>,
}

/// Internal router index selected for inspection.
#[cfg(feature = "unstable-internal-ops")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalRouterTarget {
    /// Root mount table.
    Root,
    /// Storage-prefix index.
    Storage,
    /// Mount-accessor index.
    Accessor,
    /// Mount-UUID index.
    Uuid,
}

#[cfg(feature = "unstable-internal-ops")]
impl InternalRouterTarget {
    fn path_segment(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Storage => "storage",
            Self::Accessor => "accessor",
            Self::Uuid => "uuid",
        }
    }
}

/// Options for [`Sys::bootstrap_dev`].
///
/// The default is intentionally the smallest useful Shamir setup: one share
/// and a threshold of one. That is suitable for disposable local development
/// only and is not a production initialization ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevBootstrapOptions {
    /// Number of Shamir unseal key shares to create.
    pub secret_shares: u8,
    /// Number of shares required to unseal the development instance.
    pub secret_threshold: u8,
}

impl DevBootstrapOptions {
    /// Creates validated development bootstrap options.
    pub fn new(secret_shares: u8, secret_threshold: u8) -> Result<Self> {
        validate_dev_bootstrap_options(secret_shares, secret_threshold)?;
        Ok(Self {
            secret_shares,
            secret_threshold,
        })
    }

    /// Returns the default single-key development configuration.
    pub const fn single_key() -> Self {
        Self {
            secret_shares: 1,
            secret_threshold: 1,
        }
    }
}

impl Default for DevBootstrapOptions {
    fn default() -> Self {
        Self::single_key()
    }
}

/// Explicit confirmation required for disposable development bootstrap.
///
/// This acknowledgement does not prove that a numeric loopback endpoint is a
/// development server. Local tunnels, proxies, and port-forwards can still
/// reach production. Construct it only after auditing the complete network
/// path and confirming the target is disposable.
#[cfg(feature = "dev-bootstrap")]
#[derive(Clone, Copy, Debug)]
pub struct DevBootstrapAcknowledgement {
    _private: (),
}

#[cfg(feature = "dev-bootstrap")]
impl DevBootstrapAcknowledgement {
    /// Confirms that the caller audited the target as disposable development.
    #[must_use]
    pub const fn confirm_disposable_target() -> Self {
        Self { _private: () }
    }
}

/// Result from [`Sys::bootstrap_dev`].
///
/// This type intentionally does not implement `Clone`. It contains a root
/// token and unseal shares for a disposable local development instance.
pub struct DevBootstrap {
    /// Authenticated root client for the freshly bootstrapped dev instance.
    pub client: Client<Authenticated>,
    /// Initial root token returned by OpenBao.
    ///
    /// This is identical to the token stored in [`Self::client`]. Both copies
    /// are zeroed on drop. Prefer using `client` for API calls and expose this
    /// field only when an operator ceremony or test fixture needs the raw root
    /// token.
    pub root_token: SecretString,
    /// Unseal key shares returned by OpenBao.
    pub unseal_keys: Vec<SecretString>,
    /// Base64-encoded unseal key shares returned by OpenBao.
    pub unseal_keys_base64: Vec<SecretString>,
    /// Final unseal response after bootstrap.
    pub unseal_status: UnsealStatus,
}

impl fmt::Debug for DevBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevBootstrap")
            .field("client", &self.client)
            .field("root_token", &"<redacted>")
            .field("unseal_key_count", &self.unseal_keys.len())
            .field("unseal_key_base64_count", &self.unseal_keys_base64.len())
            .field("unseal_status", &self.unseal_status)
            .finish()
    }
}

/// Mount or auth backend information returned by `/sys/mounts` and `/sys/auth`.
#[derive(Clone, Debug, Deserialize)]
pub struct MountInfo {
    /// Backend type, such as `kv`, `pki`, or `approle`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable backend description.
    #[serde(default)]
    pub description: Option<String>,
    /// Mount accessor, when returned. Treat as sensitive metadata.
    #[serde(default)]
    pub accessor: Option<SecretString>,
    /// Backend configuration.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub config: MountConfig,
    /// Backend options.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_map")]
    pub options: Option<BTreeMap<String, String>>,
    /// Whether this mount is local to the node.
    #[serde(default)]
    pub local: bool,
    /// Whether this mount is sealed wrapped.
    #[serde(default)]
    pub seal_wrap: bool,
    /// Whether this mount is external entropy access enabled.
    #[serde(default)]
    pub external_entropy_access: bool,
}

/// Mount or auth backend tuning/configuration fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MountConfig {
    /// Human-readable backend description for tune requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Default lease TTL, in seconds when returned by OpenBao or duration string when submitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_lease_ttl: Option<LeaseDuration>,
    /// Maximum lease TTL, in seconds when returned by OpenBao or duration string when submitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lease_ttl: Option<LeaseDuration>,
    /// Whether backend caching is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_no_cache: Option<bool>,
    /// Audit non-HMAC request keys.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_bounded_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub audit_non_hmac_request_keys: Option<Vec<String>>,
    /// Audit non-HMAC response keys.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_bounded_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub audit_non_hmac_response_keys: Option<Vec<String>>,
    /// Listing visibility, such as `unauth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_visibility: Option<String>,
    /// Passthrough request headers.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_bounded_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub passthrough_request_headers: Option<Vec<String>>,
    /// Allowed response headers.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_bounded_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_response_headers: Option<Vec<String>>,
    /// Plugin version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_version: Option<String>,
    /// Token type used by auth mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// User lockout configuration used by auth mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_lockout_config: Option<UserLockoutConfig>,
}

/// Lease duration as OpenBao returns or accepts it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseDuration {
    /// Duration in whole seconds.
    Seconds(u64),
    /// Duration string such as `30m` or `1h`.
    Duration(String),
}

impl Serialize for LeaseDuration {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Seconds(seconds) => serializer.serialize_u64(*seconds),
            Self::Duration(duration) => serializer.serialize_str(duration),
        }
    }
}

impl<'de> Deserialize<'de> for LeaseDuration {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(LeaseDurationVisitor)
    }
}

struct LeaseDurationVisitor;

impl Visitor<'_> for LeaseDurationVisitor {
    type Value = LeaseDuration;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a non-negative second count or a duration string")
    }

    fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
        Ok(LeaseDuration::Seconds(value))
    }

    fn visit_i64<E>(self, value: i64) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        u64::try_from(value)
            .map(LeaseDuration::Seconds)
            .map_err(|_| E::custom("duration seconds must not be negative"))
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        crate::validation::validate_duration_string(value, true)
            .then(|| LeaseDuration::Duration(value.to_owned()))
            .ok_or_else(|| E::custom("invalid duration string"))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        crate::validation::validate_duration_string(&value, true)
            .then_some(LeaseDuration::Duration(value))
            .ok_or_else(|| E::custom("invalid duration string"))
    }
}

/// User lockout configuration for auth method tuning.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UserLockoutConfig {
    /// Number of failed attempts before lockout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_threshold: Option<u64>,
    /// Lockout duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_duration: Option<LeaseDuration>,
    /// Duration after which the failed-attempt counter is reset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_counter_reset_duration: Option<LeaseDuration>,
    /// Disable lockout handling for the mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_disable: Option<bool>,
}

/// Request for enabling a secrets engine.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MountEnableRequest {
    /// Backend type, such as `kv`, `pki`, or `transit`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable backend description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Backend configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<MountConfig>,
    /// Backend options.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// Whether this mount is local to the node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
    /// Whether this mount is seal wrapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_wrap: Option<bool>,
    /// Whether this mount can access external entropy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_entropy_access: Option<bool>,
}

impl MountEnableRequest {
    /// Creates a secrets-engine enable request for `backend_type`.
    pub fn new(backend_type: impl Into<String>) -> Self {
        Self {
            backend_type: backend_type.into(),
            ..Self::default()
        }
    }

    /// Creates a KV v2 secrets-engine enable request.
    pub fn kv2() -> Self {
        let mut options = BTreeMap::new();
        options.insert("version".to_owned(), "2".to_owned());
        Self {
            backend_type: "kv".to_owned(),
            options,
            ..Self::default()
        }
    }

    /// Sets a human-readable backend description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the backend default lease TTL after validating duration syntax.
    pub fn with_default_lease_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "mount default_lease_ttl")?;
        self.config
            .get_or_insert_with(MountConfig::default)
            .default_lease_ttl = Some(LeaseDuration::Duration(ttl));
        Ok(self)
    }

    /// Sets the backend maximum lease TTL after validating duration syntax.
    pub fn with_max_lease_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "mount max_lease_ttl")?;
        self.config
            .get_or_insert_with(MountConfig::default)
            .max_lease_ttl = Some(LeaseDuration::Duration(ttl));
        Ok(self)
    }
}

/// Request for enabling an auth method.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AuthEnableRequest {
    /// Auth backend type, such as `approle`, `userpass`, or `kubernetes`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable backend description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Backend configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<MountConfig>,
    /// Whether this auth method is local to the node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
}

impl AuthEnableRequest {
    /// Creates an auth-method enable request for `backend_type`.
    pub fn new(backend_type: impl Into<String>) -> Self {
        Self {
            backend_type: backend_type.into(),
            ..Self::default()
        }
    }

    /// Sets a human-readable auth-method description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the auth method default lease TTL after validating duration syntax.
    pub fn with_default_lease_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "auth default_lease_ttl")?;
        self.config
            .get_or_insert_with(MountConfig::default)
            .default_lease_ttl = Some(LeaseDuration::Duration(ttl));
        Ok(self)
    }

    /// Sets the auth method maximum lease TTL after validating duration syntax.
    pub fn with_max_lease_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "auth max_lease_ttl")?;
        self.config
            .get_or_insert_with(MountConfig::default)
            .max_lease_ttl = Some(LeaseDuration::Duration(ttl));
        Ok(self)
    }
}

/// Response wrapping lookup metadata.
#[derive(Clone, Debug, Deserialize)]
pub struct WrappingLookup {
    /// Wrapping token creation time.
    #[serde(default)]
    pub creation_time: Option<String>,
    /// Wrapping token creation path.
    #[serde(default)]
    pub creation_path: Option<String>,
    /// Wrapping token creation TTL in seconds.
    #[serde(default)]
    pub creation_ttl: u64,
}

/// Context for requesting response-wrapped OpenBao JSON responses.
///
/// Use [`Client::wrapping`](crate::Client::wrapping) to construct this type.
/// Each request adds `X-Vault-Wrap-TTL` and returns [`WrappedResponse<T>`],
/// where `T` is the original response shape you would have requested with
/// [`Client::request_json`](crate::Client::request_json).
pub struct WrappingContext<'a> {
    client: &'a Client<Authenticated>,
    ttl: HeaderValue,
}

impl<'a> WrappingContext<'a> {
    pub(crate) fn new(client: &'a Client<Authenticated>, ttl: &str) -> Result<Self> {
        validate_wrapping_ttl(ttl)?;
        let ttl =
            HeaderValue::from_str(ttl).map_err(|error| Error::InvalidHeader(error.to_string()))?;
        Ok(Self { client, ttl })
    }

    /// Sends a wrapped JSON request and returns wrapping token metadata.
    ///
    /// The returned [`WrappedResponse<T>`] does not contain the inner response
    /// body. The inner response remains in OpenBao's cubbyhole storage until a
    /// holder of the single-use wrapping token unwraps it.
    pub async fn request_json<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<WrappedResponse<'a, T>>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.request_json_accepting(method, path, body, &[StatusCode::OK])
            .await
    }

    /// Sends a wrapped JSON request with explicit accepted statuses.
    pub async fn request_json_accepting<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<WrappedResponse<'a, T>>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.request_json_query_accepting(method, path, &[], body, accepted_statuses)
            .await
    }

    /// Sends a wrapped JSON request with validated query parameters.
    pub async fn request_json_query_accepting<T, B>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<WrappedResponse<'a, T>>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        crate::client::ensure_public_raw_api_enabled()?;
        let headers = [(
            HeaderName::from_static("x-vault-wrap-ttl"),
            self.ttl.clone(),
        )];
        let envelope: ResponseEnvelope<Option<Empty>> = self
            .client
            .request_json_query_headers_accepting(
                method,
                path,
                query,
                &headers,
                body,
                accepted_statuses,
            )
            .await?;
        let wrap_info = envelope.wrap_info.ok_or(Error::MissingField("wrap_info"))?;
        Ok(WrappedResponse {
            client: self.client,
            wrap_info,
            consumed: false,
            _response: PhantomData,
        })
    }
}

impl fmt::Debug for WrappingContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappingContext")
            .field("ttl", &"<validated>")
            .finish_non_exhaustive()
    }
}

/// Metadata for a wrapped OpenBao response of type `T`.
///
/// The inner response is not stored in this value. Only the single-use
/// wrapping token metadata is returned, and all token/accessor fields are
/// redacted by `Debug`.
pub struct WrappedResponse<'a, T> {
    client: &'a Client<Authenticated>,
    wrap_info: WrapInfo,
    consumed: bool,
    _response: PhantomData<T>,
}

impl<'a, T> WrappedResponse<'a, T> {
    /// Returns the wrapping metadata.
    #[must_use]
    pub fn wrap_info(&self) -> &WrapInfo {
        &self.wrap_info
    }

    /// Returns the single-use wrapping token.
    #[must_use]
    pub fn token(&self) -> &SecretString {
        &self.wrap_info.token
    }

    /// Returns the wrapping token accessor, when OpenBao returned one.
    #[must_use]
    pub fn accessor(&self) -> Option<&SecretString> {
        self.wrap_info.accessor.as_ref()
    }

    /// Returns the wrapping token TTL in seconds.
    #[must_use]
    pub fn ttl(&self) -> u64 {
        self.wrap_info.ttl
    }

    /// Returns whether this wrapper successfully redeemed its token.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Attempts to redeem the token without transferring wrapper ownership.
    ///
    /// The token remains in this value when the future is cancelled or when
    /// transport or decoding fails. Such failures are outcome-unknown: the
    /// server may have consumed the single-use token even though the client did
    /// not receive a response. Do not retry automatically. Use wrapping lookup
    /// or an application-specific recovery decision.
    pub async fn try_unwrap(&mut self) -> Result<T>
    where
        T: DeserializeOwned,
    {
        if self.consumed {
            return Err(Error::InvalidParameter(
                "wrapping token was already consumed".into(),
            ));
        }
        let payload = WrappingTokenPayload {
            token: self.wrap_info.token.expose_secret(),
        };
        let result = self
            .client
            .request_json_internal(Method::POST, "sys/wrapping/unwrap", Some(&payload))
            .await;
        if result.is_ok() {
            self.consumed = true;
            self.wrap_info.token = SecretString::from(String::new());
            self.wrap_info.accessor = None;
        }
        result
    }

    /// Consumes the wrapping token and decodes the original response shape.
    ///
    /// This returns the same response shape requested from
    /// [`WrappingContext::request_json`]. For ordinary OpenBao data endpoints,
    /// use `T = ResponseEnvelope<MyData>` and then inspect `envelope.data`.
    ///
    /// This compatibility method cannot preserve the local token if its future
    /// is cancelled. Prefer [`Self::try_unwrap`], which keeps ownership with
    /// the caller until the operation succeeds.
    #[deprecated(since = "2.1.0", note = "use cancellation-safe try_unwrap(&mut self)")]
    pub async fn unwrap(mut self) -> Result<T>
    where
        T: DeserializeOwned,
    {
        self.try_unwrap().await
    }
}

impl<T> fmt::Debug for WrappedResponse<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedResponse")
            .field("wrap_info", &self.wrap_info)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

/// Create or update parameters for an OpenBao workflow.
///
/// Workflow definitions can embed request templates and literal values, so
/// `Debug` always redacts the definition. OpenBao 2.6.0 through 2.6.2 contain an
/// upstream handler defect that discards the `cas` field. The SDK models the
/// wire field but rejects CAS-selected writes locally for affected profiles,
/// and never retries workflow writes.
pub struct WorkflowWriteRequest {
    workflow: SecretString,
    description: Option<String>,
    cas: Option<i64>,
    cas_required: bool,
    allow_unauthenticated: bool,
}

impl WorkflowWriteRequest {
    /// Creates a request from an HCL or JSON workflow definition.
    pub fn new(workflow: SecretString) -> Result<Self> {
        validate_workflow_definition(workflow.expose_secret())?;
        Ok(Self {
            workflow,
            description: None,
            cas: None,
            cas_required: false,
            allow_unauthenticated: false,
        })
    }

    /// Sets a bounded, control-character-free description.
    pub fn with_description(mut self, description: impl Into<String>) -> Result<Self> {
        let description = description.into();
        validate_system_response_metadata::<serde::de::value::Error>(&description)
            .map_err(|_| Error::InvalidParameter("workflow description is invalid".into()))?;
        self.description = Some(description);
        Ok(self)
    }

    /// Sets the expected workflow version. Use `-1` for strict creation.
    pub fn with_cas(mut self, version: i64) -> Result<Self> {
        if version < -1 {
            return Err(Error::InvalidParameter(
                "workflow cas must be -1 or a non-negative version".into(),
            ));
        }
        self.cas = Some(version);
        Ok(self)
    }

    /// Requires CAS on this and future updates.
    #[must_use]
    pub fn require_cas(mut self, required: bool) -> Self {
        self.cas_required = required;
        self
    }

    /// Allows token-free execution when the server explicitly enables the
    /// unauthenticated workflow route.
    ///
    /// This builder is available only with `unauthenticated-workflows` plus
    /// `unauthenticated-workflows-acknowledged`.
    #[cfg(feature = "unauthenticated-workflows")]
    #[must_use]
    pub fn allow_unauthenticated(mut self, allowed: bool) -> Self {
        self.allow_unauthenticated = allowed;
        self
    }
}

impl fmt::Debug for WorkflowWriteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowWriteRequest")
            .field("workflow", &"<redacted>")
            .field("description", &self.description)
            .field("cas", &self.cas)
            .field("cas_required", &self.cas_required)
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .finish()
    }
}

#[derive(Serialize)]
struct WorkflowWritePayload<'a> {
    workflow: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cas: Option<i64>,
    cas_required: bool,
    allow_unauthenticated: bool,
}

/// Stored OpenBao workflow metadata and definition.
pub struct WorkflowInfo {
    /// Canonical workflow path.
    pub path: String,
    /// HCL or JSON workflow definition. Treat as secret material.
    pub workflow: SecretString,
    /// Operator description.
    pub description: String,
    /// Monotonic workflow version.
    pub version: u64,
    /// Whether updates require check-and-set.
    pub cas_required: bool,
    /// Whether token-free execution is permitted by this workflow.
    pub allow_unauthenticated: bool,
}

impl fmt::Debug for WorkflowInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowInfo")
            .field("path", &self.path)
            .field("workflow", &"<redacted>")
            .field("description", &self.description)
            .field("version", &self.version)
            .field("cas_required", &self.cas_required)
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .finish()
    }
}

impl<'de> Deserialize<'de> for WorkflowInfo {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawWorkflowInfo {
            #[serde(default)]
            path: String,
            workflow: SecretString,
            #[serde(default)]
            description: String,
            version: u64,
            #[serde(default)]
            cas_required: bool,
            #[serde(default)]
            allow_unauthenticated: bool,
        }

        let raw = RawWorkflowInfo::deserialize(deserializer)?;
        if !raw.path.is_empty() {
            let segments = validate_endpoint_path(&raw.path).map_err(D::Error::custom)?;
            if segments.is_empty() {
                return Err(D::Error::custom("workflow path must not be empty"));
            }
        }
        validate_workflow_definition(raw.workflow.expose_secret()).map_err(D::Error::custom)?;
        validate_system_response_metadata::<D::Error>(&raw.description)?;
        Ok(Self {
            path: raw.path,
            workflow: raw.workflow,
            description: raw.description,
            version: raw.version,
            cas_required: raw.cas_required,
            allow_unauthenticated: raw.allow_unauthenticated,
        })
    }
}

/// Bounded workflow list or recursive scan response.
#[derive(Default)]
pub struct WorkflowList {
    /// Workflow paths in server order.
    pub keys: Vec<String>,
    /// Sensitive workflow definitions keyed by path.
    pub key_info: BTreeMap<String, WorkflowInfo>,
}

impl fmt::Debug for WorkflowList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowList")
            .field("key_count", &self.keys.len())
            .field("key_info_count", &self.key_info.len())
            .finish()
    }
}

impl ListEntries for WorkflowList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

impl<'de> Deserialize<'de> for WorkflowList {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawWorkflowList {
            #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
            keys: Vec<String>,
            #[serde(default, deserialize_with = "deserialize_bounded_workflow_map")]
            key_info: BTreeMap<String, WorkflowInfo>,
        }
        let raw = RawWorkflowList::deserialize(deserializer)?;
        for key in &raw.keys {
            validate_workflow_path_for_serde::<D::Error>(key)?;
        }
        Ok(Self {
            keys: raw.keys,
            key_info: raw.key_info,
        })
    }
}

/// Bounded arbitrary JSON object used for workflow input, output, and traces.
///
/// The bytes live in sanitizing storage and `Debug` never reveals their
/// contents. The object is capped at 8 MiB independently of client transport
/// limits.
pub struct WorkflowData {
    contents: SecretVec,
}

impl WorkflowData {
    /// Creates workflow data from a JSON object in sanitizing storage.
    pub fn from_json_bytes(contents: SecretVec) -> Result<Self> {
        validate_workflow_json(&contents)?;
        Ok(Self { contents })
    }

    /// Serializes a value into a bounded sanitizing JSON object.
    pub fn from_serializable<T>(value: &T) -> Result<Self>
    where
        T: Serialize + ?Sized,
    {
        Self::from_json_bytes(crate::client::encode_bounded_json(
            value,
            MAX_WORKFLOW_DATA_BYTES,
        )?)
    }

    /// Creates an empty workflow input object.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            contents: SecretVec::from_slice(b"{}"),
        }
    }

    /// Borrows the validated JSON bytes for explicit secret-aware handling.
    pub fn with_json_bytes<T>(&self, inspect: impl FnOnce(&[u8]) -> T) -> T {
        self.contents.with_secret(inspect)
    }

    /// Returns the encoded byte length without exposing contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.contents.len()
    }

    /// Returns whether the encoded object is empty. Valid workflow data is
    /// never byte-empty, so this normally returns `false`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }
}

impl fmt::Debug for WorkflowData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowData")
            .field("contents", &"<redacted>")
            .field("encoded_len", &self.contents.len())
            .finish()
    }
}

impl Serialize for WorkflowData {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.contents.with_secret(|bytes| {
            let raw = serde_json::from_slice::<&RawValue>(bytes).map_err(S::Error::custom)?;
            raw.serialize(serializer)
        })
    }
}

/// ACL policy list response.
#[derive(Clone, Debug, Serialize)]
pub struct PolicyList {
    /// Policy names.
    pub policies: Vec<String>,
}

impl<'de> Deserialize<'de> for PolicyList {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawPolicyList {
            #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
            policies: Vec<String>,
            #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
            keys: Vec<String>,
        }

        let raw = RawPolicyList::deserialize(deserializer)?;
        Ok(Self {
            policies: if raw.policies.is_empty() {
                raw.keys
            } else {
                raw.policies
            },
        })
    }
}

impl ListEntries for PolicyList {
    fn entries(&self) -> &[String] {
        &self.policies
    }
}

/// ACL policy read response.
#[derive(Clone, Serialize)]
pub struct PolicyInfo {
    /// Policy name.
    pub name: String,
    /// Policy document.
    pub rules: String,
    /// Policy expiration timestamp, when configured.
    #[serde(default)]
    pub expiration: Option<String>,
    /// Last modification timestamp, when returned by OpenBao.
    #[serde(default)]
    pub modified: Option<String>,
    /// Policy version, when returned by OpenBao.
    #[serde(default)]
    pub version: Option<u64>,
    /// Whether check-and-set is required for future updates.
    #[serde(default)]
    pub cas_required: bool,
}

impl fmt::Debug for PolicyInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyInfo")
            .field("name", &self.name)
            .field("rules", &"<redacted>")
            .field("expiration", &self.expiration)
            .field("modified", &self.modified)
            .field("version", &self.version)
            .field("cas_required", &self.cas_required)
            .finish()
    }
}

impl<'de> Deserialize<'de> for PolicyInfo {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawPolicyInfo {
            #[serde(default)]
            name: String,
            #[serde(default)]
            rules: Option<String>,
            #[serde(default)]
            policy: Option<String>,
            #[serde(default)]
            expiration: Option<String>,
            #[serde(default)]
            modified: Option<String>,
            #[serde(default)]
            version: Option<u64>,
            #[serde(default)]
            cas_required: bool,
        }

        let raw = RawPolicyInfo::deserialize(deserializer)?;
        Ok(Self {
            name: raw.name,
            rules: raw.rules.or(raw.policy).unwrap_or_default(),
            expiration: raw.expiration,
            modified: raw.modified,
            version: raw.version,
            cas_required: raw.cas_required,
        })
    }
}

/// ACL policy readback including OpenBao 2.6 identity-template overrides.
#[derive(Clone, Serialize)]
pub struct PolicyInfoDetails {
    /// Policy fields available across supported OpenBao releases.
    #[serde(flatten)]
    pub policy: PolicyInfo,
    /// Whether rendered identity-template values may contain `/`.
    pub allow_slashes_in_identity_templates: bool,
    /// Whether rendered identity-template values may contain `*` or `+`.
    pub allow_wildcards_in_identity_templates: bool,
}

impl fmt::Debug for PolicyInfoDetails {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyInfoDetails")
            .field("policy", &self.policy)
            .field(
                "allow_slashes_in_identity_templates",
                &self.allow_slashes_in_identity_templates,
            )
            .field(
                "allow_wildcards_in_identity_templates",
                &self.allow_wildcards_in_identity_templates,
            )
            .finish()
    }
}

impl<'de> Deserialize<'de> for PolicyInfoDetails {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawPolicyInfoDetails {
            #[serde(default)]
            name: String,
            #[serde(default)]
            rules: Option<String>,
            #[serde(default)]
            policy: Option<String>,
            #[serde(default)]
            expiration: Option<String>,
            #[serde(default)]
            modified: Option<String>,
            #[serde(default)]
            version: Option<u64>,
            #[serde(default)]
            cas_required: bool,
            #[serde(default)]
            allow_slashes_in_identity_templates: bool,
            #[serde(default)]
            allow_wildcards_in_identity_templates: bool,
        }

        let raw = RawPolicyInfoDetails::deserialize(deserializer)?;
        Ok(Self {
            policy: PolicyInfo {
                name: raw.name,
                rules: raw.rules.or(raw.policy).unwrap_or_default(),
                expiration: raw.expiration,
                modified: raw.modified,
                version: raw.version,
                cas_required: raw.cas_required,
            },
            allow_slashes_in_identity_templates: raw.allow_slashes_in_identity_templates,
            allow_wildcards_in_identity_templates: raw.allow_wildcards_in_identity_templates,
        })
    }
}

/// Explicit acknowledgment for OpenBao 2.6 ACL identity-template delimiter overrides.
///
/// OpenBao rejects `/`, `*`, and `+` in rendered ACL identity-template values
/// by default. Permitting them can let untrusted identity metadata select
/// additional paths or wildcard capabilities. This value is constructible only
/// when `identity-template-overrides-acknowledged` is enabled.
#[cfg(feature = "identity-template-overrides-acknowledged")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AclIdentityTemplateOverrides {
    allow_slashes: bool,
    allow_wildcards: bool,
}

#[cfg(feature = "identity-template-overrides-acknowledged")]
impl AclIdentityTemplateOverrides {
    /// Acknowledges the path-injection risk and permits `/` in rendered values.
    #[must_use]
    pub const fn acknowledge_slashes() -> Self {
        Self {
            allow_slashes: true,
            allow_wildcards: false,
        }
    }

    /// Acknowledges the wildcard-injection risk and permits `*` and `+`.
    #[must_use]
    pub const fn acknowledge_wildcards() -> Self {
        Self {
            allow_slashes: false,
            allow_wildcards: true,
        }
    }

    /// Acknowledges both path-separator and wildcard-injection risks.
    #[must_use]
    pub const fn acknowledge_slashes_and_wildcards() -> Self {
        Self {
            allow_slashes: true,
            allow_wildcards: true,
        }
    }
}

/// ACL policy create/update request.
#[derive(Clone, Default, Serialize)]
pub struct PolicyWriteRequest {
    /// Policy document.
    pub policy: String,
    /// Expiration timestamp (OpenBao 2.3.1+). Mutually exclusive with `ttl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    /// Policy lifetime duration (OpenBao 2.3.1+). Mutually exclusive with `expiration`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Check-and-set version (OpenBao 2.3.1+). Use `-1` for strict create.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas: Option<i64>,
    /// Whether check-and-set should be required by this update (OpenBao 2.3.1+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_required: Option<bool>,
}

impl fmt::Debug for PolicyWriteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyWriteRequest")
            .field("policy", &"<redacted>")
            .field("expiration", &self.expiration)
            .field("ttl", &self.ttl)
            .field("cas", &self.cas)
            .field("cas_required", &self.cas_required)
            .finish()
    }
}

/// ACL policy JSON Merge Patch request (OpenBao 2.6.1+).
///
/// Every field is optional because omission preserves the stored value.
/// This differs from [`PolicyWriteRequest`], where an omitted expiration on
/// POST/PUT clears the previous expiration.
#[derive(Clone, Default, Serialize)]
pub struct PolicyPatchRequest {
    /// Replacement policy document. Omission preserves the current document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Replacement expiration timestamp. Mutually exclusive with `ttl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    /// Replacement policy lifetime duration. Mutually exclusive with `expiration`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Required current policy version for this update.
    ///
    /// PATCH requires the policy to exist, so `-1` cannot provide strict
    /// creation semantics here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas: Option<i64>,
    /// Replacement check-and-set requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_required: Option<bool>,
}

impl fmt::Debug for PolicyPatchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyPatchRequest")
            .field("policy", &self.policy.as_ref().map(|_| "<redacted>"))
            .field("expiration", &self.expiration)
            .field("ttl", &self.ttl)
            .field("cas", &self.cas)
            .field("cas_required", &self.cas_required)
            .finish()
    }
}

#[cfg(feature = "identity-template-overrides-acknowledged")]
#[derive(Serialize)]
struct PolicyWriteWithIdentityTemplateOverrides<'a> {
    #[serde(flatten)]
    request: &'a PolicyWriteRequest,
    #[serde(skip_serializing_if = "is_false")]
    allow_slashes_in_identity_templates: bool,
    #[serde(skip_serializing_if = "is_false")]
    allow_wildcards_in_identity_templates: bool,
}

#[cfg(feature = "identity-template-overrides-acknowledged")]
#[derive(Serialize)]
struct PolicyPatchWithIdentityTemplateOverrides<'a> {
    #[serde(flatten)]
    request: &'a PolicyPatchRequest,
    #[serde(skip_serializing_if = "is_false")]
    allow_slashes_in_identity_templates: bool,
    #[serde(skip_serializing_if = "is_false")]
    allow_wildcards_in_identity_templates: bool,
}

#[cfg(feature = "identity-template-overrides-acknowledged")]
const fn is_false(value: &bool) -> bool {
    !*value
}

impl PolicyWriteRequest {
    /// Creates a policy write request from an ACL policy document.
    pub fn new(policy: impl Into<String>) -> Self {
        Self {
            policy: policy.into(),
            ..Self::default()
        }
    }

    /// Sets the policy lifetime duration.
    #[must_use]
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.ttl = Some(ttl.into());
        self
    }

    fn validate(&self) -> Result<()> {
        if self.expiration.is_some() && self.ttl.is_some() {
            return Err(Error::InvalidParameter(
                "policy expiration and ttl are mutually exclusive".into(),
            ));
        }
        if let Some(ttl) = &self.ttl {
            crate::validation::validate_duration_parameter(ttl, "policy ttl")?;
        }
        Ok(())
    }
}

impl PolicyPatchRequest {
    /// Creates an empty patch. Select at least one field before sending it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policy: None,
            expiration: None,
            ttl: None,
            cas: None,
            cas_required: None,
        }
    }

    /// Replaces the policy document while preserving omitted metadata.
    #[must_use]
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }

    /// Replaces the policy lifetime duration while preserving other fields.
    #[must_use]
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.ttl = Some(ttl.into());
        self
    }

    fn validate(&self) -> Result<()> {
        if self.policy.is_none()
            && self.expiration.is_none()
            && self.ttl.is_none()
            && self.cas.is_none()
            && self.cas_required.is_none()
        {
            return Err(Error::InvalidParameter(
                "ACL policy patch must select at least one field".into(),
            ));
        }
        if self.expiration.is_some() && self.ttl.is_some() {
            return Err(Error::InvalidParameter(
                "policy expiration and ttl are mutually exclusive".into(),
            ));
        }
        if let Some(ttl) = &self.ttl {
            crate::validation::validate_duration_parameter(ttl, "policy ttl")?;
        }
        if self.cas.is_some_and(|cas| cas < 1) {
            return Err(Error::InvalidParameter(
                "ACL policy PATCH cas must be a positive existing policy version".into(),
            ));
        }
        Ok(())
    }
}

/// Password policy list response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasswordPolicyList {
    /// Password policy names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for PasswordPolicyList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Password policy read response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasswordPolicy {
    /// Password policy document.
    ///
    /// OpenBao accepts the policy language as an opaque document. The SDK does
    /// not parse or reinterpret it.
    pub policy: String,
}

/// Password policy write request.
#[derive(Clone, Debug, Serialize)]
pub struct PasswordPolicyWriteRequest {
    /// Password policy document.
    pub policy: String,
}

impl PasswordPolicyWriteRequest {
    /// Creates a password policy write request.
    #[must_use]
    pub fn new(policy: impl Into<String>) -> Self {
        Self {
            policy: policy.into(),
        }
    }
}

/// Generated password returned by `/sys/policies/password/:name/generate`.
#[derive(Clone, Deserialize)]
pub struct GeneratedPassword {
    /// Generated password. Treat as credential material.
    pub password: SecretString,
}

impl fmt::Debug for GeneratedPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedPassword")
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Capability name returned by OpenBao capability inspection endpoints.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    /// Allows creation when a value does not already exist.
    Create,
    /// Allows reading an existing value or metadata.
    Read,
    /// Allows updating an existing value.
    Update,
    /// Allows deleting a value.
    Delete,
    /// Allows listing path children.
    List,
    /// Allows partial patch updates.
    Patch,
    /// Allows privileged system operations on paths that require sudo.
    Sudo,
    /// Denies access.
    Deny,
    /// Root-level capability returned for root tokens.
    Root,
    /// Capability name not known by this crate version.
    Unknown(String),
}

impl Capability {
    /// Parses a capability name while preserving unknown future values.
    #[must_use]
    pub fn from_name(name: impl AsRef<str>) -> Self {
        match name.as_ref() {
            "create" => Self::Create,
            "read" => Self::Read,
            "update" => Self::Update,
            "delete" => Self::Delete,
            "list" => Self::List,
            "patch" => Self::Patch,
            "sudo" => Self::Sudo,
            "deny" => Self::Deny,
            "root" => Self::Root,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Returns the OpenBao capability name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Patch => "patch",
            Self::Sudo => "sudo",
            Self::Deny => "deny",
            Self::Root => "root",
            Self::Unknown(name) => name.as_str(),
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<&str> for Capability {
    fn from(value: &str) -> Self {
        Self::from_name(value)
    }
}

impl From<String> for Capability {
    fn from(value: String) -> Self {
        Self::from_name(value)
    }
}

/// Borrowed typed view over one OpenBao capability list.
#[derive(Clone, Copy, Debug)]
pub struct CapabilityView<'a> {
    capabilities: &'a [String],
}

impl<'a> CapabilityView<'a> {
    /// Returns the original capability names returned by OpenBao.
    #[must_use]
    pub fn raw(self) -> &'a [String] {
        self.capabilities
    }

    /// Iterates over typed capabilities, preserving unknown future values.
    pub fn iter(self) -> impl Iterator<Item = Capability> + 'a {
        self.capabilities.iter().map(Capability::from_name)
    }

    /// Returns true when this list contains the given capability.
    #[must_use]
    pub fn contains(self, capability: Capability) -> bool {
        self.contains_name(capability.as_str())
    }

    /// Returns true when OpenBao explicitly denied access.
    #[must_use]
    pub fn is_denied(self) -> bool {
        self.contains_name(Capability::Deny.as_str())
    }

    /// Returns true when this list contains at least one effective capability.
    ///
    /// Empty lists and explicit `deny` responses are not permitted. A `root`
    /// capability is considered permitted.
    #[must_use]
    pub fn is_permitted(self) -> bool {
        !self.capabilities.is_empty() && !self.is_denied()
    }

    /// Returns true when the capability list allows create.
    #[must_use]
    pub fn can_create(self) -> bool {
        self.allows(Capability::Create)
    }

    /// Returns true when the capability list allows read.
    #[must_use]
    pub fn can_read(self) -> bool {
        self.allows(Capability::Read)
    }

    /// Returns true when the capability list allows update.
    #[must_use]
    pub fn can_update(self) -> bool {
        self.allows(Capability::Update)
    }

    /// Returns true when the capability list allows delete.
    #[must_use]
    pub fn can_delete(self) -> bool {
        self.allows(Capability::Delete)
    }

    /// Returns true when the capability list allows list.
    #[must_use]
    pub fn can_list(self) -> bool {
        self.allows(Capability::List)
    }

    /// Returns true when the capability list allows patch.
    #[must_use]
    pub fn can_patch(self) -> bool {
        self.allows(Capability::Patch)
    }

    /// Returns true when the capability list allows sudo.
    #[must_use]
    pub fn can_sudo(self) -> bool {
        self.allows(Capability::Sudo)
    }

    fn allows(self, capability: Capability) -> bool {
        !self.is_denied()
            && (self.contains_name(Capability::Root.as_str()) || self.contains(capability))
    }

    fn contains_name(self, capability: &str) -> bool {
        self.capabilities
            .iter()
            .any(|candidate| candidate == capability)
    }
}

/// Capabilities returned for queried OpenBao paths.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Capabilities {
    /// Backwards-compatible capabilities field returned for single-path queries.
    pub capabilities: Vec<String>,
    /// Capabilities keyed by queried path.
    #[serde(flatten)]
    pub by_path: BTreeMap<String, Vec<String>>,
}

/// Capabilities attached to one resultant ACL path.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ResultantAclPath {
    /// Capability names for the path.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub capabilities: Vec<String>,
}

impl ResultantAclPath {
    /// Borrows the capability list as typed helper methods.
    #[must_use]
    pub fn capabilities(&self) -> CapabilityView<'_> {
        CapabilityView {
            capabilities: &self.capabilities,
        }
    }
}

/// Resultant ACL returned by `/sys/internal/ui/resultant-acl`.
///
/// OpenBao documents this as an internal UI endpoint with no backwards
/// compatibility guarantee. The SDK models only the stable-in-practice path
/// maps and root flag; new fields are ignored.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ResultantAcl {
    /// Exact paths keyed by OpenBao path.
    #[serde(default, deserialize_with = "deserialize_bounded_resultant_acl_map")]
    pub exact_paths: BTreeMap<String, ResultantAclPath>,
    /// Glob/prefix paths keyed by OpenBao path.
    #[serde(default, deserialize_with = "deserialize_bounded_resultant_acl_map")]
    pub glob_paths: BTreeMap<String, ResultantAclPath>,
    /// Whether the requesting token has root-level access.
    #[serde(default)]
    pub root: bool,
    /// Namespace root used by UI callers, when returned.
    #[serde(default)]
    pub chroot_namespace: Option<String>,
}

/// In-flight OpenBao request metadata.
///
/// Treat this as sensitive operational data: paths, client addresses, and
/// token accessors can reveal active workloads and secret topology.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct InFlightRequest {
    /// Request start timestamp.
    #[serde(default)]
    pub start_time: Option<String>,
    /// Client remote address.
    #[serde(default, alias = "remote_address")]
    pub client_remote_address: Option<String>,
    /// Request path.
    #[serde(default, alias = "path")]
    pub request_path: Option<String>,
    /// HTTP method.
    #[serde(default, alias = "method")]
    pub request_method: Option<String>,
    /// Client identifier, when returned.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Token accessor for the active request, when returned by OpenBao.
    #[serde(default, alias = "client_token_accessor")]
    pub accessor: Option<SecretString>,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for InFlightRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InFlightRequest")
            .field("start_time", &self.start_time)
            .field("client_remote_address", &self.client_remote_address)
            .field("request_path", &self.request_path)
            .field("request_method", &self.request_method)
            .field("client_id", &self.client_id)
            .field("accessor", &"<redacted>")
            .finish()
    }
}

/// In-flight request map keyed by OpenBao request ID.
///
/// Available only with `operator-ops` and `operator-ops-acknowledged`.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct InFlightRequests(
    /// Request metadata keyed by request ID.
    #[serde(deserialize_with = "deserialize_bounded_in_flight_request_map")]
    pub BTreeMap<String, InFlightRequest>,
);

/// Login MFA validation request for `/sys/mfa/validate`.
#[derive(Clone)]
pub struct MfaValidateRequest {
    /// MFA request ID returned in a login auth response with an MFA requirement.
    pub mfa_request_id: String,
    /// MFA method IDs or method names mapped to passcode credentials.
    pub mfa_payload: BTreeMap<String, Vec<SecretString>>,
}

impl MfaValidateRequest {
    /// Creates an MFA validation request.
    pub fn new(mfa_request_id: impl Into<String>) -> Self {
        Self {
            mfa_request_id: mfa_request_id.into(),
            mfa_payload: BTreeMap::new(),
        }
    }

    /// Adds one MFA method credential.
    ///
    /// OpenBao accepts method UUIDs or method names as keys. For methods that
    /// do not use passcodes, pass an empty `SecretString`.
    #[must_use]
    pub fn with_passcode(
        mut self,
        method_id_or_name: impl Into<String>,
        passcode: SecretString,
    ) -> Self {
        self.mfa_payload
            .entry(method_id_or_name.into())
            .or_default()
            .push(passcode);
        self
    }

    /// Adds multiple credentials for one MFA method.
    #[must_use]
    pub fn with_passcodes(
        mut self,
        method_id_or_name: impl Into<String>,
        passcodes: impl IntoIterator<Item = SecretString>,
    ) -> Self {
        self.mfa_payload
            .entry(method_id_or_name.into())
            .or_default()
            .extend(passcodes);
        self
    }

    fn validate(&self) -> Result<()> {
        if self.mfa_request_id.trim().is_empty() {
            return Err(Error::InvalidParameter(
                "MFA request ID must not be empty".into(),
            ));
        }
        if self.mfa_payload.is_empty() {
            return Err(Error::InvalidParameter(
                "MFA validation requires at least one method credential".into(),
            ));
        }
        if self.mfa_payload.len() > crate::response::MAX_RESPONSE_STRINGS {
            return Err(Error::InvalidParameter(
                "MFA validation method count exceeds item limit".into(),
            ));
        }
        for (method, passcodes) in &self.mfa_payload {
            if method.trim().is_empty() {
                return Err(Error::InvalidParameter(
                    "MFA validation method IDs must not be empty".into(),
                ));
            }
            if passcodes.is_empty() || passcodes.len() > crate::response::MAX_RESPONSE_STRINGS {
                return Err(Error::InvalidParameter(
                    "MFA validation passcode list must be non-empty and bounded".into(),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for MfaValidateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MfaValidateRequest")
            .field("mfa_request_id", &self.mfa_request_id)
            .field("mfa_payload", &"<redacted>")
            .finish()
    }
}

impl Serialize for MfaValidateRequest {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Payload<'a> {
            mfa_request_id: &'a str,
            mfa_payload: BTreeMap<&'a str, Vec<&'a str>>,
        }

        let mut mfa_payload = BTreeMap::new();
        for (method, passcodes) in &self.mfa_payload {
            mfa_payload.insert(
                method.as_str(),
                passcodes
                    .iter()
                    .map(SecretString::expose_secret)
                    .collect::<Vec<_>>(),
            );
        }
        Payload {
            mfa_request_id: &self.mfa_request_id,
            mfa_payload,
        }
        .serialize(serializer)
    }
}

/// Auth response returned after successful MFA validation.
#[derive(Clone, Deserialize)]
pub struct MfaValidateAuth {
    /// Client token returned by OpenBao.
    pub client_token: SecretString,
    /// Token accessor returned by OpenBao.
    pub accessor: SecretString,
    /// Policies attached to the token.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Token policies attached to the token.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub token_policies: Vec<String>,
    /// Identity policies attached to the token.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_vec")]
    pub identity_policies: Option<Vec<String>>,
    /// Token metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
    /// Whether the token is orphaned.
    #[serde(default)]
    pub orphan: bool,
    /// Entity ID associated with the token.
    #[serde(default)]
    pub entity_id: Option<String>,
    /// Lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the token is renewable.
    #[serde(default)]
    pub renewable: bool,
}

impl fmt::Debug for MfaValidateAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MfaValidateAuth")
            .field("client_token", &"<redacted>")
            .field("accessor", &"<redacted>")
            .field("policies", &self.policies)
            .field("token_policies", &self.token_policies)
            .field("identity_policies", &self.identity_policies)
            .field("metadata", &self.metadata)
            .field("orphan", &self.orphan)
            .field("entity_id", &self.entity_id)
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .finish()
    }
}

#[derive(Deserialize)]
struct MfaValidateEnvelope {
    auth: Option<MfaValidateAuth>,
}

impl Capabilities {
    /// Returns the single-path compatibility capability list.
    #[must_use]
    pub fn single_path(&self) -> CapabilityView<'_> {
        CapabilityView {
            capabilities: &self.capabilities,
        }
    }

    /// Returns true when the single-path compatibility list has any effective
    /// capability.
    #[must_use]
    pub fn is_permitted(&self) -> bool {
        self.single_path().is_permitted()
    }

    /// Returns capabilities for one queried path.
    ///
    /// Leading slashes are ignored to match the normalization used by request
    /// path validation.
    #[must_use]
    pub fn for_path(&self, path: &str) -> Option<CapabilityView<'_>> {
        let path = path.trim_start_matches('/');
        self.by_path
            .get(path)
            .map(|capabilities| CapabilityView { capabilities })
    }

    /// Iterates over path-keyed capability lists.
    pub fn paths(&self) -> impl Iterator<Item = (&str, CapabilityView<'_>)> {
        self.by_path
            .iter()
            .map(|(path, capabilities)| (path.as_str(), CapabilityView { capabilities }))
    }

    /// Returns true when the path-keyed capability list allows read.
    #[must_use]
    pub fn can_read_path(&self, path: &str) -> bool {
        self.for_path(path).is_some_and(CapabilityView::can_read)
    }

    /// Returns true when the path-keyed capability list allows update.
    #[must_use]
    pub fn can_update_path(&self, path: &str) -> bool {
        self.for_path(path).is_some_and(CapabilityView::can_update)
    }

    /// Returns true when the path-keyed capability list allows delete.
    #[must_use]
    pub fn can_delete_path(&self, path: &str) -> bool {
        self.for_path(path).is_some_and(CapabilityView::can_delete)
    }

    /// Returns true when the path-keyed capability list allows list.
    #[must_use]
    pub fn can_list_path(&self, path: &str) -> bool {
        self.for_path(path).is_some_and(CapabilityView::can_list)
    }
}

impl<'de> Deserialize<'de> for Capabilities {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(CapabilitiesVisitor)
    }
}

struct CapabilitiesVisitor;

impl<'de> Visitor<'de> for CapabilitiesVisitor {
    type Value = Capabilities;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded OpenBao capabilities object")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut capabilities = None;
        let mut by_path = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if key == "capabilities" {
                if capabilities.is_some() {
                    return Err(A::Error::custom("duplicate capabilities field"));
                }
                capabilities = Some(map.next_value::<BoundedStringList>()?.0);
                continue;
            }
            if by_path.len() >= crate::response::MAX_RESPONSE_STRINGS {
                let _ignored = map.next_value::<IgnoredAny>()?;
                return Err(A::Error::custom(
                    "OpenBao capabilities map exceeds item limit",
                ));
            }
            by_path.insert(key, map.next_value::<BoundedStringList>()?.0);
        }
        Ok(Capabilities {
            capabilities: capabilities.unwrap_or_default(),
            by_path,
        })
    }
}

fn deserialize_bounded_resultant_acl_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, ResultantAclPath>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedMapVisitor::<
        ResultantAclPath,
        { crate::response::MAX_RESPONSE_STRINGS },
    > {
        message: "OpenBao resultant ACL map exceeds item limit",
        _marker: PhantomData,
    })
}

#[cfg(feature = "operator-ops")]
fn deserialize_bounded_secret_string_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedMapVisitor::<
        SecretString,
        { crate::response::MAX_RESPONSE_STRINGS },
    > {
        message: "OpenBao secret string map exceeds item limit",
        _marker: PhantomData,
    })
}

#[cfg(feature = "operator-ops")]
fn deserialize_bounded_in_flight_request_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, InFlightRequest>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedMapVisitor::<
        InFlightRequest,
        { crate::response::MAX_RESPONSE_STRINGS },
    > {
        message: "OpenBao in-flight request map exceeds item limit",
        _marker: PhantomData,
    })
}

struct BoundedMapVisitor<T, const MAX: usize> {
    message: &'static str,
    _marker: PhantomData<T>,
}

impl<'de, T, const MAX: usize> Visitor<'de> for BoundedMapVisitor<T, MAX>
where
    T: Deserialize<'de>,
{
    type Value = BTreeMap<String, T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} OpenBao entries")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, T>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(self.message));
        }
        Ok(values)
    }
}

/// Enabled audit device information returned by `/sys/audit`.
#[derive(Clone, Debug, Deserialize)]
pub struct AuditDevice {
    /// Audit device type, such as `file`, `socket`, or `syslog`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable audit device description.
    #[serde(default)]
    pub description: Option<String>,
    /// Audit-device-specific options.
    #[serde(default, deserialize_with = "deserialize_bounded_string_map")]
    pub options: BTreeMap<String, String>,
    /// Whether this audit device is local to the node.
    #[serde(default)]
    pub local: bool,
}

/// Request for enabling an audit device.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AuditEnableRequest {
    /// Audit device type, such as `file`, `socket`, or `syslog`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable audit device description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Audit-device-specific options.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// Whether this audit device is local to the node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
}

impl AuditEnableRequest {
    /// Creates an audit-device enable request for `backend_type`.
    pub fn new(backend_type: impl Into<String>) -> Self {
        Self {
            backend_type: backend_type.into(),
            ..Self::default()
        }
    }

    /// Sets a human-readable audit-device description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Audit hash response returned by `/sys/audit-hash/:path`.
#[derive(Clone, Debug, Deserialize)]
pub struct AuditHash {
    /// HMAC value computed by OpenBao for the supplied audit device and input.
    pub hash: String,
}

/// Audited request headers returned by `/sys/config/auditing/request-headers`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuditedRequestHeaders {
    /// Audited request-header configuration keyed by header name.
    #[serde(default, deserialize_with = "deserialize_bounded_audited_header_map")]
    pub headers: BTreeMap<String, AuditedRequestHeaderConfig>,
}

/// Audit configuration for one request header.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct AuditedRequestHeaderConfig {
    /// Whether OpenBao should HMAC this header value in audit logs.
    #[serde(default)]
    pub hmac: bool,
}

impl AuditedRequestHeaderConfig {
    /// Creates audited request-header configuration.
    #[must_use]
    pub const fn new(hmac: bool) -> Self {
        Self { hmac }
    }
}

/// Metadata returned by `/sys/leases/lookup`.
#[derive(Clone, Deserialize)]
pub struct LeaseLookup {
    /// Lease identifier. This can revoke the secret and is treated as secret material.
    pub id: SecretString,
    /// Lease issue timestamp.
    pub issue_time: String,
    /// Lease expiration timestamp.
    pub expire_time: String,
    /// Last renewal timestamp, when the lease has been renewed.
    #[serde(default)]
    pub last_renewal: Option<String>,
    /// Whether this lease is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Remaining lease TTL in seconds.
    #[serde(default)]
    pub ttl: u64,
}

impl fmt::Debug for LeaseLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseLookup")
            .field("id", &"<redacted>")
            .field("issue_time", &self.issue_time)
            .field("expire_time", &self.expire_time)
            .field("last_renewal", &self.last_renewal)
            .field("renewable", &self.renewable)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Lease metadata including fields introduced by OpenBao 2.6.
#[derive(Clone, Deserialize)]
pub struct LeaseLookupDetails {
    /// Lease metadata available across supported OpenBao releases.
    #[serde(flatten)]
    pub lease: LeaseLookup,
    /// Namespace containing the lease.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub namespace_path: Option<String>,
    /// Backend path that issued the lease.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub path: Option<String>,
    /// Revocation error retained by OpenBao.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_safe_metadata_string"
    )]
    pub revoke_error: Option<String>,
}

impl fmt::Debug for LeaseLookupDetails {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseLookupDetails")
            .field("lease", &self.lease)
            .field(
                "namespace_path",
                &self.namespace_path.as_ref().map(|_| "<redacted>"),
            )
            .field("path", &self.path.as_ref().map(|_| "<redacted>"))
            .field(
                "revoke_error",
                &self.revoke_error.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Result of renewing a lease.
#[derive(Clone)]
pub struct LeaseRenewal {
    /// Renewed lease identifier. This can revoke the secret and is treated as secret material.
    pub lease_id: SecretString,
    /// Renewed lease duration in seconds.
    pub lease_duration: u64,
    /// Whether this lease remains renewable.
    pub renewable: bool,
}

/// Lease count summary returned by `/sys/leases/count`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LeaseCount {
    /// Total lease count returned by OpenBao.
    #[serde(default)]
    pub lease_count: u64,
    /// Counts grouped by mount or namespace path.
    #[serde(default, deserialize_with = "deserialize_bounded_u64_map")]
    pub counts: BTreeMap<String, u64>,
}

/// Lease identifiers returned by a prefix listing.
#[derive(Clone, Default, Deserialize)]
pub struct LeaseIdList {
    /// Lease identifiers. Each value can be used to revoke a credential and is
    /// therefore treated as secret material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys: Vec<SecretString>,
}

impl fmt::Debug for LeaseIdList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseIdList")
            .field("keys_count", &self.keys.len())
            .finish()
    }
}

impl fmt::Debug for LeaseRenewal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseRenewal")
            .field("lease_id", &"<redacted>")
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .finish()
    }
}

/// OpenBao plugin catalog type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginType {
    /// Auth method plugin.
    Auth,
    /// Database plugin.
    Database,
    /// Secret engine plugin.
    Secret,
}

impl PluginType {
    fn as_path_segment(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Database => "database",
            Self::Secret => "secret",
        }
    }
}

/// Summary of all plugin catalog entries grouped by type.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PluginCatalog {
    /// Auth plugin names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub auth: Vec<String>,
    /// Database plugin names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub database: Vec<String>,
    /// Secret plugin names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub secret: Vec<String>,
    /// Detailed plugin summaries, when returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_plugin_detail_vec")]
    pub detailed: Vec<PluginDetail>,
}

/// Plugin catalog entry returned in detailed listings.
#[derive(Clone, Debug, Deserialize)]
pub struct PluginDetail {
    /// Plugin name.
    pub name: String,
    /// Plugin type.
    #[serde(rename = "type")]
    pub plugin_type: String,
    /// Plugin version.
    #[serde(default)]
    pub version: Option<String>,
    /// Whether this is built into OpenBao.
    #[serde(default)]
    pub builtin: bool,
    /// OpenBao deprecation status.
    #[serde(default)]
    pub deprecation_status: Option<String>,
}

/// Plugin names for one catalog type.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PluginList {
    /// Plugin names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for PluginList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request for registering or updating a plugin catalog entry.
#[derive(Clone)]
pub struct PluginRegisterRequest {
    /// Semantic plugin version.
    pub version: Option<String>,
    /// 64-character hex SHA-256 digest of the plugin binary.
    pub sha256: String,
    /// Command used to execute the plugin, relative to OpenBao's plugin directory.
    pub command: String,
    /// Command arguments. Treat as secret material because operators often put credentials in args.
    pub args: Vec<SecretString>,
    /// Environment entries in `KEY=value` form. Treat as secret material.
    pub env: Vec<SecretString>,
    /// Whether the plugin is an OCI-backed declarative plugin (OpenBao 2.5+).
    pub oci: Option<bool>,
}

impl fmt::Debug for PluginRegisterRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginRegisterRequest")
            .field("version", &self.version)
            .field("sha256", &self.sha256)
            .field("command", &self.command)
            .field("args", &format_args!("<{} redacted>", self.args.len()))
            .field("env", &format_args!("<{} redacted>", self.env.len()))
            .field("oci", &self.oci)
            .finish()
    }
}

/// Plugin catalog entry configuration.
#[derive(Clone, Deserialize)]
pub struct PluginInfo {
    /// Plugin name.
    pub name: String,
    /// Semantic plugin version.
    #[serde(default)]
    pub version: Option<String>,
    /// Whether this plugin is built into OpenBao.
    #[serde(default)]
    pub builtin: bool,
    /// Command used to execute the plugin.
    #[serde(default)]
    pub command: Option<String>,
    /// Plugin binary SHA-256 digest.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Command arguments. Treated as secret material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub args: Vec<SecretString>,
    /// Environment entries. Treated as secret material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub env: Vec<SecretString>,
    /// OpenBao deprecation status.
    #[serde(default)]
    pub deprecation_status: Option<String>,
    /// Whether this is a declarative plugin (OpenBao 2.5+).
    #[serde(default)]
    pub declarative: Option<bool>,
    /// Whether this plugin is backed by an OCI image (OpenBao 2.5+).
    #[serde(default)]
    pub oci: Option<bool>,
}

impl fmt::Debug for PluginInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginInfo")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("builtin", &self.builtin)
            .field("command", &self.command)
            .field("sha256", &self.sha256)
            .field("args", &format_args!("<{} redacted>", self.args.len()))
            .field("env", &format_args!("<{} redacted>", self.env.len()))
            .field("deprecation_status", &self.deprecation_status)
            .field("declarative", &self.declarative)
            .field("oci", &self.oci)
            .finish()
    }
}

/// Request for reloading mounted plugin backends.
#[derive(Clone, Debug, Default)]
pub struct PluginReloadRequest {
    /// Plugin name to reload across all mounts on this node or cluster.
    pub plugin: Option<String>,
    /// Mount paths to reload.
    pub mounts: Vec<String>,
    /// Reload scope, such as `global`.
    pub scope: Option<String>,
}

#[derive(Serialize)]
struct WrappingTokenPayload<'a> {
    token: &'a str,
}

#[derive(Serialize)]
struct AuditHashPayload<'a> {
    input: &'a str,
}

#[derive(Serialize)]
struct LeaseLookupPayload<'a> {
    lease_id: &'a str,
}

#[derive(Serialize)]
struct LeaseRenewPayload<'a> {
    lease_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    increment: Option<u64>,
}

#[derive(Serialize)]
struct LeaseRevokePayload<'a> {
    lease_id: &'a str,
}

#[derive(Serialize)]
struct PluginRegisterPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    sha256: &'a str,
    command: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    args: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    env: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oci: Option<bool>,
}

#[derive(Serialize)]
struct PluginReloadPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

#[derive(Serialize)]
struct LoggerLevelPayload<'a> {
    level: &'a str,
}

#[derive(Serialize)]
struct LockedUsersPayload<'a> {
    mount_accessor: &'a str,
}

#[derive(Serialize)]
struct RaftJoinPayload<'a> {
    leader_api_addr: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leader_ca_cert: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leader_client_cert: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leader_client_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leader_tls_servername: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_join: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_join_scheme: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_join_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    non_voter: Option<bool>,
}

#[derive(Serialize)]
struct RaftPeerPayload<'a> {
    server_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dr_operation_token: Option<&'a str>,
}

#[derive(Clone, Copy)]
enum RaftPeerOperation {
    Remove,
    Promote,
    Demote,
}

impl RaftPeerOperation {
    const fn as_path_segment(self) -> &'static str {
        match self {
            Self::Remove => "remove-peer",
            Self::Promote => "promote",
            Self::Demote => "demote",
        }
    }
}

#[derive(Serialize)]
struct CapabilitiesPayload<'a> {
    paths: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accessor: Option<&'a str>,
}

#[derive(Serialize)]
struct SysRandomPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<SysToolsOutputFormat>,
}

#[derive(Serialize)]
struct SysHashPayload<'a> {
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<SysToolsOutputFormat>,
}

#[cfg(feature = "operator-ops")]
#[derive(Serialize)]
struct RawWritePayload<'a> {
    value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    compression_type: Option<RawCompression>,
    #[serde(skip_serializing_if = "RawEncoding::is_none")]
    encoding: RawEncoding,
}

#[cfg(feature = "dev-bootstrap")]
#[derive(Serialize)]
struct InitPayload {
    secret_shares: u8,
    secret_threshold: u8,
}

#[cfg(feature = "dev-bootstrap")]
#[derive(Deserialize)]
struct InitResponse {
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    keys: Vec<SecretString>,
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    keys_base64: Vec<SecretString>,
    root_token: SecretString,
}

#[cfg(feature = "dev-bootstrap")]
#[derive(Serialize)]
struct UnsealPayload<'a> {
    key: &'a str,
}

#[cfg(feature = "operator-ops")]
#[derive(Serialize)]
struct OperatorUnsealPayload<'a> {
    key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reset: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    migrate: Option<bool>,
}

#[cfg(feature = "operator-ops")]
#[derive(Serialize)]
struct OperatorKeyShareUpdatePayload<'a> {
    key: &'a str,
    nonce: &'a str,
}

impl<State> Client<State> {
    /// Accesses system backend helpers.
    pub fn sys(&self) -> Sys<'_, State> {
        Sys { client: self }
    }
}

impl<State> Sys<'_, State> {
    /// Reads `/sys/init` initialization status.
    pub async fn init_status(&self) -> Result<InitStatus> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/init", Option::<&Empty>::None)
            .await
    }

    /// Reads `/sys/health`.
    ///
    /// Health endpoints intentionally return non-200 status codes for standby,
    /// sealed, or uninitialized nodes. Those statuses are accepted and decoded.
    pub async fn health(&self) -> Result<Health> {
        self.client
            .request_sys_json_accepting(
                Method::GET,
                "sys/health",
                Option::<&Empty>::None,
                &[
                    StatusCode::OK,
                    StatusCode::NO_CONTENT,
                    StatusCode::TOO_MANY_REQUESTS,
                    StatusCode::NOT_IMPLEMENTED,
                    StatusCode::SERVICE_UNAVAILABLE,
                    openbao_status(472)?,
                    openbao_status(473)?,
                ],
            )
            .await
    }

    /// Performs a bodyless `/sys/health` probe.
    pub async fn health_head(&self) -> Result<()> {
        self.client
            .request_sys_bytes_accepting_internal(
                Method::HEAD,
                "sys/health",
                &[],
                None,
                None,
                &[
                    StatusCode::OK,
                    StatusCode::NO_CONTENT,
                    StatusCode::TOO_MANY_REQUESTS,
                    StatusCode::NOT_IMPLEMENTED,
                    StatusCode::SERVICE_UNAVAILABLE,
                    openbao_status(472)?,
                    openbao_status(473)?,
                ],
            )
            .await?;
        Ok(())
    }

    /// Reads `/sys/seal-status`.
    pub async fn seal_status(&self) -> Result<SealStatus> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/seal-status", Option::<&Empty>::None)
            .await
    }

    /// Reads `/sys/seal-status` with build and recovery-seal metadata.
    pub async fn seal_status_details(&self) -> Result<SealStatusDetails> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/seal-status", Option::<&Empty>::None)
            .await
    }

    /// Polls `/sys/seal-status` until OpenBao is initialized and unsealed.
    ///
    /// Available only with the non-default `tokio-helpers` feature. This is a
    /// bounded startup/recovery helper: it returns the first unsealed status or
    /// an SDK timeout error after `timeout` elapses. It does not install
    /// request-level back-pressure, retry middleware, or background polling;
    /// applications remain responsible for ongoing sealed-node behavior.
    ///
    /// The caller's Tokio runtime must have time enabled.
    #[cfg(feature = "tokio-helpers")]
    pub async fn wait_until_unsealed(
        &self,
        timeout: std::time::Duration,
        interval: std::time::Duration,
    ) -> Result<SealStatus> {
        if timeout.is_zero() {
            return Err(Error::InvalidTimeout(
                "OpenBao unseal wait timeout must be greater than zero",
            ));
        }
        match tokio::time::timeout(
            timeout,
            self.wait_until_unsealed_with_delay(timeout, interval, tokio::time::sleep),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(Error::InvalidTimeout(
                "OpenBao did not become unsealed within timeout",
            )),
        }
    }

    /// Polls `/sys/seal-status` until OpenBao is initialized and unsealed.
    ///
    /// This runtime-neutral variant lets callers provide their own async delay
    /// function. It is useful for custom runtimes and deterministic tests.
    /// Transport failures are retried until the retry budget is exhausted;
    /// non-transient errors are returned immediately. Sleeps are capped to the
    /// remaining budget, but this runtime-neutral method cannot interrupt an
    /// in-flight HTTP future. Use [`Self::wait_until_unsealed`] with
    /// `tokio-helpers` when `timeout` must be a strict overall deadline.
    pub async fn wait_until_unsealed_with_delay<F, Fut>(
        &self,
        timeout: std::time::Duration,
        interval: std::time::Duration,
        mut delay: F,
    ) -> Result<SealStatus>
    where
        F: FnMut(std::time::Duration) -> Fut,
        Fut: core::future::Future<Output = ()>,
    {
        if timeout.is_zero() {
            return Err(Error::InvalidTimeout(
                "OpenBao unseal wait timeout must be greater than zero",
            ));
        }
        if interval.is_zero() {
            return Err(Error::InvalidTimeout(
                "OpenBao unseal wait poll interval must be greater than zero",
            ));
        }
        let start = std::time::Instant::now();
        loop {
            match self.seal_status().await {
                Ok(status) if status.initialized && !status.sealed => return Ok(status),
                Ok(_) => {}
                Err(error) if error.is_temporary() => {}
                Err(error) => return Err(error),
            }
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(Error::InvalidTimeout(
                    "OpenBao did not become unsealed within timeout",
                ));
            }
            delay(interval.min(timeout.saturating_sub(elapsed))).await;
        }
    }

    /// Polls `/sys/health` until OpenBao is initialized, unsealed, and active.
    ///
    /// Available only with the non-default `tokio-helpers` feature. The entire
    /// HTTP-and-delay future is bounded by `timeout`, so a slow in-flight
    /// request is cancelled when the deadline expires.
    ///
    /// The caller's Tokio runtime must have time enabled.
    #[cfg(feature = "tokio-helpers")]
    pub async fn wait_ready(
        &self,
        timeout: std::time::Duration,
        interval: std::time::Duration,
    ) -> Result<Health> {
        if timeout.is_zero() {
            return Err(Error::InvalidTimeout(
                "OpenBao readiness timeout must be greater than zero",
            ));
        }
        match tokio::time::timeout(
            timeout,
            self.wait_ready_with_delay(timeout, interval, tokio::time::sleep),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(Error::InvalidTimeout(
                "OpenBao did not become ready within timeout",
            )),
        }
    }

    /// Polls `/sys/health` until OpenBao is initialized, unsealed, and active.
    ///
    /// This helper is runtime-neutral: callers provide the async delay
    /// function. Sleeps are capped to the remaining retry budget. Transport
    /// failures, rate limiting, sealed responses, and server errors are
    /// retried; non-transient errors are returned immediately. This method
    /// cannot interrupt an in-flight HTTP future, so use [`Self::wait_ready`]
    /// with `tokio-helpers` when `timeout` must be a strict overall deadline.
    pub async fn wait_ready_with_delay<F, Fut>(
        &self,
        timeout: std::time::Duration,
        interval: std::time::Duration,
        mut delay: F,
    ) -> Result<Health>
    where
        F: FnMut(std::time::Duration) -> Fut,
        Fut: core::future::Future<Output = ()>,
    {
        if timeout.is_zero() {
            return Err(Error::InvalidTimeout(
                "OpenBao readiness timeout must be greater than zero",
            ));
        }
        if interval.is_zero() {
            return Err(Error::InvalidTimeout(
                "OpenBao readiness poll interval must be greater than zero",
            ));
        }
        let start = std::time::Instant::now();
        loop {
            match self.health().await {
                Ok(health) if health.initialized && !health.sealed && !health.standby => {
                    return Ok(health);
                }
                Ok(_) => {}
                Err(error) if error.is_temporary() => {}
                Err(error) => return Err(error),
            }
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(Error::InvalidTimeout(
                    "OpenBao did not become ready within timeout",
                ));
            }
            delay(interval.min(timeout.saturating_sub(elapsed))).await;
        }
    }

    /// Reads `/sys/leader`.
    pub async fn leader_status(&self) -> Result<LeaderStatus> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/leader", Option::<&Empty>::None)
            .await
    }

    /// Reads `/sys/ha-status`.
    pub async fn ha_status(&self) -> Result<HaStatus> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/ha-status", Option::<&Empty>::None)
            .await
    }

    /// Reads `/sys/key-status`.
    pub async fn key_status(&self) -> Result<KeyStatus> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/key-status", Option::<&Empty>::None)
            .await
    }

    /// Reads `/sys/internal/specs/openapi`.
    ///
    /// Set `generic_mount_paths` to replace concrete mount paths with a
    /// dynamic `{mountPath}` parameter when OpenBao supports it.
    pub async fn openapi_document(&self, generic_mount_paths: bool) -> Result<JsonValue> {
        let document: BoundedJsonValue = self
            .client
            .request_sys_json_query_accepting(
                Method::GET,
                "sys/internal/specs/openapi",
                &[("generic_mount_paths", generic_mount_paths.to_string())],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(document.into_inner())
    }

    /// Reads `/sys/internal/ui/namespaces`.
    ///
    /// OpenBao documents this endpoint as internal UI support without
    /// backwards compatibility guarantees.
    pub async fn ui_namespaces(&self) -> Result<UiNamespaces> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                "sys/internal/ui/namespaces",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads `/sys/internal/ui/mounts`.
    ///
    /// OpenBao documents this endpoint as internal UI and CLI preflight
    /// support without backwards compatibility guarantees.
    pub async fn ui_mounts(&self) -> Result<UiMounts> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                "sys/internal/ui/mounts",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads JSON telemetry metrics from `/sys/metrics`.
    ///
    /// Use [`Self::metrics_prometheus`] when the Prometheus text format is
    /// required.
    pub async fn metrics_json(&self) -> Result<JsonValue> {
        let document: BoundedJsonValue = self
            .client
            .request_sys_json_query_accepting(
                Method::GET,
                "sys/metrics",
                &[("format", "json".to_owned())],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(document.into_inner())
    }

    /// Reads Prometheus text telemetry metrics from `/sys/metrics`.
    ///
    /// The response still obeys [`OpenBaoConfig`](crate::OpenBaoConfig)'s
    /// maximum response size. Use a dedicated metrics token and keep telemetry
    /// label cardinality bounded in production deployments.
    pub async fn metrics_prometheus(&self) -> Result<String> {
        let body = self
            .client
            .request_sys_bytes_accepting_internal(
                Method::GET,
                "sys/metrics",
                &[("format", "prometheus".to_owned())],
                Some(HeaderValue::from_static("text/plain")),
                None,
                &[StatusCode::OK],
            )
            .await?;
        body.with_secret(|bytes| {
            String::from_utf8(bytes.to_vec())
                .map_err(|_| Error::Decode("OpenBao metrics response was not valid UTF-8".into()))
        })
    }

    /// Reads host diagnostics from `/sys/host-info`.
    ///
    /// OpenBao returns platform-specific CPU, disk, host, and memory sections,
    /// so this method exposes the `data` object as JSON while keeping the
    /// normal response-size and content-type protections.
    pub async fn host_info_json(&self) -> Result<JsonValue> {
        let envelope: ResponseEnvelope<BoundedJsonValue> = self
            .client
            .request_sys_json_internal(Method::GET, "sys/host-info", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data.into_inner())
    }

    /// Reads sanitized OpenBao configuration state from `/sys/config/state/sanitized`.
    ///
    /// OpenBao removes known sensitive configuration fields before returning
    /// this document. The schema is broad and deployment-specific, so this
    /// helper exposes the sanitized JSON object under the normal response-size
    /// and content-type protections.
    pub async fn sanitized_config_state_json(&self) -> Result<JsonValue> {
        let document: BoundedJsonValue = self
            .client
            .request_sys_json_internal(
                Method::GET,
                "sys/config/state/sanitized",
                Option::<&Empty>::None,
            )
            .await?;
        Ok(document.into_inner())
    }

    /// Reads runtime logger levels from `/sys/loggers`.
    pub async fn logger_levels(&self) -> Result<LoggerLevels> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/loggers", Option::<&Empty>::None)
            .await
    }

    /// Reads one runtime logger level from `/sys/loggers/:name`.
    pub async fn logger_level(&self, name: &str) -> Result<LoggerLevels> {
        self.client
            .request_sys_json_internal(Method::GET, &sys_logger_path(name)?, Option::<&Empty>::None)
            .await
    }
}

impl Sys<'_, Unauthenticated> {
    /// Executes a workflow without a token when OpenBao was configured with
    /// `allow_unauthenticated_workflows` and the stored workflow opts in.
    ///
    /// Available only with `unauthenticated-workflows` plus
    /// `unauthenticated-workflows-acknowledged`. The route is conditionally
    /// registered by OpenBao; this method never probes or falls back to an
    /// authenticated route.
    #[cfg(feature = "unauthenticated-workflows")]
    pub async fn execute_unauthenticated_workflow(
        &self,
        path: &str,
        input: &WorkflowData,
    ) -> Result<WorkflowData> {
        let path = workflow_path("sys/workflows/unauthed-execute", path)?;
        let body = self
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                Method::POST,
                &path,
                &path,
                &[] as &[(&str, &str)],
                Some(input),
                &[StatusCode::OK],
            )
            .await?;
        workflow_data_from_envelope(body)
    }

    /// Initializes a production OpenBao instance.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This can return root, unseal, or recovery material. Do not call this
    /// from normal application startup.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_init(
        &self,
        request: &OperatorInitRequest,
    ) -> Result<OperatorInitResponse> {
        if let (Some(shares), Some(threshold)) = (request.secret_shares, request.secret_threshold) {
            validate_key_share_options(shares, threshold)?;
        }
        if let (Some(shares), Some(threshold)) =
            (request.recovery_shares, request.recovery_threshold)
        {
            validate_key_share_options(shares, threshold)?;
        }
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::OPERATOR_INIT_STORED_SHARES,
                request.stored_shares.is_some(),
            )])
            .await?;
        self.client
            .request_sys_json_internal(Method::POST, "sys/init", Some(request))
            .await
    }

    /// Submits one production unseal key share.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_unseal(&self, request: &OperatorUnsealRequest) -> Result<UnsealStatus> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/unseal",
                Some(&OperatorUnsealPayload {
                    key: request.key.expose_secret(),
                    reset: request.reset,
                    migrate: request.migrate,
                }),
            )
            .await
    }

    /// Submits an unseal share and returns newer OpenBao build metadata.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_unseal_details(
        &self,
        request: &OperatorUnsealRequest,
    ) -> Result<UnsealStatusDetails> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/unseal",
                Some(&OperatorUnsealPayload {
                    key: request.key.expose_secret(),
                    reset: request.reset,
                    migrate: request.migrate,
                }),
            )
            .await
    }

    /// Retired compatibility shim for development bootstrap.
    ///
    /// This method fails closed because a numeric loopback address can forward
    /// to production. Enable `dev-bootstrap` and
    /// `dev-bootstrap-acknowledged`, then call
    /// [`Self::bootstrap_dev_acknowledged`] with an explicit acknowledgement.
    #[deprecated(
        since = "2.1.0",
        note = "enable dev-bootstrap plus dev-bootstrap-acknowledged and use bootstrap_dev_acknowledged"
    )]
    pub async fn bootstrap_dev(&self, _options: &DevBootstrapOptions) -> Result<DevBootstrap> {
        Err(Error::DevBootstrapDisabled)
    }

    /// Initializes and unseals a fresh loopback OpenBao development instance.
    ///
    /// This helper is intentionally narrow:
    ///
    /// - it refuses non-loopback targets;
    /// - it refuses already-initialized OpenBao instances;
    /// - it uses Shamir key shares and returns root/unseal material in memory;
    /// - it is for disposable local development and automated tests only.
    ///
    /// Do not use this for production, staging, shared labs, HSM/KMS-backed
    /// auto-unseal deployments, or any environment where root-token and unseal
    /// key handling must follow an operator ceremony.
    #[cfg(feature = "dev-bootstrap")]
    pub async fn bootstrap_dev_acknowledged(
        &self,
        _acknowledgement: DevBootstrapAcknowledgement,
        options: &DevBootstrapOptions,
    ) -> Result<DevBootstrap> {
        validate_dev_bootstrap_options(options.secret_shares, options.secret_threshold)?;
        require_loopback_dev_target(self.client)?;

        let init_status = self.init_status().await?;
        if init_status.initialized {
            return Err(Error::InvalidParameter(
                "dev bootstrap refuses to run against an already initialized OpenBao instance"
                    .into(),
            ));
        }

        let init_response: InitResponse = self
            .client
            .request_sys_json_internal(
                Method::POST,
                "sys/init",
                Some(&InitPayload {
                    secret_shares: options.secret_shares,
                    secret_threshold: options.secret_threshold,
                }),
            )
            .await?;

        if init_response.root_token.expose_secret().is_empty() {
            return Err(Error::MissingField("root_token"));
        }
        if init_response.keys.len() < usize::from(options.secret_threshold) {
            return Err(Error::MissingField("keys"));
        }

        let mut unseal_status = None;
        for key in init_response
            .keys
            .iter()
            .take(usize::from(options.secret_threshold))
        {
            let status = self.unseal_once(key).await?;
            let sealed = status.sealed;
            unseal_status = Some(status);
            if !sealed {
                break;
            }
        }

        let unseal_status = unseal_status.ok_or(Error::MissingField("unseal status"))?;
        if unseal_status.sealed {
            return Err(Error::Decode(
                "OpenBao remained sealed after submitting the configured dev threshold".into(),
            ));
        }

        let client = self
            .client
            .clone_without_state()
            .try_with_token(init_response.root_token.clone())?;

        Ok(DevBootstrap {
            client,
            root_token: init_response.root_token,
            unseal_keys: init_response.keys,
            unseal_keys_base64: init_response.keys_base64,
            unseal_status,
        })
    }

    #[cfg(feature = "dev-bootstrap")]
    async fn unseal_once(&self, key: &SecretString) -> Result<UnsealStatus> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/unseal",
                Some(&UnsealPayload {
                    key: key.expose_secret(),
                }),
            )
            .await
    }
}

impl Sys<'_, Authenticated> {
    /// Lists top-level workflow paths.
    ///
    /// OpenBao 2.6.0 returns `404` when no workflows exist; this method
    /// normalizes that state to an empty list.
    pub async fn list_workflows(&self) -> Result<WorkflowList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let result = self
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                method,
                "sys/workflows/manage",
                "sys/workflows/manage",
                &[] as &[(&str, &str)],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await;
        match result {
            Ok(body) => workflow_typed_data_from_envelope(body),
            Err(Error::Api { status, .. }) if status == StatusCode::NOT_FOUND => {
                Ok(WorkflowList::default())
            }
            Err(error) => Err(error),
        }
    }

    /// Recursively scans workflow paths with bounded pagination options.
    pub async fn scan_workflows(&self, options: &crate::ListPageOptions) -> Result<WorkflowList> {
        let method =
            Method::from_bytes(b"SCAN").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let query = options.query_pairs();
        let body = self
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                method,
                "sys/workflows/manage",
                "sys/workflows/manage",
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        workflow_typed_data_from_envelope(body)
    }

    /// Reads one stored workflow and its sensitive definition.
    pub async fn read_workflow(&self, path: &str) -> Result<WorkflowInfo> {
        let path = workflow_path("sys/workflows/manage", path)?;
        let body = self
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                Method::GET,
                &path,
                &path,
                &[] as &[(&str, &str)],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        workflow_typed_data_from_envelope(body)
    }

    /// Creates or updates one workflow without automatic retry.
    ///
    /// OpenBao 2.6.0 has a server-side CAS propagation defect. CAS-selected
    /// writes are rejected before transport while that release is the only
    /// workflow-capable profile. A future fixed profile can safely enable the
    /// already-modelled body field without changing this request type.
    pub async fn write_workflow(
        &self,
        path: &str,
        request: &WorkflowWriteRequest,
    ) -> Result<WorkflowInfo> {
        validate_workflow_write_request(request)?;
        let path = workflow_path("sys/workflows/manage", path)?;
        let payload = WorkflowWritePayload {
            workflow: request.workflow.expose_secret(),
            description: request.description.as_deref(),
            cas: request.cas,
            cas_required: request.cas_required,
            allow_unauthenticated: request.allow_unauthenticated,
        };
        let body = self
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                Method::POST,
                &path,
                &path,
                &[] as &[(&str, &str)],
                Some(&payload),
                &[StatusCode::OK],
            )
            .await?;
        workflow_typed_data_from_envelope(body)
    }

    /// Deletes one workflow. OpenBao does not apply CAS to deletion.
    pub async fn delete_workflow(&self, path: &str) -> Result<Empty> {
        let path = workflow_path("sys/workflows/manage", path)?;
        self.client
            .request_registered_secret_json_accepting(
                "/sys/",
                Method::DELETE,
                &path,
                &path,
                &[] as &[(&str, &str)],
                Option::<&Empty>::None,
                &[StatusCode::NO_CONTENT],
            )
            .await?;
        Ok(Empty {})
    }

    /// Executes an authenticated workflow with bounded arbitrary JSON input.
    pub async fn execute_workflow(&self, path: &str, input: &WorkflowData) -> Result<WorkflowData> {
        let path = workflow_path("sys/workflows/execute", path)?;
        let body = self
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                Method::POST,
                &path,
                &path,
                &[] as &[(&str, &str)],
                Some(input),
                &[StatusCode::OK],
            )
            .await?;
        workflow_data_from_envelope(body)
    }

    /// Executes a workflow in diagnostic trace mode.
    ///
    /// Trace output can contain the caller's OpenBao token, generated request
    /// bodies, response bodies, and all intermediate values. It remains in
    /// [`WorkflowData`] sanitizing storage and must never be logged.
    #[cfg(feature = "workflow-trace")]
    pub async fn trace_workflow(&self, path: &str, input: &WorkflowData) -> Result<WorkflowData> {
        let path = workflow_path("sys/workflows/trace", path)?;
        let body = self
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                Method::POST,
                &path,
                &path,
                &[] as &[(&str, &str)],
                Some(input),
                &[StatusCode::OK],
            )
            .await?;
        workflow_data_from_envelope(body)
    }

    #[cfg(feature = "operator-ops")]
    async fn request_generate_root_json<T, B>(
        &self,
        endpoint: crate::compatibility::OpenBaoEndpointSpec,
        body: Option<&B>,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let (resolved, path) = self
            .client
            .resolve_openbao_literal_endpoint(endpoint)
            .await?;
        match path.as_str() {
            "sys/generate-root/attempt" | "sys/generate-root/update" => {
                self.client
                    .request_resolved_literal_endpoint_json_accepting(
                        &resolved,
                        &path,
                        body,
                        &[StatusCode::OK],
                    )
                    .await
            }
            "sys/generate-root-token/attempt" | "sys/generate-root-token/update" => {
                let envelope: ResponseEnvelope<T> = self
                    .client
                    .request_resolved_literal_endpoint_json_accepting(
                        &resolved,
                        &path,
                        body,
                        &[StatusCode::OK],
                    )
                    .await?;
                Ok(envelope.data)
            }
            _ => Err(Error::Internal(
                "root generation selected an unreviewed route",
            )),
        }
    }

    /// Streams bounded frames from `/sys/monitor`.
    ///
    /// This diagnostic endpoint can expose request paths, identifiers, and
    /// application-provided log fields. Treat every returned frame as
    /// sensitive and untrusted. The request remains active until the returned
    /// stream reaches EOF, fails, or is dropped.
    #[cfg(feature = "monitor-stream")]
    pub async fn monitor(&self, options: MonitorOptions) -> Result<MonitorStream> {
        let query = [
            ("log_level", options.log_level.as_str().to_owned()),
            ("log_format", options.log_format.as_str().to_owned()),
        ];
        let response = self
            .client
            .request_sys_stream_internal(Method::GET, "sys/monitor", &query, &[StatusCode::OK])
            .await?;
        Ok(MonitorStream::new(response, options))
    }

    /// Generates random bytes through `/sys/tools/random`.
    ///
    /// OpenBao defaults to platform entropy, 32 bytes, and base64 output when
    /// the request does not override those values.
    pub async fn random(&self, request: &SysRandomRequest) -> Result<SysRandomResponse> {
        request.validate()?;
        let payload = SysRandomPayload {
            format: request.format,
        };
        let envelope: ResponseEnvelope<SysRandomResponse> = self
            .client
            .request_sys_json_internal(
                Method::POST,
                &sys_random_path(None, request.bytes),
                Some(&payload),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Generates random bytes through `/sys/tools/random/:source`.
    pub async fn random_from_source(
        &self,
        source: SysRandomSource,
        request: &SysRandomRequest,
    ) -> Result<SysRandomResponse> {
        request.validate()?;
        let payload = SysRandomPayload {
            format: request.format,
        };
        let envelope: ResponseEnvelope<SysRandomResponse> = self
            .client
            .request_sys_json_internal(
                Method::POST,
                &sys_random_path(Some(source), request.bytes),
                Some(&payload),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Hashes base64-encoded input through `/sys/tools/hash/:algorithm`.
    pub async fn hash(
        &self,
        algorithm: SysHashAlgorithm,
        request: &SysHashRequest,
    ) -> Result<SysHashResponse> {
        let payload = SysHashPayload {
            input: request.input.expose_secret(),
            format: request.format,
        };
        let envelope: ResponseEnvelope<SysHashResponse> = self
            .client
            .request_sys_json_internal(Method::POST, &sys_hash_path(algorithm), Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Seals the active OpenBao node.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_seal(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(Method::POST, "sys/seal", Option::<&Empty>::None)
            .await
    }

    /// Rotates the barrier encryption keyring.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_keyring(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(Method::POST, "sys/rotate/keyring", Option::<&Empty>::None)
            .await
    }

    /// Forces the active node to step down through `/sys/step-down`.
    ///
    /// OpenBao requires a root token or `sudo` capability on the path. The
    /// node may become active again if no standby takes the active lock.
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn step_down_leader(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(Method::POST, "sys/step-down", Option::<&Empty>::None)
            .await
    }

    /// Reads legacy rekey status from `/sys/rekey/init`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_status(&self) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/rekey/init", Option::<&Empty>::None)
            .await
    }

    /// Starts legacy rekey through `/sys/rekey/init`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_start(
        &self,
        request: &OperatorKeySharesRequest,
    ) -> Result<OperatorKeySharesStatus> {
        validate_key_share_options(request.secret_shares, request.secret_threshold)?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::OPERATOR_REKEY_STORED_SHARES,
                request.stored_shares.is_some(),
            )])
            .await?;
        self.client
            .request_sys_json_internal(Method::POST, "sys/rekey/init", Some(request))
            .await
    }

    /// Cancels legacy rekey through `/sys/rekey/init`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_cancel(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(Method::DELETE, "sys/rekey/init", Option::<&Empty>::None)
            .await
    }

    /// Submits one key share to legacy rekey.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_update(
        &self,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorKeyShareUpdateResponse> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/rekey/update",
                Some(&OperatorKeyShareUpdatePayload {
                    key: request.key.expose_secret(),
                    nonce: &request.nonce,
                }),
            )
            .await
    }

    /// Reads the PGP-encrypted backup from barrier rekey.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_backup(&self) -> Result<OperatorRecoveryKeyBackup> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/rekey/backup", Option::<&Empty>::None)
            .await
    }

    /// Deletes the PGP-encrypted backup from barrier rekey.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_delete_backup(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(Method::DELETE, "sys/rekey/backup", Option::<&Empty>::None)
            .await
    }

    /// Reads barrier-rekey verification status.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_verify_status(&self) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/rekey/verify", Option::<&Empty>::None)
            .await
    }

    /// Cancels barrier-rekey verification.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_verify_cancel(&self) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_sys_json_internal(Method::DELETE, "sys/rekey/verify", Option::<&Empty>::None)
            .await
    }

    /// Submits one new share to barrier-rekey verification.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_verify_update(
        &self,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorKeyShareUpdateResponse> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/rekey/verify",
                Some(&OperatorKeyShareUpdatePayload {
                    key: request.key.expose_secret(),
                    nonce: &request.nonce,
                }),
            )
            .await
    }

    /// Reads OpenBao v2.4+ key-share rotation status.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_status(
        &self,
        target: OperatorRotateTarget,
    ) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                &rotate_init_path(target),
                Option::<&Empty>::None,
            )
            .await
    }

    /// Starts OpenBao v2.4+ key-share rotation.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_start(
        &self,
        target: OperatorRotateTarget,
        request: &OperatorKeySharesRequest,
    ) -> Result<OperatorKeySharesStatus> {
        validate_key_share_options(request.secret_shares, request.secret_threshold)?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::OPERATOR_REKEY_STORED_SHARES,
                request.stored_shares.is_some(),
            )])
            .await?;
        self.client
            .request_sys_json_internal(Method::POST, &rotate_init_path(target), Some(request))
            .await
    }

    /// Cancels OpenBao v2.4+ key-share rotation.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_cancel(&self, target: OperatorRotateTarget) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::DELETE,
                &rotate_init_path(target),
                Option::<&Empty>::None,
            )
            .await
    }

    /// Submits one key share to OpenBao v2.4+ key-share rotation.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_update(
        &self,
        target: OperatorRotateTarget,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorKeyShareUpdateResponse> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                &rotate_update_path(target),
                Some(&OperatorKeyShareUpdatePayload {
                    key: request.key.expose_secret(),
                    nonce: &request.nonce,
                }),
            )
            .await
    }

    /// Rotates the barrier encryption key through the legacy all-version path.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_barrier(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(Method::POST, "sys/rotate", Option::<&Empty>::None)
            .await
    }

    /// Rotates the root key through OpenBao's v2.5.5+ dedicated path.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_root_key(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(Method::POST, "sys/rotate/root", Option::<&Empty>::None)
            .await
    }

    /// Reads key-share rotation verification status.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_verify_status(
        &self,
        target: OperatorRotateTarget,
    ) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                &rotate_verify_path(target),
                Option::<&Empty>::None,
            )
            .await
    }

    /// Submits one new share to key-share rotation verification.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_verify_update(
        &self,
        target: OperatorRotateTarget,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorKeyShareUpdateResponse> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                &rotate_verify_path(target),
                Some(&OperatorKeyShareUpdatePayload {
                    key: request.key.expose_secret(),
                    nonce: &request.nonce,
                }),
            )
            .await
    }

    /// Cancels key-share rotation verification.
    ///
    /// OpenBao uses the historical `/sys/rotation/.../verify` spelling only
    /// for this DELETE operation.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_verify_cancel(
        &self,
        target: OperatorRotateTarget,
    ) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_sys_json_internal(
                Method::DELETE,
                &rotation_verify_cancel_path(target),
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads a PGP-encrypted key-share rotation backup.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_backup(
        &self,
        target: OperatorRotateTarget,
    ) -> Result<OperatorRecoveryKeyBackup> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                &rotate_backup_path(target),
                Option::<&Empty>::None,
            )
            .await
    }

    /// Deletes a PGP-encrypted key-share rotation backup.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_delete_backup(
        &self,
        target: OperatorRotateTarget,
    ) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::DELETE,
                &rotate_backup_path(target),
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads automatic barrier rotation configuration.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotation_config(&self) -> Result<OperatorRotationConfig> {
        let envelope: ResponseEnvelope<OperatorRotationConfig> = self
            .client
            .request_sys_json_internal(Method::GET, "sys/rotate/config", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Writes automatic barrier rotation configuration.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_write_rotation_config(
        &self,
        config: &OperatorRotationConfig,
    ) -> Result<Empty> {
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::ROTATION_INTERVAL,
                config.interval.is_some(),
            )])
            .await?;
        self.client
            .request_sys_json_internal(Method::POST, "sys/rotate/config", Some(config))
            .await
    }

    /// Reads automatic keyring rotation configuration (OpenBao v2.4+).
    #[cfg(feature = "operator-ops")]
    pub async fn operator_keyring_rotation_config(&self) -> Result<OperatorRotationConfig> {
        let envelope: ResponseEnvelope<OperatorRotationConfig> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                "sys/rotate/keyring/config",
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Writes automatic keyring rotation configuration (OpenBao v2.4+).
    #[cfg(feature = "operator-ops")]
    pub async fn operator_write_keyring_rotation_config(
        &self,
        config: &OperatorRotationConfig,
    ) -> Result<Empty> {
        self.client
            .request_sys_json_internal(Method::POST, "sys/rotate/keyring/config", Some(config))
            .await
    }

    /// Reads root-token generation progress from the exact-profile route.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_generate_root_status(&self) -> Result<OperatorTokenGenerationStatus> {
        self.request_generate_root_json(
            crate::compatibility::generated::GENERATED_SYS_GENERATE_ROOT_STATUS,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Starts root token generation through the exact-profile route.
    ///
    /// Profiles through 2.5.5 use `/sys/generate-root/attempt`; OpenBao 2.6+
    /// uses `/sys/generate-root-token/attempt`. The client never probes or
    /// falls back between these operator endpoints.
    ///
    /// The returned OTP, when present, is returned only once by OpenBao and
    /// must be kept as root-level operator ceremony material.
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_generate_root_start(
        &self,
        request: &OperatorTokenGenerationStartRequest,
    ) -> Result<OperatorTokenGenerationStart> {
        self.request_generate_root_json(
            crate::compatibility::generated::GENERATED_SYS_GENERATE_ROOT_START,
            Some(request),
        )
        .await
    }

    /// Cancels root token generation through the exact-profile route.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_generate_root_cancel(&self) -> Result<Empty> {
        self.client
            .request_literal_endpoint_json_accepting(
                crate::compatibility::generated::GENERATED_SYS_GENERATE_ROOT_CANCEL,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Submits one key share to root token generation through the
    /// exact-profile route.
    ///
    /// The completed response contains an encoded root token that must be
    /// decoded with [`Sys::operator_decode_token`] and the OTP from the start
    /// response, unless a PGP key was used.
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_generate_root_update(
        &self,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorTokenGenerationStatus> {
        self.request_generate_root_json(
            crate::compatibility::generated::GENERATED_SYS_GENERATE_ROOT_UPDATE,
            Some(&OperatorKeyShareUpdatePayload {
                key: request.key.expose_secret(),
                nonce: &request.nonce,
            }),
        )
        .await
    }

    /// Reads recovery-token generation progress from
    /// `/sys/generate-recovery-token/attempt`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_generate_recovery_token_status(
        &self,
    ) -> Result<OperatorTokenGenerationStatus> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                "sys/generate-recovery-token/attempt",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Starts recovery-token generation through
    /// `/sys/generate-recovery-token/attempt`.
    ///
    /// Recovery tokens are root-level credentials for recovery mode and live
    /// only in memory until the next OpenBao restart.
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_generate_recovery_token_start(
        &self,
        request: &OperatorTokenGenerationStartRequest,
    ) -> Result<OperatorTokenGenerationStart> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/generate-recovery-token/attempt",
                Some(request),
            )
            .await
    }

    /// Cancels recovery-token generation through
    /// `/sys/generate-recovery-token/attempt`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_generate_recovery_token_cancel(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::DELETE,
                "sys/generate-recovery-token/attempt",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Submits one key share to recovery-token generation.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_generate_recovery_token_update(
        &self,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorTokenGenerationStatus> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/generate-recovery-token/update",
                Some(&OperatorKeyShareUpdatePayload {
                    key: request.key.expose_secret(),
                    nonce: &request.nonce,
                }),
            )
            .await
    }

    /// Decodes an encoded root or recovery token locally.
    ///
    /// OpenBao documents token decoding as a client-side XOR operation; there
    /// is no `/sys/decode-token` HTTP endpoint. The returned token is root- or
    /// recovery-level credential material.
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_decode_token(
        &self,
        request: &DecodeTokenRequest,
    ) -> Result<DecodeTokenResponse> {
        decode_operator_token(request)
    }

    /// Reads legacy recovery-key rekey status from
    /// `/sys/rekey-recovery-key/init`.
    ///
    /// This legacy unauthenticated endpoint family is deprecated by OpenBao as
    /// of 2.4. Prefer [`Sys::operator_rotate_status`] with
    /// [`OperatorRotateTarget::Recovery`] when available.
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_recovery_key_status(&self) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                "sys/rekey-recovery-key/init",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Starts legacy recovery-key rekey through `/sys/rekey-recovery-key/init`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_recovery_key_start(
        &self,
        request: &OperatorKeySharesRequest,
    ) -> Result<OperatorKeySharesStatus> {
        validate_key_share_options(request.secret_shares, request.secret_threshold)?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::OPERATOR_REKEY_STORED_SHARES,
                request.stored_shares.is_some(),
            )])
            .await?;
        self.client
            .request_sys_json_internal(Method::POST, "sys/rekey-recovery-key/init", Some(request))
            .await
    }

    /// Cancels legacy recovery-key rekey through `/sys/rekey-recovery-key/init`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_recovery_key_cancel(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::DELETE,
                "sys/rekey-recovery-key/init",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Submits one current recovery key share to legacy recovery-key rekey.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_recovery_key_update(
        &self,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorKeyShareUpdateResponse> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/rekey-recovery-key/update",
                Some(&OperatorKeyShareUpdatePayload {
                    key: request.key.expose_secret(),
                    nonce: &request.nonce,
                }),
            )
            .await
    }

    /// Reads legacy recovery-key rekey verification status.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_recovery_key_verify_status(
        &self,
    ) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                "sys/rekey-recovery-key/verify",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Cancels legacy recovery-key rekey verification.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_recovery_key_verify_cancel(
        &self,
    ) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_sys_json_internal(
                Method::DELETE,
                "sys/rekey-recovery-key/verify",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Submits one new recovery key share to legacy rekey verification.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_recovery_key_verify_update(
        &self,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorKeyShareUpdateResponse> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/rekey-recovery-key/verify",
                Some(&OperatorKeyShareUpdatePayload {
                    key: request.key.expose_secret(),
                    nonce: &request.nonce,
                }),
            )
            .await
    }

    /// Reads the PGP-encrypted backup from legacy recovery-key rekey.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_recovery_key_backup(&self) -> Result<OperatorRecoveryKeyBackup> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                "sys/rekey/recovery-key-backup",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Deletes the PGP-encrypted backup from legacy recovery-key rekey.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_recovery_key_delete_backup(&self) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::DELETE,
                "sys/rekey/recovery-key-backup",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads one raw storage backend key through `/sys/raw/:path`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// OpenBao documents this endpoint as disabled by default and as operating
    /// on underlying storage paths, not logical secret paths. Treat returned
    /// values as sensitive operational material.
    #[cfg(feature = "operator-ops")]
    pub async fn raw_read(&self, path: &str, options: &RawReadOptions) -> Result<RawReadResponse> {
        let mut query = vec![("compressed", options.compressed.to_string())];
        if let Some(encoding) = options.encoding.as_query_value() {
            query.push(("encoding", encoding));
        }
        self.client
            .request_sys_json_query_accepting(
                Method::GET,
                &raw_storage_path(path)?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await
    }

    /// Writes one raw storage backend key through `/sys/raw/:path`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This can mutate OpenBao's underlying storage and should be used only
    /// during an explicit operator recovery or migration procedure.
    #[cfg(feature = "operator-ops")]
    pub async fn raw_write(&self, path: &str, request: &RawWriteRequest) -> Result<Empty> {
        let payload = RawWritePayload {
            value: request.value.expose_secret(),
            compression_type: request.compression_type,
            encoding: request.encoding,
        };
        self.client
            .request_sys_json_accepting(
                Method::POST,
                &raw_storage_path(path)?,
                Some(&payload),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Lists raw storage backend keys through `/sys/raw/:prefix?list=true`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// OpenBao documents this endpoint as requiring `sudo` capability.
    #[cfg(feature = "operator-ops")]
    pub async fn raw_list(&self, prefix: &str) -> Result<RawList> {
        let envelope: ResponseEnvelope<RawList> = self
            .client
            .request_sys_json_query_accepting(
                Method::GET,
                &raw_storage_path(prefix)?,
                &[("list", "true".to_owned())],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes one raw storage backend key through `/sys/raw/:path`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This can destroy OpenBao internal state and should be used only during
    /// an explicit operator recovery or migration procedure.
    #[cfg(feature = "operator-ops")]
    pub async fn raw_delete(&self, path: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &raw_storage_path(path)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reads a runtime profile through `/sys/pprof/:profile`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// Pprof data can include command-line arguments, stack traces, and other
    /// local-node diagnostic material. The SDK returns a sanitizing byte buffer
    /// and applies the configured maximum response-size cap.
    #[cfg(feature = "operator-ops")]
    pub async fn pprof(&self, profile: PprofProfile, options: &PprofOptions) -> Result<SecretVec> {
        validate_pprof_options(profile, options)?;
        let mut query = Vec::new();
        if let Some(seconds) = options.seconds {
            query.push(("seconds", seconds.to_string()));
        }
        if let Some(debug) = options.debug {
            query.push(("debug", debug.to_string()));
        }
        self.client
            .request_sys_bytes_accepting_internal(
                Method::GET,
                &pprof_path(profile),
                &query,
                None,
                None,
                &[StatusCode::OK],
            )
            .await
    }

    /// Lists mounted secrets engines.
    pub async fn list_mounts(&self) -> Result<BTreeMap<String, MountInfo>> {
        let envelope: ResponseEnvelope<MountInfoMap> = self
            .client
            .request_sys_json_internal(Method::GET, "sys/mounts", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data.0)
    }

    /// Reads one mounted secrets engine.
    pub async fn read_mount(&self, mount_path: &str) -> Result<MountInfo> {
        let envelope: ResponseEnvelope<MountInfo> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                &sys_path("sys/mounts", mount_path, None)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Enables a secrets engine at `mount_path`.
    pub async fn enable_mount(
        &self,
        mount_path: &str,
        request: &MountEnableRequest,
    ) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_path("sys/mounts", mount_path, None)?,
                Some(request),
            )
            .await
    }

    /// Enables a KV v2 secrets engine at `mount_path`.
    pub async fn enable_kv2(&self, mount_path: &str, description: Option<&str>) -> Result<Empty> {
        let mut request = MountEnableRequest::kv2();
        if let Some(description) = description {
            request.description = Some(description.to_owned());
        }
        self.enable_mount(mount_path, &request).await
    }

    /// Disables a mounted secrets engine.
    pub async fn disable_mount(&self, mount_path: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &sys_path("sys/mounts", mount_path, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reads tune data for a secrets engine.
    pub async fn read_mount_tune(&self, mount_path: &str) -> Result<MountConfig> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                &sys_path("sys/mounts", mount_path, Some("tune"))?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Tunes a secrets engine.
    pub async fn tune_mount(&self, mount_path: &str, config: &MountConfig) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_path("sys/mounts", mount_path, Some("tune"))?,
                Some(config),
            )
            .await
    }

    /// Lists enabled auth methods.
    pub async fn list_auth_methods(&self) -> Result<BTreeMap<String, MountInfo>> {
        let envelope: ResponseEnvelope<MountInfoMap> = self
            .client
            .request_sys_json_internal(Method::GET, "sys/auth", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data.0)
    }

    /// Reads one enabled auth method configuration.
    pub async fn read_auth_method(&self, mount_path: &str) -> Result<MountInfo> {
        let envelope: ResponseEnvelope<MountInfo> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                &sys_path("sys/auth", mount_path, None)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Enables an auth method at `mount_path`.
    pub async fn enable_auth_method(
        &self,
        mount_path: &str,
        request: &AuthEnableRequest,
    ) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_path("sys/auth", mount_path, None)?,
                Some(request),
            )
            .await
    }

    /// Disables an auth method.
    pub async fn disable_auth_method(&self, mount_path: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &sys_path("sys/auth", mount_path, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reads tune data for an auth method.
    pub async fn read_auth_tune(&self, mount_path: &str) -> Result<MountConfig> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                &sys_path("sys/auth", mount_path, Some("tune"))?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Tunes an auth method.
    pub async fn tune_auth_method(&self, mount_path: &str, config: &MountConfig) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_path("sys/auth", mount_path, Some("tune"))?,
                Some(config),
            )
            .await
    }

    /// Reads `/sys/internal/ui/mounts/:path`.
    ///
    /// OpenBao documents this endpoint as internal UI and CLI preflight
    /// support without backwards compatibility guarantees. It accepts a mount
    /// path or a path hosted by a mount.
    pub async fn ui_mount_details(&self, path: &str) -> Result<UiMountDetails> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                &internal_ui_mount_path(path)?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads the historical internal UI feature flags endpoint.
    ///
    /// This unstable endpoint exists in locked OpenBao profiles from `2.0.0`
    /// through `2.4.4` and was removed in `2.5.0`. A selected newer profile
    /// returns [`Error::UnsupportedOpenBaoCapability`] before transmission.
    #[cfg(feature = "unstable-internal-ops")]
    pub async fn ui_feature_flags(&self) -> Result<UiFeatureFlags> {
        self.client
            .request_registered_json_query_headers_accepting(
                "/sys/",
                Method::GET,
                "sys/internal/ui/feature-flags",
                "sys/internal/ui/feature-flags",
                &[] as &[(&str, String)],
                &[],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await
    }

    /// Lists configured UI response headers through an unstable internal API.
    #[cfg(feature = "unstable-internal-ops")]
    pub async fn list_ui_headers(&self) -> Result<PolicyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.client
            .request_sys_json_internal(method, "sys/config/ui/headers", Option::<&Empty>::None)
            .await
    }

    /// Reads one configured UI response header.
    #[cfg(feature = "unstable-internal-ops")]
    pub async fn read_ui_header(&self, name: &str) -> Result<UiHeaderConfig> {
        let envelope: ResponseEnvelope<UiHeaderConfig> = self
            .client
            .request_sys_json_internal(Method::GET, &ui_header_path(name)?, Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Writes one UI response header.
    #[cfg(feature = "unstable-internal-ops")]
    pub async fn write_ui_header(&self, name: &str, config: &UiHeaderConfig) -> Result<Empty> {
        if config.values.len() > crate::response::MAX_RESPONSE_STRINGS {
            return Err(Error::InvalidParameter(
                "UI header value list exceeds item limit".into(),
            ));
        }
        self.client
            .request_sys_json_internal(Method::POST, &ui_header_path(name)?, Some(config))
            .await
    }

    /// Deletes one configured UI response header.
    #[cfg(feature = "unstable-internal-ops")]
    pub async fn delete_ui_header(&self, name: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &ui_header_path(name)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reads unstable internal entity counters.
    #[cfg(feature = "unstable-internal-ops")]
    pub async fn internal_entity_counters(&self) -> Result<InternalCounters> {
        let envelope: ResponseEnvelope<InternalCounters> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                "sys/internal/counters/entities",
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads unstable internal token counters.
    #[cfg(feature = "unstable-internal-ops")]
    pub async fn internal_token_counters(&self) -> Result<InternalCounters> {
        let envelope: ResponseEnvelope<InternalCounters> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                "sys/internal/counters/tokens",
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Inspects the unstable internal request root (OpenBao 2.5.5+).
    #[cfg(feature = "unstable-internal-ops")]
    pub async fn internal_request_inspection(&self) -> Result<JsonValue> {
        let envelope: ResponseEnvelope<BoundedJsonValue> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                "sys/internal/inspect/request/root",
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data.into_inner())
    }

    /// Inspects one unstable internal router index.
    #[cfg(feature = "unstable-internal-ops")]
    pub async fn internal_router_inspection(
        &self,
        target: InternalRouterTarget,
    ) -> Result<InternalRouterInspection> {
        let envelope: ResponseEnvelope<InternalRouterInspection> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                &format!("sys/internal/inspect/router/{}", target.path_segment()),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists ACL policies.
    pub async fn list_policies(&self) -> Result<PolicyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<PolicyList> = self
            .client
            .request_sys_json_internal(method, "sys/policies/acl", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Lists ACL policies below a policy prefix.
    pub async fn list_policies_with_prefix(&self, prefix: &str) -> Result<PolicyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<PolicyList> = self
            .client
            .request_sys_json_internal(
                method,
                &sys_path("sys/policies/acl", prefix, None)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads one ACL policy.
    pub async fn read_policy(&self, name: &str) -> Result<PolicyInfo> {
        let envelope: ResponseEnvelope<PolicyInfo> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                &sys_path("sys/policies/acl", name, None)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads one ACL policy with OpenBao 2.6 identity-template override state.
    pub async fn read_policy_details(&self, name: &str) -> Result<PolicyInfoDetails> {
        let envelope: ResponseEnvelope<PolicyInfoDetails> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                &sys_path("sys/policies/acl", name, None)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates an ACL policy.
    pub async fn write_policy(&self, name: &str, request: &PolicyWriteRequest) -> Result<Empty> {
        request.validate()?;
        self.client
            .validate_versioned_request_fields(&[
                (
                    &crate::request_compatibility::fields::POLICY_EXPIRATION,
                    request.expiration.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_TTL,
                    request.ttl.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_CAS,
                    request.cas.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_CAS_REQUIRED,
                    request.cas_required.is_some(),
                ),
            ])
            .await?;
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_path("sys/policies/acl", name, None)?,
                Some(request),
            )
            .await
    }

    /// Patches selected ACL policy fields without clearing omitted metadata.
    ///
    /// This endpoint is available from OpenBao 2.6.1. The policy must already
    /// exist. In contrast to [`Self::write_policy`], omitted expiration and
    /// identity-template settings are preserved.
    pub async fn patch_policy(&self, name: &str, request: &PolicyPatchRequest) -> Result<Empty> {
        request.validate()?;
        self.client
            .validate_versioned_request_fields(&[
                (
                    &crate::request_compatibility::fields::POLICY_EXPIRATION,
                    request.expiration.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_TTL,
                    request.ttl.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_CAS,
                    request.cas.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_CAS_REQUIRED,
                    request.cas_required.is_some(),
                ),
            ])
            .await?;
        self.client
            .request_sys_json_headers_accepting(
                Method::PATCH,
                &sys_path("sys/policies/acl", name, None)?,
                &[(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/merge-patch+json"),
                )],
                Some(request),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Patches an ACL policy while enabling reviewed identity-template delimiters.
    #[cfg(feature = "identity-template-overrides-acknowledged")]
    pub async fn patch_policy_with_identity_template_overrides(
        &self,
        name: &str,
        request: &PolicyPatchRequest,
        overrides: AclIdentityTemplateOverrides,
    ) -> Result<Empty> {
        request.validate()?;
        self.client
            .validate_versioned_request_fields(&[
                (
                    &crate::request_compatibility::fields::POLICY_EXPIRATION,
                    request.expiration.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_TTL,
                    request.ttl.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_CAS,
                    request.cas.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_CAS_REQUIRED,
                    request.cas_required.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_ALLOW_TEMPLATE_SLASHES,
                    overrides.allow_slashes,
                ),
                (
                    &crate::request_compatibility::fields::POLICY_ALLOW_TEMPLATE_WILDCARDS,
                    overrides.allow_wildcards,
                ),
            ])
            .await?;
        let payload = PolicyPatchWithIdentityTemplateOverrides {
            request,
            allow_slashes_in_identity_templates: overrides.allow_slashes,
            allow_wildcards_in_identity_templates: overrides.allow_wildcards,
        };
        self.client
            .request_sys_json_headers_accepting(
                Method::PATCH,
                &sys_path("sys/policies/acl", name, None)?,
                &[(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/merge-patch+json"),
                )],
                Some(&payload),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Creates or updates an ACL policy while enabling reviewed identity-template delimiters.
    ///
    /// OpenBao 2.6 rejects `/`, `*`, and `+` in rendered identity-template
    /// values by default. Enable an override only when every identity metadata
    /// source used by the policy is trusted and constrained. Ordinary
    /// [`PolicyWriteRequest`] serialization cannot emit these flags.
    #[cfg(feature = "identity-template-overrides-acknowledged")]
    pub async fn write_policy_with_identity_template_overrides(
        &self,
        name: &str,
        request: &PolicyWriteRequest,
        overrides: AclIdentityTemplateOverrides,
    ) -> Result<Empty> {
        request.validate()?;
        self.client
            .validate_versioned_request_fields(&[
                (
                    &crate::request_compatibility::fields::POLICY_EXPIRATION,
                    request.expiration.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_TTL,
                    request.ttl.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_CAS,
                    request.cas.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_CAS_REQUIRED,
                    request.cas_required.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::POLICY_ALLOW_TEMPLATE_SLASHES,
                    overrides.allow_slashes,
                ),
                (
                    &crate::request_compatibility::fields::POLICY_ALLOW_TEMPLATE_WILDCARDS,
                    overrides.allow_wildcards,
                ),
            ])
            .await?;
        let payload = PolicyWriteWithIdentityTemplateOverrides {
            request,
            allow_slashes_in_identity_templates: overrides.allow_slashes,
            allow_wildcards_in_identity_templates: overrides.allow_wildcards,
        };
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_path("sys/policies/acl", name, None)?,
                Some(&payload),
            )
            .await
    }

    /// Deletes an ACL policy.
    pub async fn delete_policy(&self, name: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &sys_path("sys/policies/acl", name, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Lists ACL policies with OpenBao's detailed policy-list representation.
    ///
    /// This endpoint is available in OpenBao 2.5 and later.
    pub async fn list_policies_detailed(&self) -> Result<PolicyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<PolicyList> = self
            .client
            .request_sys_json_internal(method, "sys/policies/detailed/acl", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Lists detailed ACL policies below a prefix.
    ///
    /// This endpoint is available in OpenBao 2.5 and later.
    pub async fn list_policies_detailed_with_prefix(&self, prefix: &str) -> Result<PolicyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<PolicyList> = self
            .client
            .request_sys_json_internal(
                method,
                &sys_path("sys/policies/detailed/acl", prefix, None)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists password policies.
    pub async fn list_password_policies(&self) -> Result<PasswordPolicyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.client
            .request_sys_json_internal(method, "sys/policies/password", Option::<&Empty>::None)
            .await
    }

    /// Reads one password policy.
    pub async fn read_password_policy(&self, name: &str) -> Result<PasswordPolicy> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                &sys_path("sys/policies/password", name, None)?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Creates or updates a password policy.
    ///
    /// OpenBao validates that the policy can generate passwords before saving
    /// it. The SDK treats the policy body as an opaque document.
    pub async fn write_password_policy(
        &self,
        name: &str,
        request: &PasswordPolicyWriteRequest,
    ) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_path("sys/policies/password", name, None)?,
                Some(request),
            )
            .await
    }

    /// Deletes one password policy.
    pub async fn delete_password_policy(&self, name: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &sys_path("sys/policies/password", name, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Generates a password from an existing password policy.
    pub async fn generate_password(&self, name: &str) -> Result<GeneratedPassword> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                &sys_path("sys/policies/password", name, Some("generate"))?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Queries capabilities for the caller's token.
    pub async fn capabilities_self<I, P>(&self, paths: I) -> Result<Capabilities>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let paths = validate_capability_paths(paths)?;
        let payload = CapabilitiesPayload {
            paths: &paths,
            token: None,
            accessor: None,
        };
        let envelope: ResponseEnvelope<Capabilities> = self
            .client
            .request_sys_json_internal(Method::POST, "sys/capabilities-self", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Queries capabilities for a token value.
    pub async fn capabilities<I, P>(&self, token: &SecretString, paths: I) -> Result<Capabilities>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let paths = validate_capability_paths(paths)?;
        let payload = CapabilitiesPayload {
            paths: &paths,
            token: Some(token.expose_secret()),
            accessor: None,
        };
        let envelope: ResponseEnvelope<Capabilities> = self
            .client
            .request_sys_json_internal(Method::POST, "sys/capabilities", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Queries capabilities for a token accessor.
    pub async fn capabilities_accessor<I, P>(
        &self,
        accessor: &SecretString,
        paths: I,
    ) -> Result<Capabilities>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let paths = validate_capability_paths(paths)?;
        let payload = CapabilitiesPayload {
            paths: &paths,
            token: None,
            accessor: Some(accessor.expose_secret()),
        };
        let envelope: ResponseEnvelope<Capabilities> = self
            .client
            .request_sys_json_internal(Method::POST, "sys/capabilities-accessor", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Reads the resultant ACL for the requesting token.
    ///
    /// OpenBao documents `/sys/internal/ui/resultant-acl` as an internal UI
    /// endpoint without a backwards-compatibility guarantee. The SDK models
    /// the stable-in-practice exact/glob path maps conservatively and ignores
    /// future fields.
    pub async fn resultant_acl(&self) -> Result<ResultantAcl> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                "sys/internal/ui/resultant-acl",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads currently in-flight OpenBao request metadata.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This diagnostic endpoint can reveal active request paths, remote
    /// addresses, and token accessors. Treat the response as sensitive
    /// operational data.
    #[cfg(feature = "operator-ops")]
    pub async fn in_flight_requests(&self) -> Result<InFlightRequests> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/in-flight-req", Option::<&Empty>::None)
            .await
    }

    /// Validates a login MFA request and returns the resulting auth token.
    ///
    /// Use this when a login attempt returns an MFA requirement instead of a
    /// client token. `mfa_payload` passcodes are stored as `SecretString` and
    /// exposed only while serializing this request.
    pub async fn validate_mfa(&self, request: &MfaValidateRequest) -> Result<MfaValidateAuth> {
        request.validate()?;
        let envelope: MfaValidateEnvelope = self
            .client
            .request_sys_json_internal(Method::POST, "sys/mfa/validate", Some(request))
            .await?;
        envelope.auth.ok_or(Error::MissingField("auth"))
    }

    /// Lists enabled audit devices.
    pub async fn list_audit_devices(&self) -> Result<BTreeMap<String, AuditDevice>> {
        let devices: AuditDeviceMap = self
            .client
            .request_sys_json_internal(Method::GET, "sys/audit", Option::<&Empty>::None)
            .await?;
        Ok(devices.0)
    }

    /// Enables an audit device at `path`.
    pub async fn enable_audit_device(
        &self,
        path: &str,
        request: &AuditEnableRequest,
    ) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_path("sys/audit", path, None)?,
                Some(request),
            )
            .await
    }

    /// Disables an audit device.
    ///
    /// OpenBao creates a new audit salt if a device is later re-enabled, so
    /// stored audit HMACs from the disabled device cannot be recomputed.
    pub async fn disable_audit_device(&self, path: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &sys_path("sys/audit", path, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Calculates the HMAC OpenBao would write for `input` through an audit device.
    pub async fn audit_hash(&self, path: &str, input: &SecretString) -> Result<AuditHash> {
        let payload = AuditHashPayload {
            input: input.expose_secret(),
        };
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_path("sys/audit-hash", path, None)?,
                Some(&payload),
            )
            .await
    }

    /// Lists audited request headers through `/sys/config/auditing/request-headers`.
    ///
    /// OpenBao requires `sudo` capability for this endpoint.
    pub async fn list_audited_request_headers(&self) -> Result<AuditedRequestHeaders> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                "sys/config/auditing/request-headers",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads one audited request header configuration.
    ///
    /// OpenBao requires `sudo` capability for this endpoint.
    pub async fn read_audited_request_header(
        &self,
        name: &str,
    ) -> Result<AuditedRequestHeaderConfig> {
        let headers: BTreeMap<String, AuditedRequestHeaderConfig> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                &audited_request_header_path(name)?,
                Option::<&Empty>::None,
            )
            .await?;
        headers
            .into_values()
            .next()
            .ok_or(Error::MissingField("audited request header"))
    }

    /// Creates or updates one audited request header configuration.
    ///
    /// OpenBao requires `sudo` capability for this endpoint.
    pub async fn write_audited_request_header(
        &self,
        name: &str,
        config: AuditedRequestHeaderConfig,
    ) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::POST,
                &audited_request_header_path(name)?,
                Some(&config),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Deletes one audited request header configuration.
    ///
    /// OpenBao requires `sudo` capability for this endpoint.
    pub async fn delete_audited_request_header(&self, name: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &audited_request_header_path(name)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Looks up lease metadata using the non-prefix `/sys/leases/lookup` endpoint.
    pub async fn lookup_lease(&self, lease_id: &SecretString) -> Result<LeaseLookup> {
        let payload = LeaseLookupPayload {
            lease_id: validate_lease_id(lease_id)?,
        };
        let envelope: ResponseEnvelope<LeaseLookup> = self
            .client
            .request_sys_json_internal(Method::POST, "sys/leases/lookup", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Looks up lease metadata including OpenBao 2.6 backend context.
    pub async fn lookup_lease_details(
        &self,
        lease_id: &SecretString,
    ) -> Result<LeaseLookupDetails> {
        let payload = LeaseLookupPayload {
            lease_id: validate_lease_id(lease_id)?,
        };
        let envelope: ResponseEnvelope<LeaseLookupDetails> = self
            .client
            .request_sys_json_internal(Method::POST, "sys/leases/lookup", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Lists lease counts, optionally filtered by lease type.
    pub async fn list_leases(&self, lease_type: &str) -> Result<LeaseCount> {
        validate_query_string_value(lease_type, "lease type")?;
        let envelope: ResponseEnvelope<LeaseCount> = self
            .client
            .request_sys_json_query_accepting(
                Method::GET,
                "sys/leases",
                &[("type", lease_type.to_owned())],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists lease identifiers below a validated lease prefix.
    pub async fn list_lease_ids(&self, prefix: &str) -> Result<LeaseIdList> {
        let prefix = validate_lease_prefix(prefix)?;
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<LeaseIdList> = self
            .client
            .request_sys_json_internal(
                method,
                &format!("sys/leases/lookup/{prefix}"),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Renews a non-token lease using the JSON-body `/sys/leases/renew` endpoint.
    ///
    /// Token leases should be renewed with the token helpers instead.
    pub async fn renew_lease(
        &self,
        lease_id: &SecretString,
        increment_seconds: Option<u64>,
    ) -> Result<LeaseRenewal> {
        let payload = LeaseRenewPayload {
            lease_id: validate_lease_id(lease_id)?,
            increment: increment_seconds,
        };
        let envelope: ResponseEnvelope<Option<Empty>> = self
            .client
            .request_sys_json_internal(Method::POST, "sys/leases/renew", Some(&payload))
            .await?;
        Ok(LeaseRenewal {
            lease_id: envelope.lease_id,
            lease_duration: envelope.lease_duration,
            renewable: envelope.renewable,
        })
    }

    /// Revokes one exact lease using the non-prefix `/sys/leases/revoke` endpoint.
    pub async fn revoke_lease(&self, lease_id: &SecretString) -> Result<Empty> {
        let payload = LeaseRevokePayload {
            lease_id: validate_lease_id(lease_id)?,
        };
        self.client
            .request_sys_json_accepting(
                Method::POST,
                "sys/leases/revoke",
                Some(&payload),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Revokes all leases under a lease ID prefix.
    ///
    /// This requires tightly controlled sudo capability and can revoke many
    /// dynamic credentials at once.
    pub async fn revoke_lease_prefix(&self, prefix: &str, sync: Option<bool>) -> Result<Empty> {
        let prefix = validate_lease_prefix(prefix)?;
        let query = sync
            .map(|sync| vec![("sync", sync.to_string())])
            .unwrap_or_default();
        self.client
            .request_sys_json_query_accepting(
                Method::POST,
                &format!("sys/leases/revoke-prefix/{prefix}"),
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Force-revokes all leases under a prefix while suppressing backend errors.
    ///
    /// This endpoint is dangerous because backend cleanup errors are ignored.
    /// Use only for operator-controlled emergency recovery.
    pub async fn force_revoke_lease_prefix(&self, prefix: &str) -> Result<Empty> {
        let prefix = validate_lease_prefix(prefix)?;
        self.client
            .request_sys_json_accepting(
                Method::POST,
                &format!("sys/leases/revoke-force/{prefix}"),
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Starts OpenBao lease tidy maintenance.
    ///
    /// OpenBao scans and cleans expired leases asynchronously. This is an
    /// administrative maintenance operation; applications should still manage
    /// their own active dynamic credential lease lifecycle explicitly.
    pub async fn tidy_leases(&self) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::POST,
                "sys/leases/tidy",
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Counts active leases, optionally filtered by OpenBao lease type.
    pub async fn count_leases(&self, lease_type: Option<&str>) -> Result<LeaseCount> {
        let query = match lease_type {
            Some(lease_type) => {
                validate_query_string_value(lease_type, "lease type")?;
                vec![("type", lease_type.to_owned())]
            }
            None => Vec::new(),
        };
        let envelope: ResponseEnvelope<LeaseCount> = self
            .client
            .request_sys_json_query_accepting(
                Method::GET,
                "sys/leases/count",
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists all plugin catalog entries grouped by plugin type.
    pub async fn list_plugins(&self) -> Result<PluginCatalog> {
        let envelope: ResponseEnvelope<PluginCatalog> = self
            .client
            .request_sys_json_internal(Method::GET, "sys/plugins/catalog", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Lists plugin names for one plugin type.
    pub async fn list_plugins_by_type(&self, plugin_type: PluginType) -> Result<PluginList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<PluginList> = self
            .client
            .request_sys_json_internal(
                method,
                &plugin_catalog_type_path(plugin_type)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Registers or updates a plugin catalog entry.
    ///
    /// OpenBao requires `sudo` capability for this endpoint. The SDK treats
    /// plugin args and env values as secret material because they commonly
    /// carry credentials or deployment-specific sensitive data.
    pub async fn register_plugin(
        &self,
        plugin_type: PluginType,
        name: &str,
        request: &PluginRegisterRequest,
    ) -> Result<Empty> {
        validate_sha256_hex(&request.sha256, "plugin SHA-256")?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::PLUGIN_OCI,
                request.oci.is_some(),
            )])
            .await?;
        let payload = PluginRegisterPayload {
            version: request.version.as_deref(),
            sha256: &request.sha256,
            command: &request.command,
            args: request
                .args
                .iter()
                .map(|value| value.expose_secret())
                .collect(),
            env: request
                .env
                .iter()
                .map(|value| value.expose_secret())
                .collect(),
            oci: request.oci,
        };
        self.client
            .request_sys_json_internal(
                Method::POST,
                &plugin_catalog_entry_path(plugin_type, name)?,
                Some(&payload),
            )
            .await
    }

    /// Reads one plugin catalog entry.
    pub async fn read_plugin(
        &self,
        plugin_type: PluginType,
        name: &str,
        version: Option<&str>,
    ) -> Result<PluginInfo> {
        let query = plugin_version_query(version)?;
        let envelope: ResponseEnvelope<PluginInfo> = self
            .client
            .request_sys_json_query_accepting(
                Method::GET,
                &plugin_catalog_entry_path(plugin_type, name)?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Removes one plugin catalog entry.
    ///
    /// OpenBao requires `sudo` capability for this endpoint.
    pub async fn delete_plugin(
        &self,
        plugin_type: PluginType,
        name: &str,
        version: Option<&str>,
    ) -> Result<Empty> {
        let query = plugin_version_query(version)?;
        self.client
            .request_sys_json_query_accepting(
                Method::DELETE,
                &plugin_catalog_entry_path(plugin_type, name)?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reloads mounted plugin backends by plugin name or explicit mount paths.
    ///
    /// Exactly one of `plugin` or `mounts` must be supplied.
    pub async fn reload_plugin_backend(&self, request: &PluginReloadRequest) -> Result<Empty> {
        let payload = validate_plugin_reload_request(request)?;
        self.client
            .request_sys_json_internal(Method::POST, "sys/plugins/reload/backend", Some(&payload))
            .await
    }

    /// Sets all runtime logger levels through `/sys/loggers`.
    ///
    /// OpenBao does not persist this change across reload or restart.
    pub async fn set_logger_levels(&self, level: LoggerLevel) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/loggers",
                Some(&LoggerLevelPayload {
                    level: level.as_str(),
                }),
            )
            .await
    }

    /// Sets one runtime logger level through `/sys/loggers/:name`.
    ///
    /// OpenBao does not persist this change across reload or restart.
    pub async fn set_logger_level(&self, name: &str, level: LoggerLevel) -> Result<Empty> {
        self.client
            .request_sys_json_internal(
                Method::POST,
                &sys_logger_path(name)?,
                Some(&LoggerLevelPayload {
                    level: level.as_str(),
                }),
            )
            .await
    }

    /// Reverts all runtime logger levels to the configured level.
    pub async fn reset_logger_levels(&self) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                "sys/loggers",
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reverts one runtime logger level to the configured level.
    pub async fn reset_logger_level(&self, name: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &sys_logger_path(name)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reads `/sys/config/cors`.
    ///
    /// OpenBao requires `sudo` capability for this endpoint.
    pub async fn cors_config(&self) -> Result<CorsConfig> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/config/cors", Option::<&Empty>::None)
            .await
    }

    /// Reads CORS configuration including OpenBao 2.6 credential state.
    pub async fn cors_config_details(&self) -> Result<CorsConfigDetails> {
        self.client
            .request_sys_json_internal(Method::GET, "sys/config/cors", Option::<&Empty>::None)
            .await
    }

    /// Writes `/sys/config/cors`.
    ///
    /// OpenBao requires `sudo` capability for this endpoint. The request uses
    /// explicit string arrays so commas are not ambiguously parsed by callers.
    pub async fn write_cors_config(&self, request: &CorsConfigRequest) -> Result<Empty> {
        request.validate()?;
        self.client
            .request_sys_json_internal(Method::POST, "sys/config/cors", Some(request))
            .await
    }

    /// Writes CORS configuration with OpenBao 2.6 credential support.
    pub async fn write_cors_config_with_credentials(
        &self,
        request: &CorsConfigRequest,
        allow_credentials: bool,
    ) -> Result<Empty> {
        request.validate()?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::CORS_ALLOW_CREDENTIALS,
                true,
            )])
            .await?;
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/config/cors",
                Some(&CorsConfigRequestWithCredentials {
                    request,
                    allow_credentials,
                }),
            )
            .await
    }

    /// Deletes `/sys/config/cors`.
    ///
    /// OpenBao requires `sudo` capability for this endpoint.
    pub async fn delete_cors_config(&self) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                "sys/config/cors",
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Lists installed OpenBao versions through `/sys/version-history`.
    pub async fn version_history(&self) -> Result<VersionHistory> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.client
            .request_sys_json_internal(method, "sys/version-history", Option::<&Empty>::None)
            .await
    }

    /// Lists installed versions with OpenBao 2.6 commit metadata.
    pub async fn version_history_details(&self) -> Result<VersionHistoryDetails> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.client
            .request_sys_json_internal(method, "sys/version-history", Option::<&Empty>::None)
            .await
    }

    /// Lists child namespaces through `/sys/namespaces`.
    pub async fn list_namespaces(&self) -> Result<NamespaceList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<NamespaceList> = self
            .client
            .request_sys_json_internal(method, "sys/namespaces", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Creates a namespace through `/sys/namespaces/:path`.
    pub async fn create_namespace(&self, path: &str, request: &NamespaceRequest) -> Result<Empty> {
        validate_namespace_request(request)?;
        self.client
            .request_sys_json_accepting(
                Method::POST,
                &namespace_path(path)?,
                Some(request),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Creates a Shamir-sealed namespace through `/sys/namespaces/:path`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged` and
    /// only for OpenBao 2.6.0 or newer exact profiles. The generated unseal
    /// shares are returned once and must be transferred to separate operator
    /// custody. Losing enough shares to fall below the threshold can make the
    /// namespace permanently inaccessible.
    #[cfg(feature = "operator-ops")]
    pub async fn create_sealable_namespace(
        &self,
        path: &str,
        request: &SealableNamespaceRequest,
    ) -> Result<SealableNamespaceCreation> {
        let path = namespace_path(path)?;
        validate_sealable_namespace_request(request)?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::NAMESPACE_SEAL_CONFIG,
                true,
            )])
            .await?;
        let payload = SealableNamespacePayload {
            custom_metadata: &request.custom_metadata,
            seal: request.seal_document(),
            pgp_keys: (!request.pgp_keys.is_empty()).then_some(request.pgp_keys.as_slice()),
        };
        let envelope: ResponseEnvelope<SealableNamespaceCreation> = self
            .client
            .request_sys_json_internal(Method::POST, &path, Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Reads namespace information through `/sys/namespaces/:path`.
    pub async fn read_namespace(&self, path: &str) -> Result<NamespaceInfo> {
        self.client
            .request_sys_json_internal(Method::GET, &namespace_path(path)?, Option::<&Empty>::None)
            .await
    }

    /// Patches namespace metadata through `/sys/namespaces/:path`.
    pub async fn patch_namespace(&self, path: &str, request: &NamespaceRequest) -> Result<Empty> {
        validate_namespace_request(request)?;
        self.client
            .request_sys_json_headers_accepting(
                Method::PATCH,
                &namespace_path(path)?,
                &[(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/merge-patch+json"),
                )],
                Some(request),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Clears all namespace custom metadata through `/sys/namespaces/:path`.
    ///
    /// OpenBao 2.5.5 added support for clearing namespace custom metadata by
    /// sending a JSON Merge Patch with top-level `custom_metadata: null`.
    pub async fn clear_namespace_metadata(&self, path: &str) -> Result<Empty> {
        let request = NamespaceClearMetadataRequest {
            custom_metadata: None,
        };
        self.client
            .request_sys_json_headers_accepting(
                Method::PATCH,
                &namespace_path(path)?,
                &[(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/merge-patch+json"),
                )],
                Some(&request),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Deletes a namespace through `/sys/namespaces/:path`.
    pub async fn delete_namespace(&self, path: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &namespace_path(path)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reads `/sys/namespaces/:path/seal-status` for a sealable namespace.
    ///
    /// This endpoint is available from OpenBao 2.6.0. Reading a non-sealable
    /// namespace's seal status returns an OpenBao API error.
    pub async fn namespace_seal_status(&self, path: &str) -> Result<NamespaceSealStatus> {
        let path = format!("{}/seal-status", namespace_path(path)?);
        let envelope: ResponseEnvelope<NamespaceSealStatus> = self
            .client
            .request_sys_json_internal(Method::GET, &path, Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Seals `/sys/namespaces/:path/seal` and recursively seals its children.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged` and
    /// only for OpenBao 2.6.0 or newer exact profiles. Sealing immediately
    /// discards in-memory namespace keys and interrupts any unseal attempt.
    #[cfg(feature = "operator-ops")]
    pub async fn seal_namespace(&self, path: &str) -> Result<Empty> {
        let path = format!("{}/seal", namespace_path(path)?);
        self.client
            .request_sys_json_accepting(
                Method::POST,
                &path,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Submits one secret share to `/sys/namespaces/:path/unseal`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged` and
    /// only for OpenBao 2.6.0 or newer exact profiles. The share is sent as
    /// sensitive request material and is never included in Debug output.
    #[cfg(feature = "operator-ops")]
    pub async fn unseal_namespace(
        &self,
        path: &str,
        key: &SecretString,
    ) -> Result<NamespaceSealStatus> {
        validate_namespace_unseal_key(key)?;
        self.namespace_unseal(path, Some(key), false).await
    }

    /// Resets progress for `/sys/namespaces/:path/unseal` without a key share.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged` and
    /// only for OpenBao 2.6.0 or newer exact profiles.
    #[cfg(feature = "operator-ops")]
    pub async fn reset_namespace_unseal(&self, path: &str) -> Result<NamespaceSealStatus> {
        self.namespace_unseal(path, None, true).await
    }

    /// Physically deletes a sealed namespace through `delete-sealed`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged` and
    /// only for OpenBao 2.6.0 or newer exact profiles. This sudo operation does
    /// not clean up external lease resources. Prefer [`Sys::delete_namespace`]
    /// whenever the namespace can be unsealed normally.
    ///
    /// [`SealedNamespaceDeletion::confirm_recursive`] authorizes irreversible
    /// deletion of all data and child namespaces. OpenBao schedules physical
    /// deletion asynchronously. `None` means OpenBao reported that the target
    /// did not exist.
    #[cfg(feature = "operator-ops")]
    pub async fn delete_sealed_namespace(
        &self,
        path: &str,
        confirmation: SealedNamespaceDeletion,
    ) -> Result<Option<SealedNamespaceDeletionStatus>> {
        let path = format!("{}/delete-sealed", namespace_path(path)?);
        let query = confirmation
            .force
            .then(|| ("force", "true".to_owned()))
            .into_iter()
            .collect::<Vec<_>>();
        let envelope: OptionalSealedNamespaceDeletionEnvelope = self
            .client
            .request_sys_json_query_accepting(
                Method::DELETE,
                &path,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    #[cfg(feature = "operator-ops")]
    async fn namespace_unseal(
        &self,
        path: &str,
        key: Option<&SecretString>,
        reset: bool,
    ) -> Result<NamespaceSealStatus> {
        let path = format!("{}/unseal", namespace_path(path)?);
        let payload = NamespaceUnsealPayload {
            key: key.map(ExposeSecret::expose_secret),
            reset: reset.then_some(true),
        };
        let envelope: ResponseEnvelope<NamespaceSealStatus> = self
            .client
            .request_sys_json_internal(Method::POST, &path, Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Reads global rate-limit quota configuration from `/sys/quotas/config`.
    pub async fn read_rate_limit_quota_config(&self) -> Result<RateLimitQuotaConfig> {
        let envelope: ResponseEnvelope<RateLimitQuotaConfig> = self
            .client
            .request_sys_json_internal(Method::GET, "sys/quotas/config", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Writes global rate-limit quota configuration to `/sys/quotas/config`.
    pub async fn write_rate_limit_quota_config(
        &self,
        request: &RateLimitQuotaConfig,
    ) -> Result<Empty> {
        validate_rate_limit_quota_config(request)?;
        self.client
            .request_sys_json_internal(Method::POST, "sys/quotas/config", Some(request))
            .await
    }

    /// Lists named rate-limit quotas through `/sys/quotas/rate-limit`.
    pub async fn list_rate_limit_quotas(&self) -> Result<RateLimitQuotaList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<RateLimitQuotaList> = self
            .client
            .request_sys_json_internal(method, "sys/quotas/rate-limit", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates a named rate-limit quota.
    pub async fn write_rate_limit_quota(
        &self,
        name: &str,
        request: &RateLimitQuotaRequest,
    ) -> Result<Empty> {
        validate_rate_limit_quota_request(request)?;
        self.client
            .request_sys_json_internal(Method::POST, &rate_limit_quota_path(name)?, Some(request))
            .await
    }

    /// Reads a named rate-limit quota.
    pub async fn read_rate_limit_quota(&self, name: &str) -> Result<RateLimitQuotaInfo> {
        let envelope: ResponseEnvelope<RateLimitQuotaInfo> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                &rate_limit_quota_path(name)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a named rate-limit quota.
    pub async fn delete_rate_limit_quota(&self, name: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::DELETE,
                &rate_limit_quota_path(name)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Lists users currently locked by OpenBao through `/sys/locked-users`.
    pub async fn list_locked_users(&self) -> Result<LockedUsers> {
        let envelope: ResponseEnvelope<LockedUsers> = self
            .client
            .request_sys_json_internal(Method::GET, "sys/locked-users", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Lists locked users for one auth mount accessor.
    pub async fn list_locked_users_for_accessor(
        &self,
        mount_accessor: &str,
    ) -> Result<LockedUsers> {
        let mount_accessor = single_path_segment(mount_accessor, "mount accessor")?;
        let payload = LockedUsersPayload {
            mount_accessor: &mount_accessor,
        };
        let envelope: ResponseEnvelope<LockedUsers> = self
            .client
            .request_sys_json_internal(Method::GET, "sys/locked-users", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Unlocks a user alias for an auth mount accessor.
    ///
    /// The OpenBao endpoint is idempotent and succeeds even when the user is
    /// not currently locked.
    pub async fn unlock_user(&self, mount_accessor: &str, alias_identifier: &str) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::POST,
                &locked_user_unlock_path(mount_accessor, alias_identifier)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Joins this node to an Integrated Storage Raft cluster.
    ///
    /// When using Shamir seal, OpenBao documents this call as happening before
    /// initialization on the joining node, followed immediately by unseal with
    /// leader shares.
    pub async fn raft_join(&self, request: &RaftJoinRequest) -> Result<RaftJoinResponse> {
        request.validate()?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::RAFT_JOIN_NON_VOTER,
                request.non_voter.is_some(),
            )])
            .await?;
        let payload = RaftJoinPayload {
            leader_api_addr: &request.leader_api_addr,
            retry: request.retry,
            leader_ca_cert: request.leader_ca_cert.as_deref(),
            leader_client_cert: request.leader_client_cert.as_deref(),
            leader_client_key: request
                .leader_client_key
                .as_ref()
                .map(SecretString::expose_secret),
            leader_tls_servername: request.leader_tls_servername.as_deref(),
            auto_join: request.auto_join.as_ref().map(SecretString::expose_secret),
            auto_join_scheme: request.auto_join_scheme.as_deref(),
            auto_join_port: request.auto_join_port,
            non_voter: request.non_voter,
        };
        self.client
            .request_sys_json_internal(Method::POST, "sys/storage/raft/join", Some(&payload))
            .await
    }

    /// Reads Integrated Storage Raft cluster configuration.
    pub async fn raft_configuration(&self) -> Result<RaftConfiguration> {
        let envelope: ResponseEnvelope<RaftConfiguration> = self
            .client
            .request_sys_json_internal(
                Method::GET,
                "sys/storage/raft/configuration",
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Removes one server from the Raft cluster.
    pub async fn raft_remove_peer(&self, request: &RaftPeerRequest) -> Result<Empty> {
        self.raft_peer_operation(RaftPeerOperation::Remove, request)
            .await
    }

    /// Promotes a permanent Raft non-voter to voter.
    pub async fn raft_promote_peer(&self, request: &RaftPeerRequest) -> Result<Empty> {
        self.raft_peer_operation(RaftPeerOperation::Promote, request)
            .await
    }

    /// Demotes a Raft voter to permanent non-voter.
    pub async fn raft_demote_peer(&self, request: &RaftPeerRequest) -> Result<Empty> {
        self.raft_peer_operation(RaftPeerOperation::Demote, request)
            .await
    }

    /// Bootstraps Raft when it is used exclusively for HA storage.
    pub async fn raft_bootstrap(&self) -> Result<Empty> {
        self.client
            .request_sys_json_accepting(
                Method::POST,
                "sys/storage/raft/bootstrap",
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Downloads an Integrated Storage Raft snapshot as bytes.
    ///
    /// The returned snapshot is encrypted by OpenBao's storage barrier, but it
    /// is still sensitive operational material. The SDK keeps the in-memory
    /// buffer sanitizing and applies the configured response-size cap. Large
    /// production snapshots may require a future streaming API.
    pub async fn raft_snapshot(&self) -> Result<SecretVec> {
        self.client
            .request_sys_bytes_accepting_internal(
                Method::GET,
                "sys/storage/raft/snapshot",
                &[],
                Some(HeaderValue::from_static("application/octet-stream")),
                None,
                &[StatusCode::OK],
            )
            .await
    }

    /// Restores Integrated Storage Raft from a snapshot.
    ///
    /// Snapshot restore can replace cluster state. Use only as part of an
    /// operator-controlled recovery ceremony. This in-memory helper is also
    /// subject to [`crate::OpenBaoConfig::max_request_bytes`]; enable
    /// `raft-stream` and use `raft_restore_snapshot_stream` for larger
    /// snapshots.
    pub async fn raft_restore_snapshot(&self, snapshot: &[u8]) -> Result<Empty> {
        validate_raft_snapshot(snapshot)?;
        self.client
            .request_sys_bytes_accepting_internal(
                Method::POST,
                "sys/storage/raft/snapshot",
                &[],
                None,
                Some(snapshot),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await?;
        Ok(Empty {})
    }

    /// Streams an exact-length Integrated Storage Raft snapshot restore.
    ///
    /// This is the required API for snapshots larger than the configured
    /// in-memory request limit. The stream fails if it yields more or fewer
    /// bytes than `snapshot_len`, and the declared length cannot exceed 256
    /// MiB. Available with the `raft-stream` feature.
    #[cfg(feature = "raft-stream")]
    pub async fn raft_restore_snapshot_stream<S, E>(
        &self,
        stream: S,
        snapshot_len: u64,
    ) -> Result<Empty>
    where
        S: Stream<Item = core::result::Result<Bytes, E>> + Send + Unpin + 'static,
        E: Send + 'static,
    {
        validate_raft_snapshot_length(snapshot_len)?;
        self.client
            .request_sys_exact_stream_accepting(
                Method::POST,
                "sys/storage/raft/snapshot",
                stream,
                snapshot_len,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await?;
        Ok(Empty {})
    }

    /// Force-restores Integrated Storage Raft from a snapshot.
    ///
    /// This bypasses OpenBao's checks that auto-unseal or Shamir keys match the
    /// snapshot. Use only after an explicit operator review. This in-memory
    /// helper is subject to [`crate::OpenBaoConfig::max_request_bytes`]; use
    /// `raft_force_restore_snapshot_stream` for larger snapshots.
    pub async fn raft_force_restore_snapshot(&self, snapshot: &[u8]) -> Result<Empty> {
        validate_raft_snapshot(snapshot)?;
        self.client
            .request_sys_bytes_accepting_internal(
                Method::POST,
                "sys/storage/raft/snapshot-force",
                &[],
                None,
                Some(snapshot),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await?;
        Ok(Empty {})
    }

    /// Streams an exact-length forced Integrated Storage Raft restore.
    ///
    /// This bypasses OpenBao's key-matching checks and has the same strict
    /// length enforcement as [`Self::raft_restore_snapshot_stream`]. Available
    /// with the `raft-stream` feature.
    #[cfg(feature = "raft-stream")]
    pub async fn raft_force_restore_snapshot_stream<S, E>(
        &self,
        stream: S,
        snapshot_len: u64,
    ) -> Result<Empty>
    where
        S: Stream<Item = core::result::Result<Bytes, E>> + Send + Unpin + 'static,
        E: Send + 'static,
    {
        validate_raft_snapshot_length(snapshot_len)?;
        self.client
            .request_sys_exact_stream_accepting(
                Method::POST,
                "sys/storage/raft/snapshot-force",
                stream,
                snapshot_len,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await?;
        Ok(Empty {})
    }

    /// Reads Raft Autopilot state as JSON.
    ///
    /// The state schema is mostly diagnostic and may grow with OpenBao, so this
    /// helper returns JSON under the normal response-size protections.
    pub async fn raft_autopilot_state_json(&self) -> Result<JsonValue> {
        let document: BoundedJsonValue = self
            .client
            .request_sys_json_internal(
                Method::GET,
                "sys/storage/raft/autopilot/state",
                Option::<&Empty>::None,
            )
            .await?;
        Ok(document.into_inner())
    }

    /// Reads Raft Autopilot configuration.
    pub async fn raft_autopilot_config(&self) -> Result<RaftAutopilotConfig> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                "sys/storage/raft/autopilot/configuration",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Writes Raft Autopilot configuration.
    pub async fn write_raft_autopilot_config(&self, config: &RaftAutopilotConfig) -> Result<Empty> {
        config.validate()?;
        self.client
            .request_sys_json_internal(
                Method::POST,
                "sys/storage/raft/autopilot/configuration",
                Some(config),
            )
            .await
    }

    /// Starts moving a mounted secrets engine or auth method.
    ///
    /// OpenBao revokes leases or tokens associated with the moved backend.
    /// Callers should use [`Self::remount_status`] with the returned migration
    /// ID before assuming the new mount is ready.
    pub async fn remount(&self, request: &RemountRequest) -> Result<RemountResponse> {
        request.validate()?;
        self.client
            .request_sys_json_internal(Method::POST, "sys/remount", Some(request))
            .await
    }

    /// Reads the status of a mount migration.
    pub async fn remount_status(&self, migration_id: &str) -> Result<RemountStatus> {
        self.client
            .request_sys_json_internal(
                Method::GET,
                &remount_status_path(migration_id)?,
                Option::<&Empty>::None,
            )
            .await
    }

    async fn raft_peer_operation(
        &self,
        operation: RaftPeerOperation,
        request: &RaftPeerRequest,
    ) -> Result<Empty> {
        request.validate()?;
        let payload = RaftPeerPayload {
            server_id: &request.server_id,
            dr_operation_token: request
                .dr_operation_token
                .as_ref()
                .map(SecretString::expose_secret),
        };
        self.client
            .request_sys_json_accepting(
                Method::POST,
                &format!("sys/storage/raft/{}", operation.as_path_segment()),
                Some(&payload),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Looks up a wrapping token.
    pub async fn wrapping_lookup(&self, token: &SecretString) -> Result<WrappingLookup> {
        let payload = WrappingTokenPayload {
            token: token.expose_secret(),
        };
        let envelope: ResponseEnvelope<WrappingLookup> = self
            .client
            .request_sys_json_internal(Method::POST, "sys/wrapping/lookup", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Wraps arbitrary JSON data and returns wrapping token metadata.
    pub async fn wrapping_wrap<T>(&self, ttl: &str, data: &T) -> Result<WrapInfo>
    where
        T: Serialize + ?Sized,
    {
        validate_wrapping_ttl(ttl)?;
        let ttl =
            HeaderValue::from_str(ttl).map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<Option<Empty>> = self
            .client
            .request_sys_json_headers_accepting(
                Method::POST,
                "sys/wrapping/wrap",
                &[(HeaderName::from_static("x-vault-wrap-ttl"), ttl)],
                Some(data),
                &[StatusCode::OK],
            )
            .await?;
        envelope.wrap_info.ok_or(Error::MissingField("wrap_info"))
    }

    /// Unwraps a wrapping token and decodes the original response data.
    pub async fn wrapping_unwrap<T>(&self, token: Option<&SecretString>) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        match token {
            Some(token) => {
                let payload = WrappingTokenPayload {
                    token: token.expose_secret(),
                };
                let envelope: ResponseEnvelope<T> = self
                    .client
                    .request_sys_json_internal(Method::POST, "sys/wrapping/unwrap", Some(&payload))
                    .await?;
                Ok(envelope.data)
            }
            None => {
                let envelope: ResponseEnvelope<T> = self
                    .client
                    .request_sys_json_internal(
                        Method::POST,
                        "sys/wrapping/unwrap",
                        Option::<&Empty>::None,
                    )
                    .await?;
                Ok(envelope.data)
            }
        }
    }

    /// Rewraps a wrapping token and returns replacement wrapping token metadata.
    pub async fn wrapping_rewrap(&self, token: &SecretString) -> Result<WrapInfo> {
        let payload = WrappingTokenPayload {
            token: token.expose_secret(),
        };
        let envelope: ResponseEnvelope<Option<Empty>> = self
            .client
            .request_sys_json_internal(Method::POST, "sys/wrapping/rewrap", Some(&payload))
            .await?;
        envelope.wrap_info.ok_or(Error::MissingField("wrap_info"))
    }
}

fn validate_dev_bootstrap_options(secret_shares: u8, secret_threshold: u8) -> Result<()> {
    if secret_shares == 0 {
        return Err(Error::InvalidParameter(
            "secret_shares must be greater than zero".into(),
        ));
    }
    if secret_threshold == 0 {
        return Err(Error::InvalidParameter(
            "secret_threshold must be greater than zero".into(),
        ));
    }
    if secret_threshold > secret_shares {
        return Err(Error::InvalidParameter(
            "secret_threshold must be less than or equal to secret_shares".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "operator-ops")]
fn validate_key_share_options(secret_shares: u8, secret_threshold: u8) -> Result<()> {
    if secret_shares == 0 {
        return Err(Error::InvalidParameter(
            "secret_shares must be greater than zero".into(),
        ));
    }
    if secret_threshold == 0 {
        return Err(Error::InvalidParameter(
            "secret_threshold must be greater than zero".into(),
        ));
    }
    if secret_threshold > secret_shares {
        return Err(Error::InvalidParameter(
            "secret_threshold must be less than or equal to secret_shares".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "operator-ops")]
fn rotate_init_path(target: OperatorRotateTarget) -> String {
    format!("sys/rotate/{}/init", target.path_segment())
}

#[cfg(feature = "operator-ops")]
fn rotate_update_path(target: OperatorRotateTarget) -> String {
    format!("sys/rotate/{}/update", target.path_segment())
}

#[cfg(feature = "operator-ops")]
fn rotate_verify_path(target: OperatorRotateTarget) -> String {
    format!("sys/rotate/{}/verify", target.path_segment())
}

#[cfg(feature = "operator-ops")]
fn rotation_verify_cancel_path(target: OperatorRotateTarget) -> String {
    format!("sys/rotation/{}/verify", target.path_segment())
}

#[cfg(feature = "operator-ops")]
fn rotate_backup_path(target: OperatorRotateTarget) -> String {
    format!("sys/rotate/{}/backup", target.path_segment())
}

#[cfg(feature = "dev-bootstrap")]
fn require_loopback_dev_target<State>(client: &Client<State>) -> Result<()> {
    let url = client.base_url();
    let Some(host) = url.host_str() else {
        return Err(Error::InvalidBaseUrl(
            "dev bootstrap requires a numeric loopback OpenBao host".into(),
        ));
    };
    if !host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
    {
        return Err(Error::InvalidBaseUrl(
            "dev bootstrap is restricted to numeric loopback OpenBao hosts".into(),
        ));
    }
    Ok(())
}

fn openbao_status(code: u16) -> Result<StatusCode> {
    StatusCode::from_u16(code)
        .map_err(|_| crate::Error::Internal("invalid OpenBao health status code"))
}

fn sys_path(prefix: &str, mount_path: &str, suffix: Option<&str>) -> Result<String> {
    let mut segments = vec![prefix.to_owned()];
    segments.extend(validate_mount_path(mount_path)?);
    if let Some(suffix) = suffix {
        segments.push(suffix.to_owned());
    }
    Ok(segments.join("/"))
}

fn sys_logger_path(name: &str) -> Result<String> {
    let segments = validate_mount_path(name)?;
    if segments.len() != 1 {
        return Err(Error::InvalidPath(
            "logger name must be a single path segment".into(),
        ));
    }
    Ok(["sys/loggers", &segments[0]].join("/"))
}

fn sys_random_path(source: Option<SysRandomSource>, bytes: Option<u64>) -> String {
    let mut segments = vec!["sys/tools/random"];
    let bytes = bytes.map(|value| value.to_string());
    if let Some(source) = source {
        segments.push(source.as_path_segment());
    }
    if let Some(bytes) = bytes.as_deref() {
        segments.push(bytes);
    }
    segments.join("/")
}

fn sys_hash_path(algorithm: SysHashAlgorithm) -> String {
    ["sys/tools/hash", algorithm.as_path_segment()].join("/")
}

#[cfg(feature = "operator-ops")]
fn raw_storage_path(path: &str) -> Result<String> {
    let segments = validate_endpoint_path(path)?;
    if segments.is_empty() {
        return Err(Error::InvalidPath(
            "raw storage path must not be empty".into(),
        ));
    }
    Ok(["sys/raw", &segments.join("/")].join("/"))
}

#[cfg(feature = "operator-ops")]
fn pprof_path(profile: PprofProfile) -> String {
    ["sys/pprof", profile.as_path_segment()].join("/")
}

#[cfg(feature = "operator-ops")]
fn validate_pprof_options(profile: PprofProfile, options: &PprofOptions) -> Result<()> {
    if let Some(seconds) = options.seconds {
        if !matches!(profile, PprofProfile::Profile | PprofProfile::Trace) {
            return Err(Error::InvalidParameter(
                "pprof seconds is supported only for profile and trace".into(),
            ));
        }
        if seconds == 0 || seconds > MAX_SYS_PPROF_SECONDS {
            return Err(Error::InvalidParameter(format!(
                "pprof seconds must be between 1 and {MAX_SYS_PPROF_SECONDS}"
            )));
        }
    }

    if let Some(debug) = options.debug {
        if !matches!(profile, PprofProfile::Goroutine) {
            return Err(Error::InvalidParameter(
                "pprof debug is supported only for goroutine".into(),
            ));
        }
        if debug > 2 {
            return Err(Error::InvalidParameter(
                "pprof debug must be 0, 1, or 2".into(),
            ));
        }
    }

    Ok(())
}

fn validate_sys_random_bytes(bytes: u64) -> Result<()> {
    if bytes == 0 {
        return Err(Error::InvalidParameter(
            "system random byte count must be greater than zero".into(),
        ));
    }
    if bytes > MAX_SYS_RANDOM_BYTES {
        return Err(Error::InvalidParameter(format!(
            "system random byte count must not exceed {MAX_SYS_RANDOM_BYTES}"
        )));
    }
    Ok(())
}

#[cfg(feature = "unstable-internal-ops")]
fn deserialize_bounded_router_mount_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<InternalRouterMount>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RouterMountVisitor;

    impl<'de> Visitor<'de> for RouterMountVisitor {
        type Value = Vec<InternalRouterMount>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded internal router mount list")
        }

        fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while values.len() < crate::response::MAX_RESPONSE_STRINGS {
                let Some(value) = sequence.next_element::<InternalRouterMount>()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    "OpenBao internal router list exceeds item limit",
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(RouterMountVisitor)
}

#[cfg(feature = "operator-ops")]
fn decode_operator_token(request: &DecodeTokenRequest) -> Result<DecodeTokenResponse> {
    const MAX_GENERATED_TOKEN_BYTES: usize = 16 * 1024;

    let encoded = request.encoded_token.expose_secret();
    let otp = request.otp.expose_secret().as_bytes();
    if encoded.is_empty() || encoded.len() > MAX_GENERATED_TOKEN_BYTES * 2 {
        return Err(Error::InvalidParameter(
            "encoded operator token is empty or exceeds the supported limit".into(),
        ));
    }
    if otp.is_empty() || otp.len() > MAX_GENERATED_TOKEN_BYTES {
        return Err(Error::InvalidParameter(
            "operator token OTP is empty or exceeds the supported limit".into(),
        ));
    }

    let decoded = base64_ng::ct::STANDARD_NO_PAD
        .decode_secret(encoded.as_bytes())
        .map_err(|_| Error::Decode("encoded operator token is not valid unpadded base64".into()))?;
    let exposed = decoded.into_exposed_vec();
    let mut token = SecretVec::from_vec(exposed.into_exposed_unprotected_vec_caller_must_zeroize());
    if token.len() != otp.len() {
        return Err(Error::InvalidParameter(
            "decoded operator token and OTP lengths differ".into(),
        ));
    }
    token.with_secret_mut(|bytes| {
        for (byte, otp_byte) in bytes.iter_mut().zip(otp) {
            *byte ^= otp_byte;
        }
    });
    let decoded_token = token.with_secret(|bytes| {
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| Error::Decode("decoded operator token is not valid UTF-8".into()))
    })?;
    // `SecretString::from(String)` moves this allocation into secrecy's
    // zeroizing box; it does not copy or abandon the plaintext allocation.
    Ok(DecodeTokenResponse {
        token: SecretString::from(decoded_token),
    })
}

#[cfg(feature = "transit-bytes")]
fn encode_sys_base64_secret(input: &[u8]) -> Result<SecretString> {
    let encoded = base64_ng::STANDARD
        .encode_secret(input)
        .map_err(|_| Error::InvalidParameter("base64 input is too large".into()))?;
    let exposed = encoded.try_into_exposed_string().map_err(|_| {
        Error::Internal("base64-ng produced non-UTF-8 text for standard base64 output")
    })?;
    Ok(SecretString::from(
        exposed.into_exposed_unprotected_string_caller_must_zeroize(),
    ))
}

#[cfg(feature = "transit-bytes")]
fn decode_sys_base64_secret(input: &SecretString) -> Result<SecretVec> {
    let decoded = base64_ng::ct::STANDARD
        .decode_secret(input.expose_secret().as_bytes())
        .map_err(|_| Error::Decode("OpenBao response contained invalid base64".into()))?;
    let exposed = decoded.into_exposed_vec();
    Ok(SecretVec::from_vec(
        exposed.into_exposed_unprotected_vec_caller_must_zeroize(),
    ))
}

fn namespace_path(path: &str) -> Result<String> {
    let segments = validate_namespace_path(path)?;
    Ok(["sys/namespaces", &segments.join("/")].join("/"))
}

fn validate_namespace_path(path: &str) -> Result<Vec<String>> {
    if path.ends_with('/') {
        return Err(Error::InvalidPath(
            "namespace path must not end with a slash".into(),
        ));
    }
    let segments = validate_mount_path(path)?;
    for segment in &segments {
        if segment.contains(' ') {
            return Err(Error::InvalidPath(
                "namespace path segments must not contain spaces".into(),
            ));
        }
        if matches!(
            segment.as_str(),
            "root" | "sys" | "audit" | "auth" | "cubbyhole" | "identity"
        ) {
            return Err(Error::InvalidPath(
                "namespace path segment uses a reserved OpenBao namespace name".into(),
            ));
        }
    }
    Ok(segments)
}

fn validate_namespace_request(request: &NamespaceRequest) -> Result<()> {
    validate_namespace_metadata(&request.custom_metadata)
}

fn validate_namespace_metadata(metadata: &BTreeMap<String, String>) -> Result<()> {
    if metadata.len() > crate::response::MAX_RESPONSE_STRINGS {
        return Err(Error::InvalidParameter(
            "namespace metadata exceeds maximum item count".into(),
        ));
    }
    for (key, value) in metadata {
        if key.len() > MAX_SYSTEM_RESPONSE_METADATA_BYTES
            || value.len() > MAX_SYSTEM_RESPONSE_METADATA_BYTES
        {
            return Err(Error::InvalidParameter(
                "namespace metadata exceeds byte limit".into(),
            ));
        }
        if key.chars().any(char::is_control) || value.chars().any(char::is_control) {
            return Err(Error::InvalidParameter(
                "namespace metadata must not contain control characters".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "operator-ops")]
fn validate_sealable_namespace_request(request: &SealableNamespaceRequest) -> Result<()> {
    validate_namespace_key_share_options(request.key_shares, request.key_threshold)?;
    validate_namespace_metadata(&request.custom_metadata)?;
    if !request.pgp_keys.is_empty() && request.pgp_keys.len() != usize::from(request.key_shares) {
        return Err(Error::InvalidParameter(
            "namespace PGP key count must equal key share count".into(),
        ));
    }
    for key in &request.pgp_keys {
        if key.is_empty() || key.len() > MAX_NAMESPACE_PGP_KEY_BYTES {
            return Err(Error::InvalidParameter(
                "namespace PGP key is empty or exceeds byte limit".into(),
            ));
        }
        if !key.is_ascii()
            || key.as_bytes().iter().any(u8::is_ascii_control)
            || base64_ng::STANDARD.validate_result(key.as_bytes()).is_err()
        {
            return Err(Error::InvalidParameter(
                "namespace PGP keys must be canonical standard base64 text".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "operator-ops")]
fn validate_namespace_key_share_options(key_shares: u8, key_threshold: u8) -> Result<()> {
    validate_key_share_options(key_shares, key_threshold)?;
    if key_shares > 1 && key_threshold < 2 {
        return Err(Error::InvalidParameter(
            "namespace key_threshold must be at least two when multiple shares are configured"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "operator-ops")]
fn validate_namespace_unseal_key(key: &SecretString) -> Result<()> {
    let value = key.expose_secret();
    let invalid = value.is_empty()
        || value.len() > MAX_NAMESPACE_UNSEAL_KEY_BYTES
        || value.as_bytes().iter().any(u8::is_ascii_control);
    if invalid {
        return Err(Error::InvalidParameter(
            "namespace unseal key is empty, oversized, or contains control characters".into(),
        ));
    }
    Ok(())
}

fn validate_cors_origins(origins: &[String]) -> Result<()> {
    if origins.is_empty() {
        return Err(Error::InvalidParameter(
            "CORS allowed_origins must contain at least one origin".into(),
        ));
    }
    if origins.len() > crate::response::MAX_RESPONSE_STRINGS {
        return Err(Error::InvalidParameter(
            "CORS allowed_origins exceeds maximum item count".into(),
        ));
    }
    for origin in origins {
        let trimmed = origin.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidParameter(
                "CORS allowed origin must not be empty".into(),
            ));
        }
        if trimmed != origin {
            return Err(Error::InvalidParameter(
                "CORS allowed origin must not contain leading or trailing whitespace".into(),
            ));
        }
        if trimmed == "*" || trimmed.eq_ignore_ascii_case("null") {
            return Err(Error::InvalidParameter(
                "CORS wildcard '*' and 'null' origins are not allowed because they permit ambiguous authenticated requests to OpenBao".into(),
            ));
        }
        if origin.as_bytes().iter().any(u8::is_ascii_control) {
            return Err(Error::InvalidParameter(
                "CORS allowed origin must not contain control characters".into(),
            ));
        }
        let parsed = Url::parse(origin).map_err(|_| {
            Error::InvalidParameter("CORS allowed origin must be a valid https:// URL".into())
        })?;
        if parsed.scheme() != "https" {
            return Err(Error::InvalidParameter(
                "CORS allowed origin must use the https:// scheme".into(),
            ));
        }
        if parsed.host_str().is_none()
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(Error::InvalidParameter(
                "CORS allowed origin must be an origin only, such as https://app.example.com"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn validate_http_header_names(headers: &[String], field: &'static str) -> Result<()> {
    if headers.len() > crate::response::MAX_RESPONSE_STRINGS {
        return Err(Error::InvalidParameter(format!(
            "{field} list exceeds maximum item count"
        )));
    }
    for header in headers {
        HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
            Error::InvalidParameter(format!("{field} must contain valid HTTP header names"))
        })?;
    }
    Ok(())
}

fn rate_limit_quota_path(name: &str) -> Result<String> {
    Ok([
        "sys/quotas/rate-limit",
        &single_path_segment(name, "quota name")?,
    ]
    .join("/"))
}

fn locked_user_unlock_path(mount_accessor: &str, alias_identifier: &str) -> Result<String> {
    Ok([
        "sys/locked-users",
        &single_path_segment(mount_accessor, "mount accessor")?,
        "unlock",
        &single_path_segment(alias_identifier, "alias identifier")?,
    ]
    .join("/"))
}

fn audited_request_header_path(name: &str) -> Result<String> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
        Error::InvalidParameter(
            "audited request header name must be a valid HTTP header name".into(),
        )
    })?;
    Ok(["sys/config/auditing/request-headers", name.as_str()].join("/"))
}

#[cfg(feature = "unstable-internal-ops")]
fn ui_header_path(name: &str) -> Result<String> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
        Error::InvalidParameter("UI header name must be a valid HTTP header name".into())
    })?;
    Ok(["sys/config/ui/headers", name.as_str()].join("/"))
}

fn internal_ui_mount_path(path: &str) -> Result<String> {
    if path.trim_matches('/').is_empty() {
        return Err(Error::InvalidPath("UI mount path must not be empty".into()));
    }
    Ok([
        "sys/internal/ui/mounts",
        &validate_endpoint_path(path)?.join("/"),
    ]
    .join("/"))
}

fn remount_status_path(migration_id: &str) -> Result<String> {
    Ok([
        "sys/remount/status",
        &single_path_segment(migration_id, "migration id")?,
    ]
    .join("/"))
}

fn validate_remount_endpoint_path(path: &str, field: &'static str) -> Result<()> {
    if path.trim_matches('/').is_empty() {
        return Err(Error::InvalidPath(format!("{field} must not be empty")));
    }
    let _segments = validate_endpoint_path(path)?;
    Ok(())
}

fn validate_raft_server_id(server_id: &str) -> Result<()> {
    if server_id.is_empty() {
        return Err(Error::InvalidParameter(
            "Raft server_id must not be empty".into(),
        ));
    }
    if server_id.len() > 256 {
        return Err(Error::InvalidParameter(
            "Raft server_id exceeds maximum length".into(),
        ));
    }
    if server_id.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidParameter(
            "Raft server_id must not contain control characters".into(),
        ));
    }
    Ok(())
}

fn validate_raft_snapshot(snapshot: &[u8]) -> Result<()> {
    validate_raft_snapshot_length(u64::try_from(snapshot.len()).unwrap_or(u64::MAX))
}

fn validate_raft_snapshot_length(snapshot_len: u64) -> Result<()> {
    if snapshot_len == 0 {
        return Err(Error::InvalidParameter(
            "Raft snapshot payload must not be empty".into(),
        ));
    }
    if snapshot_len > MAX_RAFT_SNAPSHOT_BYTES {
        return Err(Error::InvalidParameter(format!(
            "Raft snapshot payload exceeds maximum allowed size of {MAX_RAFT_SNAPSHOT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_optional_duration_string(value: &Option<String>, field: &'static str) -> Result<()> {
    if let Some(value) = value
        && !crate::validation::validate_duration_string(value, false)
    {
        return Err(Error::InvalidParameter(format!(
            "{field} must be a positive duration such as 30s, 5m, or 1h"
        )));
    }
    Ok(())
}

fn validate_optional_positive_integer(value: &Option<String>, field: &'static str) -> Result<()> {
    if let Some(value) = value
        && !value.parse::<u64>().is_ok_and(|number| number > 0)
    {
        return Err(Error::InvalidParameter(format!(
            "{field} must be a positive integer"
        )));
    }
    Ok(())
}

fn single_path_segment(value: &str, kind: &'static str) -> Result<String> {
    let segments = validate_mount_path(value)?;
    if segments.len() != 1 {
        return Err(Error::InvalidPath(format!(
            "{kind} must be a single path segment"
        )));
    }
    Ok(segments[0].clone())
}

fn validate_rate_limit_quota_config(request: &RateLimitQuotaConfig) -> Result<()> {
    if request.rate_limit_exempt_paths.len() > crate::response::MAX_RESPONSE_STRINGS {
        return Err(Error::InvalidParameter(
            "rate limit exempt paths exceed maximum item count".into(),
        ));
    }
    for path in &request.rate_limit_exempt_paths {
        if path.trim_matches('/').is_empty() {
            return Err(Error::InvalidPath(
                "rate limit exempt path must not be empty".into(),
            ));
        }
        let _validated = validate_endpoint_path(path)?;
    }
    Ok(())
}

fn validate_rate_limit_quota_request(request: &RateLimitQuotaRequest) -> Result<()> {
    if !request.rate.is_finite() || request.rate <= 0.0 {
        return Err(Error::InvalidParameter(
            "rate limit quota rate must be a positive finite number".into(),
        ));
    }
    if let Some(path) = &request.path {
        let _validated = validate_endpoint_path(path)?;
    }
    if let Some(interval) = &request.interval {
        crate::validation::validate_duration_parameter(interval, "rate limit interval")?;
    }
    if let Some(block_interval) = &request.block_interval {
        crate::validation::validate_duration_parameter(
            block_interval,
            "rate limit block_interval",
        )?;
    }
    if let Some(role) = request.role.as_deref() {
        validate_query_string_value(role, "rate limit role")?;
    }
    Ok(())
}

fn validate_wrapping_ttl(ttl: &str) -> Result<()> {
    if crate::validation::validate_duration_string(ttl, false) {
        return Ok(());
    }
    Err(Error::InvalidHeader(
        "wrapping TTL must be a positive duration such as 30s, 5m, or 1h".into(),
    ))
}

fn validate_capability_paths<I, P>(paths: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    let mut validated = Vec::new();
    for path in paths {
        let path = path.as_ref();
        if path.trim_matches('/').is_empty() {
            return Err(Error::InvalidPath(
                "capability path must not be empty".into(),
            ));
        }
        validated.push(validate_endpoint_path(path)?.join("/"));
    }
    if validated.is_empty() {
        return Err(Error::InvalidPath(
            "at least one capability path is required".into(),
        ));
    }
    Ok(validated)
}

fn validate_lease_id(lease_id: &SecretString) -> Result<&str> {
    const MAX_LEASE_ID_BYTES: usize = 512;

    let lease_id = lease_id.expose_secret();
    if lease_id.is_empty() {
        return Err(Error::InvalidPath("lease ID must not be empty".into()));
    }
    if lease_id.len() > MAX_LEASE_ID_BYTES {
        return Err(Error::InvalidPath(
            "lease ID exceeds maximum allowed length".into(),
        ));
    }
    if lease_id.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidPath(
            "lease ID must not contain control characters".into(),
        ));
    }
    Ok(lease_id)
}

fn validate_lease_prefix(prefix: &str) -> Result<String> {
    const MAX_LEASE_PREFIX_BYTES: usize = 512;

    if prefix.is_empty() {
        return Err(Error::InvalidPath("lease prefix must not be empty".into()));
    }
    if prefix.len() > MAX_LEASE_PREFIX_BYTES {
        return Err(Error::InvalidPath(
            "lease prefix exceeds maximum allowed length".into(),
        ));
    }
    if prefix.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidPath(
            "lease prefix must not contain control characters".into(),
        ));
    }
    Ok(validate_endpoint_path(prefix)?.join("/"))
}

fn plugin_catalog_type_path(plugin_type: PluginType) -> Result<String> {
    Ok(["sys/plugins/catalog", plugin_type.as_path_segment()].join("/"))
}

fn plugin_catalog_entry_path(plugin_type: PluginType, name: &str) -> Result<String> {
    let mut segments = vec![
        "sys/plugins/catalog".to_owned(),
        plugin_type.as_path_segment().to_owned(),
    ];
    segments.extend(validate_mount_path(name)?);
    Ok(segments.join("/"))
}

fn validate_sha256_hex(value: &str, field: &'static str) -> Result<()> {
    if value.len() != 64 {
        return Err(Error::InvalidPath(format!(
            "{field} must be a 64-character SHA-256 hex digest"
        )));
    }
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Error::InvalidPath(format!(
            "{field} must contain only lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn plugin_version_query(version: Option<&str>) -> Result<Vec<(&'static str, String)>> {
    match version {
        Some(version) => {
            validate_query_string_value(version, "plugin version")?;
            Ok(vec![("version", version.to_owned())])
        }
        None => Ok(Vec::new()),
    }
}

fn validate_plugin_reload_request<'a>(
    request: &'a PluginReloadRequest,
) -> Result<PluginReloadPayload<'a>> {
    let has_plugin = request
        .plugin
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    let has_mounts = !request.mounts.is_empty();
    match (has_plugin, has_mounts) {
        (true, false) | (false, true) => {}
        (false, false) => {
            return Err(Error::InvalidPath(
                "plugin reload requires a plugin name or mount paths".into(),
            ));
        }
        (true, true) => {
            return Err(Error::InvalidPath(
                "plugin reload accepts either plugin or mounts, not both".into(),
            ));
        }
    }

    let plugin = match request.plugin.as_deref() {
        Some(plugin) if !plugin.is_empty() => {
            let _segments = validate_mount_path(plugin)?;
            Some(plugin)
        }
        _ => None,
    };
    let mut mounts = Vec::new();
    for mount in &request.mounts {
        mounts.push(validate_mount_path(mount)?.join("/"));
    }
    if let Some(scope) = request.scope.as_deref() {
        validate_query_string_value(scope, "plugin reload scope")?;
    }

    Ok(PluginReloadPayload {
        plugin,
        mounts,
        scope: request.scope.as_deref(),
    })
}

fn validate_query_string_value(value: &str, kind: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidPath(format!("{kind} must not be empty")));
    }
    if value.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidPath(format!(
            "{kind} must not contain control characters"
        )));
    }
    Ok(())
}

fn workflow_path(prefix: &str, path: &str) -> Result<String> {
    let segments = validate_endpoint_path(path)?;
    if segments.is_empty() {
        return Err(Error::InvalidPath("workflow path must not be empty".into()));
    }
    Ok(format!("{prefix}/{}", segments.join("/")))
}

fn validate_workflow_definition(workflow: &str) -> Result<()> {
    if workflow.is_empty() {
        return Err(Error::InvalidParameter(
            "workflow definition must not be empty".into(),
        ));
    }
    if workflow.len() > MAX_WORKFLOW_DEFINITION_BYTES {
        return Err(Error::InvalidParameter(
            "workflow definition exceeds byte limit".into(),
        ));
    }
    if workflow.contains('\0') {
        return Err(Error::InvalidParameter(
            "workflow definition must not contain NUL".into(),
        ));
    }
    Ok(())
}

fn validate_workflow_write_request(request: &WorkflowWriteRequest) -> Result<()> {
    validate_workflow_definition(request.workflow.expose_secret())?;
    if request.cas.is_some() || request.cas_required {
        return Err(Error::InvalidParameter(
            "workflow CAS is unsafe on OpenBao 2.6.0 through 2.6.2 because the server discards the cas field"
                .into(),
        ));
    }
    Ok(())
}

fn validate_workflow_json(contents: &SecretVec) -> Result<()> {
    if contents.len() > MAX_WORKFLOW_DATA_BYTES {
        return Err(Error::InvalidParameter(
            "workflow JSON exceeds byte limit".into(),
        ));
    }
    contents.with_secret(|bytes| {
        let raw = serde_json::from_slice::<&RawValue>(bytes)
            .map_err(|_| Error::InvalidParameter("workflow data must be valid JSON".into()))?;
        if !raw.get().trim_start().starts_with('{') {
            return Err(Error::InvalidParameter(
                "workflow data must be a JSON object".into(),
            ));
        }
        Ok(())
    })
}

fn workflow_data_from_envelope(body: SecretVec) -> Result<WorkflowData> {
    body.with_secret(|bytes| {
        #[derive(Deserialize)]
        struct WorkflowEnvelope<'a> {
            #[serde(default, borrow)]
            data: Option<&'a RawValue>,
        }

        let envelope: WorkflowEnvelope<'_> = serde_json::from_slice(bytes)
            .map_err(|_| Error::Decode("OpenBao workflow response did not match schema".into()))?;
        let Some(data) = envelope.data.filter(|value| value.get() != "null") else {
            return Ok(WorkflowData::empty());
        };
        WorkflowData::from_json_bytes(SecretVec::from_slice(data.get().as_bytes()))
    })
}

fn workflow_typed_data_from_envelope<T>(body: SecretVec) -> Result<T>
where
    T: DeserializeOwned,
{
    body.with_secret(|bytes| {
        #[derive(Deserialize)]
        struct WorkflowEnvelope<'a> {
            #[serde(borrow)]
            data: &'a RawValue,
        }

        let envelope: WorkflowEnvelope<'_> = serde_json::from_slice(bytes)
            .map_err(|_| Error::Decode("OpenBao workflow response did not match schema".into()))?;
        serde_json::from_str(envelope.data.get())
            .map_err(|_| Error::Decode("OpenBao workflow data did not match schema".into()))
    })
}

fn validate_workflow_path_for_serde<E>(path: &str) -> core::result::Result<(), E>
where
    E: serde::de::Error,
{
    let segments = validate_endpoint_path(path).map_err(E::custom)?;
    if segments.is_empty() {
        return Err(E::custom("workflow path must not be empty"));
    }
    Ok(())
}

fn deserialize_bounded_workflow_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, WorkflowInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    struct WorkflowMapVisitor;

    impl<'de> Visitor<'de> for WorkflowMapVisitor {
        type Value = BTreeMap<String, WorkflowInfo>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "a map of at most {MAX_RESPONSE_STRINGS} workflow definitions"
            )
        }

        fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            let mut entries = 0_usize;
            while let Some(key) = map.next_key::<String>()? {
                if entries >= MAX_RESPONSE_STRINGS {
                    let _ignored = map.next_value::<IgnoredAny>()?;
                    return Err(A::Error::custom("workflow map exceeds item limit"));
                }
                validate_workflow_path_for_serde::<A::Error>(&key)?;
                let value = map.next_value::<WorkflowInfo>()?;
                if value.path != key {
                    return Err(A::Error::custom(
                        "workflow map key does not match response path",
                    ));
                }
                if values.insert(key, value).is_some() {
                    return Err(A::Error::custom("workflow map contains a duplicate path"));
                }
                entries += 1;
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(WorkflowMapVisitor)
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> core::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

const MAX_SYSTEM_RESPONSE_METADATA_BYTES: usize = 4096;

fn validate_system_response_metadata<E>(value: &str) -> core::result::Result<(), E>
where
    E: serde::de::Error,
{
    if value.len() > MAX_SYSTEM_RESPONSE_METADATA_BYTES {
        return Err(E::custom("system response metadata exceeds byte limit"));
    }
    if value.chars().any(char::is_control) {
        return Err(E::custom(
            "system response metadata contains control characters",
        ));
    }
    Ok(())
}

fn deserialize_safe_metadata_string<'de, D>(
    deserializer: D,
) -> core::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_system_response_metadata::<D::Error>(&value)?;
    Ok(value)
}

fn deserialize_optional_safe_metadata_string<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(value) = value.as_deref() {
        validate_system_response_metadata::<D::Error>(value)?;
    }
    Ok(value)
}

fn deserialize_bounded_safe_metadata_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = deserialize_bounded_string_map(deserializer)?;
    for (key, value) in &values {
        validate_system_response_metadata::<D::Error>(key)?;
        validate_system_response_metadata::<D::Error>(value)?;
    }
    Ok(values)
}

#[cfg(feature = "operator-ops")]
fn deserialize_namespace_key_shares<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    struct NamespaceKeySharesVisitor;

    impl<'de> Visitor<'de> for NamespaceKeySharesVisitor {
        type Value = Vec<SecretString>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_NAMESPACE_KEY_SHARES} namespace key shares"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut shares = Vec::new();
            while shares.len() < MAX_NAMESPACE_KEY_SHARES {
                let Some(share) = sequence.next_element::<String>()? else {
                    return Ok(shares);
                };
                if share.is_empty()
                    || share.len() > MAX_NAMESPACE_KEY_SHARE_BYTES
                    || share.as_bytes().iter().any(u8::is_ascii_control)
                {
                    return Err(A::Error::custom(
                        "namespace key share is empty, oversized, or contains control characters",
                    ));
                }
                shares.push(SecretString::from(share));
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    "namespace key share list exceeds item limit",
                ));
            }
            Ok(shares)
        }
    }

    deserializer.deserialize_seq(NamespaceKeySharesVisitor)
}

fn deserialize_bounded_plugin_detail_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<PluginDetail>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(
        BoundedPluginDetailListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

#[derive(Deserialize)]
struct BoundedStringList(#[serde(deserialize_with = "deserialize_bounded_string_vec")] Vec<String>);

#[derive(Deserialize)]
struct MountInfoMap(
    #[serde(deserialize_with = "deserialize_bounded_mount_info_map")] BTreeMap<String, MountInfo>,
);

#[derive(Deserialize)]
struct AuditDeviceMap(
    #[serde(deserialize_with = "deserialize_bounded_audit_device_map")]
    BTreeMap<String, AuditDevice>,
);

fn deserialize_bounded_logger_level_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string_map(deserializer)
}

fn deserialize_bounded_u64_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, u64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedU64MapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

fn deserialize_bounded_version_history_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, VersionHistoryEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedVersionHistoryMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

fn deserialize_bounded_version_history_details_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, VersionHistoryEntryDetails>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedVersionHistoryDetailsMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

fn deserialize_bounded_namespace_info_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, NamespaceInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedNamespaceInfoMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

fn deserialize_bounded_rate_limit_quota_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, RateLimitQuotaInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedRateLimitQuotaMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

fn deserialize_bounded_raft_server_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<RaftServer>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_seq(BoundedRaftServerListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

fn deserialize_bounded_ha_node_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<HaNode>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_seq(BoundedHaNodeListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

fn deserialize_bounded_locked_namespace_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<LockedUsersNamespace>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(
        BoundedLockedNamespaceListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

fn deserialize_bounded_locked_mount_accessor_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<LockedUsersMountAccessor>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(
        BoundedLockedMountAccessorListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

fn deserialize_bounded_mount_info_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, MountInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_map(BoundedMountInfoMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct BoundedMountInfoMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedMountInfoMapVisitor<MAX> {
    type Value = BTreeMap<String, MountInfo>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} mount entries")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, MountInfo>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao mount map exceeds item limit"));
        }
        Ok(values)
    }
}

fn deserialize_bounded_audit_device_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, AuditDevice>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_map(BoundedAuditDeviceMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct BoundedAuditDeviceMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedAuditDeviceMapVisitor<MAX> {
    type Value = BTreeMap<String, AuditDevice>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} audit devices")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, AuditDevice>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao audit device map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

fn deserialize_bounded_audited_header_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, AuditedRequestHeaderConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedAuditedHeaderMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

struct BoundedAuditedHeaderMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedAuditedHeaderMapVisitor<MAX> {
    type Value = BTreeMap<String, AuditedRequestHeaderConfig>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} audited request headers")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, AuditedRequestHeaderConfig>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao audited request header map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

fn deserialize_bounded_ui_mount_summary_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, UiMountSummary>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedUiMountSummaryMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

struct BoundedUiMountSummaryMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedUiMountSummaryMapVisitor<MAX> {
    type Value = BTreeMap<String, UiMountSummary>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} UI mount summaries")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, UiMountSummary>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao UI mount summary map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedNamespaceInfoMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedNamespaceInfoMapVisitor<MAX> {
    type Value = BTreeMap<String, NamespaceInfo>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} namespace entries")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, NamespaceInfo>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao namespace map exceeds item limit"));
        }
        Ok(values)
    }
}

struct BoundedRateLimitQuotaMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedRateLimitQuotaMapVisitor<MAX> {
    type Value = BTreeMap<String, RateLimitQuotaInfo>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} rate limit quota entries")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, RateLimitQuotaInfo>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao rate limit quota map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedU64MapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedU64MapVisitor<MAX> {
    type Value = BTreeMap<String, u64>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} integer values")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, u64>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao integer map exceeds item limit"));
        }
        Ok(values)
    }
}

struct BoundedRaftServerListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedRaftServerListVisitor<MAX> {
    type Value = Vec<RaftServer>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a list of at most {MAX} Raft servers")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<RaftServer>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao Raft server list exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedHaNodeListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedHaNodeListVisitor<MAX> {
    type Value = Vec<HaNode>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a list of at most {MAX} HA nodes")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<HaNode>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao HA node list exceeds item limit"));
        }
        Ok(values)
    }
}

struct BoundedLockedNamespaceListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedLockedNamespaceListVisitor<MAX> {
    type Value = Vec<LockedUsersNamespace>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a list of at most {MAX} locked-user namespaces")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<LockedUsersNamespace>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao locked-user namespace list exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedLockedMountAccessorListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedLockedMountAccessorListVisitor<MAX> {
    type Value = Vec<LockedUsersMountAccessor>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a list of at most {MAX} locked-user mount accessors"
        )
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<LockedUsersMountAccessor>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao locked-user mount accessor list exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedVersionHistoryMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedVersionHistoryMapVisitor<MAX> {
    type Value = BTreeMap<String, VersionHistoryEntry>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} version history entries")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, VersionHistoryEntry>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao version history map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedVersionHistoryDetailsMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedVersionHistoryDetailsMapVisitor<MAX> {
    type Value = BTreeMap<String, VersionHistoryEntryDetails>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a map of at most {MAX} detailed version history entries"
        )
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, VersionHistoryEntryDetails>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao detailed version history map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedPluginDetailListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedPluginDetailListVisitor<MAX> {
    type Value = Vec<PluginDetail>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a list of at most {MAX} plugin details")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<PluginDetail>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao plugin detail list exceeds item limit",
            ));
        }
        Ok(values)
    }
}

fn deserialize_optional_string_or_u64<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(OptionalStringOrU64Visitor)
}

struct OptionalStringOrU64Visitor;

impl<'de> Visitor<'de> for OptionalStringOrU64Visitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("null, a string integer, or an integer")
    }

    fn visit_none<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_optional_string_or_u64(deserializer)
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Some(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E> {
        Ok(Some(value))
    }

    fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
        Ok(Some(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};
    #[cfg(feature = "monitor-stream")]
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
    };

    #[cfg(feature = "monitor-stream")]
    use bytes::Bytes;
    #[cfg(feature = "monitor-stream")]
    use futures_core::Stream;

    use super::{
        AuditEnableRequest, AuditedRequestHeaders, AuthEnableRequest, Capabilities, Capability,
        CorsConfig, CorsConfigRequest, GeneratedPassword, HaStatus, LeaseDuration, LockedUsers,
        LoggerLevel, MAX_SYSTEM_RESPONSE_METADATA_BYTES, MfaValidateAuth, MfaValidateRequest,
        MountEnableRequest, NamespaceList, NamespaceRequest, PolicyList, PolicyPatchRequest,
        PolicyWriteRequest, RaftAutopilotConfig, RaftConfiguration, RaftJoinRequest,
        RaftPeerRequest, RateLimitQuotaConfig, RateLimitQuotaList, RateLimitQuotaRequest,
        RemountRequest, ResultantAcl, SysHashAlgorithm, SysHashRequest, SysRandomRequest,
        SysRandomResponse, SysRandomSource, UiMounts, UiNamespaces, VersionHistory, WorkflowData,
        WorkflowInfo, WorkflowList, WorkflowWritePayload, WorkflowWriteRequest,
        audited_request_header_path, internal_ui_mount_path, locked_user_unlock_path,
        namespace_path, rate_limit_quota_path, remount_status_path, sys_hash_path, sys_path,
        sys_random_path, validate_capability_paths, validate_dev_bootstrap_options,
        validate_lease_id, validate_namespace_request, validate_raft_server_id,
        validate_raft_snapshot, validate_raft_snapshot_length, validate_rate_limit_quota_config,
        validate_rate_limit_quota_request, validate_sha256_hex, validate_wrapping_ttl,
    };
    #[cfg(feature = "operator-ops")]
    use super::{
        DecodeTokenRequest, DecodeTokenResponse, InFlightRequests, OperatorInitResponse,
        OperatorKeyShareUpdateResponse, OperatorKeySharesRequest, OperatorRecoveryKeyBackup,
        OperatorTokenGenerationStart, OperatorTokenGenerationStatus, SealableNamespaceCreation,
        SealableNamespacePayload, SealableNamespaceRequest, SealedNamespaceDeletion,
        validate_namespace_unseal_key,
    };
    #[cfg(feature = "monitor-stream")]
    use super::{MonitorLogFormat, MonitorOptions, MonitorStream};
    #[cfg(feature = "operator-ops")]
    use super::{
        PprofOptions, PprofProfile, RawCompression, RawEncoding, RawList, RawReadOptions,
        RawReadResponse, RawWriteRequest, pprof_path, raw_storage_path, validate_pprof_options,
    };

    #[test]
    fn sys_paths_are_validated() {
        assert_eq!(
            sys_path("sys/mounts", "secret", Some("tune"))
                .unwrap_or_else(|error| panic!("{error}")),
            "sys/mounts/secret/tune"
        );
        assert!(sys_path("sys/mounts", "../secret", None).is_err());
        assert_eq!(
            super::sys_logger_path("core").unwrap_or_else(|error| panic!("{error}")),
            "sys/loggers/core"
        );
        assert!(super::sys_logger_path("core/nested").is_err());
        assert_eq!(
            namespace_path("team/app").unwrap_or_else(|error| panic!("{error}")),
            "sys/namespaces/team/app"
        );
        assert!(namespace_path("team/app/").is_err());
        assert!(namespace_path("team app").is_err());
        assert!(namespace_path("team/sys").is_err());
        assert_eq!(
            rate_limit_quota_path("global-rate-limiter").unwrap_or_else(|error| panic!("{error}")),
            "sys/quotas/rate-limit/global-rate-limiter"
        );
        assert!(rate_limit_quota_path("quota/nested").is_err());
        assert_eq!(
            locked_user_unlock_path("auth_userpass_1234", "alice")
                .unwrap_or_else(|error| panic!("{error}")),
            "sys/locked-users/auth_userpass_1234/unlock/alice"
        );
        assert!(locked_user_unlock_path("auth/userpass", "alice").is_err());
        assert!(locked_user_unlock_path("auth_userpass_1234", "team/alice").is_err());
        assert_eq!(
            remount_status_path("ef3ba21c-8be8-4e5f-8d00-cb46a532c665")
                .unwrap_or_else(|error| panic!("{error}")),
            "sys/remount/status/ef3ba21c-8be8-4e5f-8d00-cb46a532c665"
        );
        assert!(remount_status_path("migration/nested").is_err());
        assert!(super::validate_query_string_value("service", "lease type").is_ok());
        assert!(super::validate_query_string_value("", "lease type").is_err());
        assert!(super::validate_query_string_value("service\n", "lease type").is_err());
    }

    #[test]
    fn workflow_paths_payloads_and_debug_are_secret_aware() {
        assert_eq!(
            super::workflow_path("sys/workflows/manage", "team/rotate")
                .unwrap_or_else(|error| panic!("{error}")),
            "sys/workflows/manage/team/rotate"
        );
        assert!(super::workflow_path("sys/workflows/manage", "../rotate").is_err());
        assert!(super::workflow_path("sys/workflows/manage", "").is_err());

        let request = WorkflowWriteRequest::new(SecretString::from("secret-workflow-hcl"))
            .and_then(|request| request.with_description("rotation workflow"))
            .and_then(|request| request.with_cas(7))
            .unwrap_or_else(|error| panic!("{error}"))
            .require_cas(true);
        #[cfg(feature = "unauthenticated-workflows")]
        let request = request.allow_unauthenticated(true);
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-workflow-hcl"));
        let payload = WorkflowWritePayload {
            workflow: request.workflow.expose_secret(),
            description: request.description.as_deref(),
            cas: request.cas,
            cas_required: request.cas_required,
            allow_unauthenticated: request.allow_unauthenticated,
        };
        let encoded = serde_json::to_value(payload)
            .unwrap_or_else(|error| panic!("workflow payload did not serialize: {error}"));
        assert_eq!(encoded["cas"], 7);
        assert_eq!(encoded["cas_required"], true);
        assert_eq!(
            encoded["allow_unauthenticated"],
            cfg!(feature = "unauthenticated-workflows")
        );
        assert!(WorkflowWriteRequest::new(SecretString::from("")).is_err());
        assert!(
            WorkflowWriteRequest::new(SecretString::from("flow {}"))
                .and_then(|request| request.with_cas(-2))
                .is_err()
        );
        assert!(super::validate_workflow_write_request(&request).is_err());
    }

    #[test]
    fn workflow_data_is_bounded_object_json_and_redacted() {
        let data = WorkflowData::from_json_bytes(sanitization::SecretVec::from_slice(
            br#"{"password":"fixture-workflow-secret"}"#,
        ))
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!data.is_empty());
        assert!(!format!("{data:?}").contains("fixture-workflow-secret"));
        data.with_json_bytes(|bytes| assert!(bytes.ends_with(b"}")));
        assert!(WorkflowData::from_json_bytes(sanitization::SecretVec::from_slice(b"[]")).is_err());
        assert!(
            WorkflowData::from_json_bytes(sanitization::SecretVec::from_slice(b"not-json"))
                .is_err()
        );

        let envelope = sanitization::SecretVec::from_slice(
            br#"{"data":{"token":"trace-token-value"},"warnings":null}"#,
        );
        let response =
            super::workflow_data_from_envelope(envelope).unwrap_or_else(|error| panic!("{error}"));
        assert!(!format!("{response:?}").contains("trace-token-value"));
        response.with_json_bytes(|bytes| assert!(bytes.windows(11).any(|v| v == b"trace-token")));
    }

    #[test]
    fn workflow_response_types_bound_and_redact_definitions() {
        let info: WorkflowInfo = serde_json::from_value(serde_json::json!({
            "path": "team/rotate",
            "workflow": "fixture-private-workflow-definition",
            "description": "rotation workflow",
            "version": 3,
            "cas_required": true,
            "allow_unauthenticated": false
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            info.workflow.expose_secret(),
            "fixture-private-workflow-definition"
        );
        assert!(!format!("{info:?}").contains("fixture-private-workflow-definition"));

        let list: WorkflowList = serde_json::from_value(serde_json::json!({
            "keys": ["team/rotate"],
            "key_info": {
                "team/rotate": {
                    "path": "team/rotate",
                    "workflow": "fixture-private-workflow-definition",
                    "description": "rotation workflow",
                    "version": 3
                }
            }
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(list.keys, ["team/rotate"]);
        assert!(!format!("{list:?}").contains("fixture-private-workflow-definition"));

        let duplicate = r#"{
            "keys": ["team/rotate"],
            "key_info": {
                "team/rotate": {
                    "path": "team/rotate",
                    "workflow": "first",
                    "version": 1
                },
                "team/rotate": {
                    "path": "team/rotate",
                    "workflow": "second",
                    "version": 2
                }
            }
        }"#;
        assert!(serde_json::from_str::<WorkflowList>(duplicate).is_err());
    }

    #[tokio::test]
    async fn wait_ready_retries_temporary_transport_errors_until_timeout() {
        let client =
            crate::Client::new("https://127.0.0.1:1").unwrap_or_else(|error| panic!("{error}"));
        let error = match client
            .sys()
            .wait_ready_with_delay(
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(1),
                |_| async {},
            )
            .await
        {
            Ok(_) => panic!("closed port should not become ready"),
            Err(error) => error,
        };

        assert!(matches!(error, crate::Error::InvalidTimeout(_)));
    }

    #[tokio::test]
    async fn wait_ready_runtime_neutral_sleep_is_capped_to_remaining_budget() {
        let client =
            crate::Client::new("https://127.0.0.1:1").unwrap_or_else(|error| panic!("{error}"));
        let start = std::time::Instant::now();
        let error = match client
            .sys()
            .wait_ready_with_delay(
                std::time::Duration::from_millis(10),
                std::time::Duration::from_secs(5),
                tokio::time::sleep,
            )
            .await
        {
            Ok(_) => panic!("closed port should not become ready"),
            Err(error) => error,
        };

        assert!(matches!(error, crate::Error::InvalidTimeout(_)));
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(feature = "tokio-helpers")]
    #[tokio::test]
    async fn tokio_readiness_helpers_enforce_overall_deadlines() {
        let client =
            crate::Client::new("https://127.0.0.1:1").unwrap_or_else(|error| panic!("{error}"));

        let start = std::time::Instant::now();
        let ready_error = match client
            .sys()
            .wait_ready(
                std::time::Duration::from_millis(10),
                std::time::Duration::from_secs(5),
            )
            .await
        {
            Ok(_) => panic!("closed port should not become ready"),
            Err(error) => error,
        };
        assert!(matches!(ready_error, crate::Error::InvalidTimeout(_)));
        assert!(start.elapsed() < std::time::Duration::from_secs(1));

        let start = std::time::Instant::now();
        let unseal_error = match client
            .sys()
            .wait_until_unsealed(
                std::time::Duration::from_millis(10),
                std::time::Duration::from_secs(5),
            )
            .await
        {
            Ok(_) => panic!("closed port should not become unsealed"),
            Err(error) => error,
        };
        assert!(matches!(unseal_error, crate::Error::InvalidTimeout(_)));
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[tokio::test]
    async fn wait_until_unsealed_retries_temporary_transport_errors_until_timeout() {
        let client =
            crate::Client::new("https://127.0.0.1:1").unwrap_or_else(|error| panic!("{error}"));
        let error = match client
            .sys()
            .wait_until_unsealed_with_delay(
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(1),
                |_| async {},
            )
            .await
        {
            Ok(_) => panic!("closed port should not become unsealed"),
            Err(error) => error,
        };

        assert!(matches!(error, crate::Error::InvalidTimeout(_)));
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn raw_storage_paths_and_secret_types_are_validated() {
        assert_eq!(
            raw_storage_path("logical/secret").unwrap_or_else(|error| panic!("{error}")),
            "sys/raw/logical/secret"
        );
        assert!(raw_storage_path("").is_err());
        assert!(raw_storage_path("../logical").is_err());

        let options = RawReadOptions::new()
            .with_compressed(false)
            .with_encoding(RawEncoding::Base64);
        assert!(!options.compressed);
        assert_eq!(options.encoding, RawEncoding::Base64);

        let request = RawWriteRequest::new(SecretString::from(["raw-", "value"].concat()))
            .with_compression(RawCompression::Gzip)
            .with_encoding(RawEncoding::Base64);
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("raw-value"));

        let response = RawReadResponse {
            value: SecretString::from(["raw-", "response"].concat()),
        };
        assert!(!format!("{response:?}").contains("raw-response"));

        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("key-{index}"));
        }
        let error = match serde_json::from_value::<RawList>(serde_json::json!({ "keys": keys })) {
            Ok(_) => panic!("oversized raw key list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn pprof_options_are_validated() {
        assert_eq!(pprof_path(PprofProfile::Heap), "sys/pprof/heap");
        assert_eq!(pprof_path(PprofProfile::Trace), "sys/pprof/trace");

        assert!(
            validate_pprof_options(PprofProfile::Profile, &PprofOptions::new().with_seconds(1))
                .is_ok()
        );
        assert!(
            validate_pprof_options(
                PprofProfile::Trace,
                &PprofOptions::new().with_seconds(super::MAX_SYS_PPROF_SECONDS),
            )
            .is_ok()
        );
        assert!(
            validate_pprof_options(PprofProfile::Trace, &PprofOptions::new().with_seconds(0))
                .is_err()
        );
        assert!(
            validate_pprof_options(PprofProfile::Heap, &PprofOptions::new().with_seconds(1))
                .is_err()
        );
        assert!(
            validate_pprof_options(PprofProfile::Goroutine, &PprofOptions::new().with_debug(2))
                .is_ok()
        );
        assert!(
            validate_pprof_options(PprofProfile::Goroutine, &PprofOptions::new().with_debug(3))
                .is_err()
        );
        assert!(
            validate_pprof_options(PprofProfile::Heap, &PprofOptions::new().with_debug(1)).is_err()
        );
    }

    #[test]
    fn capability_paths_are_validated() {
        let paths = validate_capability_paths(["secret/data/app", "/sys/policy/default"])
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(paths, ["secret/data/app", "sys/policy/default"]);
        assert!(validate_capability_paths([""]).is_err());
        assert!(validate_capability_paths(["../secret"]).is_err());
    }

    #[test]
    fn capability_views_cover_common_access_checks() {
        let capabilities = serde_json::from_value::<Capabilities>(serde_json::json!({
            "capabilities": ["root"],
            "secret/data/app": ["read", "list", "future-capability"],
            "secret/data/blocked": ["deny"]
        }))
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(capabilities.single_path().can_delete());
        assert!(capabilities.is_permitted());
        assert!(capabilities.can_read_path("/secret/data/app"));
        assert!(capabilities.can_list_path("secret/data/app"));
        assert!(!capabilities.can_delete_path("secret/data/app"));
        assert!(!capabilities.can_read_path("secret/data/blocked"));
        assert!(
            capabilities
                .for_path("secret/data/app")
                .unwrap_or_else(|| panic!("missing capability view"))
                .is_permitted()
        );
        assert!(
            !capabilities
                .for_path("secret/data/blocked")
                .unwrap_or_else(|| panic!("missing capability view"))
                .is_permitted()
        );
        assert!(
            capabilities
                .for_path("secret/data/app")
                .unwrap_or_else(|| panic!("missing capability view"))
                .contains(Capability::Unknown("future-capability".to_owned()))
        );
        let paths = capabilities
            .paths()
            .map(|(path, view)| (path.to_owned(), view.raw().len()))
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                ("secret/data/app".to_owned(), 3),
                ("secret/data/blocked".to_owned(), 1)
            ]
        );
    }

    #[test]
    fn password_and_resultant_acl_responses_are_bounded_and_redacted() {
        let generated = GeneratedPassword {
            password: SecretString::from("generated-password"),
        };
        let debug = format!("{generated:?}");
        assert!(!debug.contains("generated-password"));

        let acl = serde_json::from_value::<ResultantAcl>(serde_json::json!({
            "root": false,
            "exact_paths": {
                "secret/data/app": { "capabilities": ["read", "update"] }
            },
            "glob_paths": {
                "secret/metadata/app/": { "capabilities": ["list"] }
            }
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(acl.exact_paths["secret/data/app"].capabilities().can_read());
        assert!(
            acl.glob_paths["secret/metadata/app/"]
                .capabilities()
                .can_list()
        );

        let mut overflow = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            overflow.insert(
                format!("secret/data/{index}"),
                serde_json::json!({ "capabilities": ["read"] }),
            );
        }
        let error = match serde_json::from_value::<ResultantAcl>(serde_json::json!({
            "exact_paths": overflow
        })) {
            Ok(_) => panic!("oversized resultant ACL unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("OpenBao resultant ACL map exceeds item limit")
        );
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn operator_token_and_in_flight_responses_redact_secrets_and_bound_maps() {
        let status = OperatorTokenGenerationStatus {
            started: true,
            nonce: Some(["nonce-", "unit"].concat()),
            progress: Some(1),
            required: Some(1),
            encoded_token: Some(SecretString::from("encoded-root-token")),
            pgp_fingerprint: None,
            otp_length: Some(24),
            complete: true,
        };
        let debug = format!("{status:?}");
        assert!(!debug.contains("encoded-root-token"));

        let start = OperatorTokenGenerationStart {
            status,
            otp: Some(SecretString::from("otp-secret")),
        };
        let debug = format!("{start:?}");
        assert!(!debug.contains("otp-secret"));

        let decode_request = DecodeTokenRequest::new(
            SecretString::from("encoded-root-token"),
            SecretString::from("otp-secret"),
        );
        let debug = format!("{decode_request:?}");
        assert!(!debug.contains("encoded-root-token"));
        assert!(!debug.contains("otp-secret"));

        let malformed_decode_request = DecodeTokenRequest::new(
            SecretString::from("encoded%token"),
            SecretString::from("otp-secret"),
        );
        assert!(super::decode_operator_token(&malformed_decode_request).is_err());

        let decoded = DecodeTokenResponse {
            token: SecretString::from("root-token"),
        };
        assert!(!format!("{decoded:?}").contains("root-token"));

        let backup = serde_json::from_value::<OperatorRecoveryKeyBackup>(serde_json::json!({
            "nonce": "backup-nonce",
            "keys": { "fingerprint": "encrypted-share" }
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            backup.keys["fingerprint"].expose_secret(),
            "encrypted-share"
        );
        assert!(!format!("{backup:?}").contains("encrypted-share"));

        let requests = serde_json::from_value::<InFlightRequests>(serde_json::json!({
            "request-id": {
                "start_time": "2026-06-04T12:00:00Z",
                "client_remote_address": "127.0.0.1:9940",
                "request_path": "/v1/secret/data/app",
                "request_method": "GET",
                "client_token_accessor": "token-accessor"
            }
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        let request = &requests.0["request-id"];
        assert_eq!(
            request.accessor.as_ref().map(SecretString::expose_secret),
            Some("token-accessor")
        );
        assert!(!format!("{request:?}").contains("token-accessor"));

        let mut overflow = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            overflow.insert(
                format!("request-{index}"),
                serde_json::json!({ "request_method": "GET" }),
            );
        }
        let error =
            match serde_json::from_value::<InFlightRequests>(serde_json::Value::Object(overflow)) {
                Ok(_) => panic!("oversized in-flight request map unexpectedly decoded"),
                Err(error) => error,
            };
        assert!(
            error
                .to_string()
                .contains("OpenBao in-flight request map exceeds item limit")
        );
    }

    #[test]
    fn wrapping_ttl_is_validated() {
        assert!(validate_wrapping_ttl("30s").is_ok());
        assert!(validate_wrapping_ttl("5m").is_ok());
        assert!(validate_wrapping_ttl("1h").is_ok());
        assert!(validate_wrapping_ttl("1h30m").is_ok());
        assert!(validate_wrapping_ttl("").is_err());
        assert!(validate_wrapping_ttl("0s").is_err());
        assert!(validate_wrapping_ttl("1h1h").is_err());
        assert!(validate_wrapping_ttl("1m1h").is_err());
        assert!(validate_wrapping_ttl("999999999999h").is_err());
        assert!(validate_wrapping_ttl("-1h").is_err());
        assert!(validate_wrapping_ttl("forever").is_err());
    }

    #[test]
    fn dev_bootstrap_options_are_validated() {
        assert!(validate_dev_bootstrap_options(1, 1).is_ok());
        assert!(validate_dev_bootstrap_options(3, 2).is_ok());
        assert!(validate_dev_bootstrap_options(0, 0).is_err());
        assert!(validate_dev_bootstrap_options(1, 0).is_err());
        assert!(validate_dev_bootstrap_options(1, 2).is_err());
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn operator_key_share_options_are_validated() {
        assert!(OperatorKeySharesRequest::new(1, 1).is_ok());
        assert!(OperatorKeySharesRequest::new(0, 1).is_err());
        assert!(OperatorKeySharesRequest::new(1, 0).is_err());
        assert!(OperatorKeySharesRequest::new(1, 2).is_err());
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn operator_secret_debug_is_redacted() {
        let init = OperatorInitResponse {
            keys: vec![SecretString::from(["unseal-", "share"].concat())],
            keys_base64: vec![SecretString::from(["base64-", "share"].concat())],
            root_token: SecretString::from(["root-", "token"].concat()),
            recovery_keys: vec![SecretString::from(["recovery-", "share"].concat())],
            recovery_keys_base64: Vec::new(),
        };
        let init_debug = format!("{init:?}");
        assert!(!init_debug.contains(&["root-", "token"].concat()));
        assert!(!init_debug.contains(&["unseal-", "share"].concat()));
        assert!(init_debug.contains("keys_count"));

        let update = OperatorKeyShareUpdateResponse {
            complete: true,
            keys: vec![SecretString::from(["new-", "share"].concat())],
            keys_base64: Vec::new(),
            nonce: Some("nonce".to_owned()),
            pgp_fingerprints: Vec::new(),
            backup: false,
            verification_required: false,
            verification_nonce: None,
            progress: None,
            required: None,
        };
        let update_debug = format!("{update:?}");
        assert!(!update_debug.contains(&["new-", "share"].concat()));
        assert!(update_debug.contains("keys_count"));
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn root_generation_responses_decode_legacy_and_enveloped_shapes() {
        let legacy: OperatorTokenGenerationStatus = serde_json::from_value(serde_json::json!({
            "started": true,
            "nonce": "legacy-nonce",
            "encoded_token": "legacy-encoded-token"
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(legacy.nonce.as_deref(), Some("legacy-nonce"));
        assert!(!format!("{legacy:?}").contains("legacy-encoded-token"));

        let current: super::ResponseEnvelope<OperatorTokenGenerationStart> =
            serde_json::from_value(serde_json::json!({
                "data": {
                    "started": true,
                    "nonce": "current-nonce",
                    "otp": "current-root-otp"
                }
            }))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(current.data.status.nonce.as_deref(), Some("current-nonce"));
        assert!(!format!("{current:?}").contains("current-root-otp"));
    }

    #[test]
    fn lease_ids_are_validated_for_json_body_use() {
        assert!(validate_lease_id(&SecretString::from("database/creds/ro/abc")).is_ok());
        assert!(validate_lease_id(&SecretString::from("")).is_err());
        assert!(validate_lease_id(&SecretString::from("database/creds/ro\nabc")).is_err());
        assert!(validate_lease_id(&SecretString::from("x".repeat(513))).is_err());
    }

    #[test]
    fn lease_lookup_topology_metadata_is_bounded_and_log_safe() {
        let lease: super::LeaseLookupDetails = serde_json::from_value(serde_json::json!({
            "id": "database/creds/readonly/lease-id",
            "issue_time": "2026-07-17T10:00:00Z",
            "expire_time": "2026-07-17T11:00:00Z",
            "namespace_path": "team/payments/",
            "path": "database/creds/readonly",
            "revoke_error": "backend unavailable"
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(lease.namespace_path.as_deref(), Some("team/payments/"));
        let debug = format!("{lease:?}");
        assert!(!debug.contains("lease-id"));
        assert!(!debug.contains("team/payments"));
        assert!(!debug.contains("database/creds"));
        assert!(!debug.contains("backend unavailable"));

        for unsafe_value in ["database/creds/readonly\nforged", "\u{0000}"] {
            assert!(
                serde_json::from_value::<super::LeaseLookupDetails>(serde_json::json!({
                    "id": "lease-id",
                    "issue_time": "2026-07-17T10:00:00Z",
                    "expire_time": "2026-07-17T11:00:00Z",
                    "path": unsafe_value
                }))
                .is_err()
            );
        }
        assert!(
            serde_json::from_value::<super::LeaseLookupDetails>(serde_json::json!({
                "id": "lease-id",
                "issue_time": "2026-07-17T10:00:00Z",
                "expire_time": "2026-07-17T11:00:00Z",
                "path": "x".repeat(4097)
            }))
            .is_err()
        );
    }

    #[test]
    fn system_version_and_seal_metadata_is_bounded_and_log_safe() {
        for field in [
            "build_date",
            "commit_date",
            "previous_version",
            "timestamp_installed",
        ] {
            let mut value = serde_json::json!({
                "build_date": null,
                "commit_date": null,
                "previous_version": null,
                "timestamp_installed": null
            });
            value[field] = serde_json::json!("forged\nmetadata");
            assert!(serde_json::from_value::<super::VersionHistoryEntryDetails>(value).is_err());
        }

        for field in [
            "type",
            "version",
            "build_date",
            "commit_date",
            "recovery_seal_type",
        ] {
            let mut value = serde_json::json!({
                "type": "shamir",
                "initialized": true,
                "sealed": false,
                "version": "2.6.0"
            });
            value[field] = serde_json::json!("forged\rmetadata");
            assert!(serde_json::from_value::<super::SealStatusDetails>(value).is_err());
        }

        for field in [
            "version",
            "cluster_name",
            "cluster_id",
            "build_date",
            "commit_date",
        ] {
            let mut value = serde_json::json!({
                "sealed": false,
                "version": "2.6.0"
            });
            value[field] = serde_json::json!("\u{001b}[31mforged");
            assert!(serde_json::from_value::<super::UnsealStatusDetails>(value).is_err());
        }

        let oversized = "x".repeat(MAX_SYSTEM_RESPONSE_METADATA_BYTES + 1);
        assert!(
            serde_json::from_value::<super::SealStatusDetails>(serde_json::json!({
                "type": "shamir",
                "initialized": true,
                "sealed": false,
                "version": "2.6.0",
                "commit_date": oversized
            }))
            .is_err()
        );
    }

    #[test]
    fn lease_duration_rejects_untyped_json() {
        assert_eq!(
            serde_json::from_str::<LeaseDuration>("3600").unwrap_or_else(|error| panic!("{error}")),
            LeaseDuration::Seconds(3600)
        );
        assert_eq!(
            serde_json::from_str::<LeaseDuration>(r#""30m""#)
                .unwrap_or_else(|error| panic!("{error}")),
            LeaseDuration::Duration("30m".to_owned())
        );
        assert!(serde_json::from_str::<LeaseDuration>("-1").is_err());
        assert!(serde_json::from_str::<LeaseDuration>(r#""never""#).is_err());
        assert!(serde_json::from_str::<LeaseDuration>(r#"{"ttl":3600}"#).is_err());
    }

    #[test]
    fn policy_list_is_bounded() {
        let mut policies = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            policies.push(format!("policy-{index}"));
        }
        let value = serde_json::json!({ "policies": policies });
        let error = match serde_json::from_value::<PolicyList>(value) {
            Ok(_) => panic!("oversized policy list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn logger_level_values_are_stable() {
        assert_eq!(LoggerLevel::Trace.as_str(), "trace");
        assert_eq!(LoggerLevel::Debug.as_str(), "debug");
        assert_eq!(LoggerLevel::Info.as_str(), "info");
        assert_eq!(LoggerLevel::Warn.as_str(), "warn");
        assert_eq!(LoggerLevel::Error.as_str(), "error");
    }

    #[test]
    fn system_tool_paths_validate_and_redact_secrets() {
        assert_eq!(SysRandomSource::Platform.as_path_segment(), "platform");
        assert_eq!(SysRandomSource::All.as_path_segment(), "all");
        assert_eq!(
            sys_random_path(None, Some(32)),
            "sys/tools/random/32".to_owned()
        );
        assert_eq!(
            sys_random_path(Some(SysRandomSource::All), Some(64)),
            "sys/tools/random/all/64".to_owned()
        );
        assert_eq!(
            sys_hash_path(SysHashAlgorithm::Sha2_256),
            "sys/tools/hash/sha2-256".to_owned()
        );
        assert!(SysRandomRequest::new().with_bytes(1).validate().is_ok());
        assert!(SysRandomRequest::new().with_bytes(0).validate().is_err());
        assert!(
            SysRandomRequest::new()
                .with_bytes(super::MAX_SYS_RANDOM_BYTES + 1)
                .validate()
                .is_err()
        );

        let request = SysHashRequest::from_base64_input(SecretString::from(
            ["base64-", "secret-input"].concat(),
        ));
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-input"));

        let response = SysRandomResponse {
            random_bytes: SecretString::from(["random-", "secret"].concat()),
        };
        let debug = format!("{response:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("random-secret"));

        #[cfg(feature = "transit-bytes")]
        {
            let valid = SysRandomResponse {
                random_bytes: SecretString::from("AA=="),
            };
            let bytes = valid
                .random_bytes()
                .unwrap_or_else(|error| panic!("{error}"));
            bytes.with_secret(|decoded| assert_eq!(decoded, &[0]));

            let malformed = SysRandomResponse {
                random_bytes: SecretString::from("AA%"),
            };
            assert!(malformed.random_bytes().is_err());
        }
    }

    #[test]
    fn logger_and_version_history_maps_are_bounded() {
        let mut loggers = serde_json::Map::new();
        let mut key_info = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            loggers.insert(format!("logger-{index}"), serde_json::json!("info"));
            key_info.insert(
                format!("2.5.{index}"),
                serde_json::json!({
                    "build_date": null,
                    "previous_version": null,
                    "timestamp_installed": "2026-05-27T00:00:00Z"
                }),
            );
        }

        let error =
            match serde_json::from_value::<super::LoggerLevels>(serde_json::Value::Object(loggers))
            {
                Ok(_) => panic!("oversized logger map unexpectedly decoded"),
                Err(error) => error,
            };
        assert!(error.to_string().contains("exceeds item limit"));

        let error = match serde_json::from_value::<VersionHistory>(serde_json::json!({
            "keys": ["2.5.4"],
            "key_info": key_info
        })) {
            Ok(_) => panic!("oversized version history map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn namespace_requests_and_maps_are_bounded() {
        let mut request = NamespaceRequest::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            request
                .custom_metadata
                .insert(format!("key-{index}"), "value".to_owned());
        }
        assert!(validate_namespace_request(&request).is_err());

        let request = NamespaceRequest::new().with_metadata("bad", "line\nbreak");
        assert!(validate_namespace_request(&request).is_err());

        let mut key_info = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            key_info.insert(
                format!("ns-{index}/"),
                serde_json::json!({
                    "id": format!("id-{index}"),
                    "path": format!("ns-{index}/"),
                    "custom_metadata": {}
                }),
            );
        }
        let error = match serde_json::from_value::<NamespaceList>(serde_json::json!({
            "keys": ["ns-0/"],
            "key_info": key_info
        })) {
            Ok(_) => panic!("oversized namespace map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn sealable_namespace_requests_validate_and_redact_operator_material() {
        assert!(SealableNamespaceRequest::new(0, 0).is_err());
        assert!(SealableNamespaceRequest::new(2, 1).is_err());
        assert!(SealableNamespaceRequest::new(2, 3).is_err());

        let request = SealableNamespaceRequest::new(3, 2)
            .and_then(|request| {
                request.with_pgp_keys(["cGdwLWtleS0x", "cGdwLWtleS0y", "cGdwLWtleS0z"])
            })
            .and_then(|request| request.with_metadata("owner", "security"))
            .unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{request:?}");
        assert!(debug.contains("pgp_keys_count: 3"));
        assert!(!debug.contains("cGdwLWtleS0x"));
        assert!(!debug.contains("security"));

        let payload = SealableNamespacePayload {
            custom_metadata: &request.custom_metadata,
            seal: request.seal_document(),
            pgp_keys: Some(request.pgp_keys.as_slice()),
        };
        let encoded = serde_json::to_value(payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            encoded["seal"],
            "seal \"shamir\" { shares = 3 threshold = 2 }"
        );
        assert_eq!(encoded["pgp_keys"].as_array().map(Vec::len), Some(3));

        assert!(
            SealableNamespaceRequest::new(2, 2)
                .and_then(|request| request.with_pgp_keys(["cGdwLWtleQ=="]))
                .is_err()
        );
        assert!(
            SealableNamespaceRequest::new(1, 1)
                .and_then(|request| request.with_pgp_keys(["not-base64"]))
                .is_err()
        );
        assert!(
            SealableNamespaceRequest::new(1, 1)
                .and_then(|request| request.with_metadata("owner", "security\nforged"))
                .is_err()
        );

        assert!(validate_namespace_unseal_key(&SecretString::from("")).is_err());
        assert!(validate_namespace_unseal_key(&SecretString::from("share\nvalue")).is_err());
        assert!(
            validate_namespace_unseal_key(&SecretString::from(
                "x".repeat(super::MAX_NAMESPACE_UNSEAL_KEY_BYTES + 1)
            ))
            .is_err()
        );
        assert!(!SealedNamespaceDeletion::confirm().force);
        assert!(SealedNamespaceDeletion::confirm_recursive().force);
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn sealable_namespace_responses_bound_and_redact_key_shares() {
        let creation: SealableNamespaceCreation = serde_json::from_value(serde_json::json!({
            "uuid": "namespace-uuid",
            "id": "namespace-id",
            "path": "team/app/",
            "tainted": false,
            "locked": false,
            "custom_metadata": {"owner": "security"},
            "key_shares": ["unseal-share-one", "unseal-share-two"],
            "key_threshold": 2
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(creation.key_shares[0].expose_secret(), "unseal-share-one");
        let debug = format!("{creation:?}");
        assert!(debug.contains("key_shares_count: 2"));
        assert!(!debug.contains("unseal-share-one"));
        assert!(!debug.contains("security"));

        let shares = (0..=super::MAX_NAMESPACE_KEY_SHARES)
            .map(|index| format!("share-{index}"))
            .collect::<Vec<_>>();
        let error = serde_json::from_value::<SealableNamespaceCreation>(serde_json::json!({
            "key_shares": shares,
            "key_threshold": 2
        }))
        .err()
        .unwrap_or_else(|| panic!("oversized namespace key shares unexpectedly decoded"));
        assert!(error.to_string().contains("exceeds item limit"));

        assert!(
            serde_json::from_value::<super::NamespaceSealStatus>(serde_json::json!({
                "type": "shamir\nforged",
                "initialized": true,
                "sealed": true,
                "n": 3,
                "t": 2,
                "progress": 0,
                "nonce": ""
            }))
            .is_err()
        );
    }

    #[test]
    fn rate_limit_quota_requests_and_maps_are_bounded() {
        let config = RateLimitQuotaConfig::new()
            .with_exempt_path("sys/health")
            .with_exempt_path("sys/seal-status");
        assert!(validate_rate_limit_quota_config(&config).is_ok());
        assert!(
            RateLimitQuotaConfig::new()
                .try_with_exempt_path("sys/health")
                .is_ok()
        );
        assert!(
            RateLimitQuotaConfig::new()
                .try_with_exempt_path("")
                .is_err()
        );

        let config = RateLimitQuotaConfig::new().with_exempt_path("");
        assert!(validate_rate_limit_quota_config(&config).is_err());

        let request = RateLimitQuotaRequest::new(100.0)
            .with_path("auth/approle/login")
            .with_interval("2m")
            .with_block_interval("5m")
            .with_role("web");
        assert!(validate_rate_limit_quota_request(&request).is_ok());
        assert!(
            RateLimitQuotaRequest::new(100.0)
                .try_with_path("auth/approle/login")
                .and_then(|request| request.try_with_interval("2m"))
                .and_then(|request| request.try_with_block_interval("5m"))
                .is_ok()
        );
        assert!(
            RateLimitQuotaRequest::new(100.0)
                .try_with_interval("forever")
                .is_err()
        );
        assert!(
            RateLimitQuotaRequest::new(100.0)
                .try_with_block_interval("forever")
                .is_err()
        );
        assert!(validate_rate_limit_quota_request(&RateLimitQuotaRequest::new(0.0)).is_err());
        assert!(
            validate_rate_limit_quota_request(&RateLimitQuotaRequest::new(f64::INFINITY)).is_err()
        );
        assert!(
            validate_rate_limit_quota_request(
                &RateLimitQuotaRequest::new(1.0).with_interval("forever")
            )
            .is_err()
        );

        let mut key_info = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            key_info.insert(
                format!("quota-{index}"),
                serde_json::json!({
                    "name": format!("quota-{index}"),
                    "path": "",
                    "rate": 100.0,
                    "interval": 1,
                    "block_interval": 0,
                    "type": "rate-limit"
                }),
            );
        }
        let error = match serde_json::from_value::<RateLimitQuotaList>(serde_json::json!({
            "keys": ["quota-0"],
            "key_info": key_info
        })) {
            Ok(_) => panic!("oversized rate limit quota map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn locked_user_lists_are_bounded() {
        let users: LockedUsers = serde_json::from_value(serde_json::json!({
            "by_namespace": [{
                "namespace_id": "root",
                "namespace_path": "",
                "counts": 2,
                "mount_accessors": [{
                    "mount_accessor": "auth_userpass_1234",
                    "counts": 2,
                    "alias_identifiers": ["alice", "bob"]
                }]
            }],
            "total": 2
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(users.total, 2);
        assert_eq!(
            users.by_namespace[0].mount_accessors[0].alias_identifiers[0],
            "alice"
        );

        let mut by_namespace = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            by_namespace.push(serde_json::json!({
                "namespace_id": format!("ns-{index}"),
                "namespace_path": format!("ns-{index}/"),
                "counts": 1,
                "mount_accessors": []
            }));
        }
        let error = match serde_json::from_value::<LockedUsers>(serde_json::json!({
            "by_namespace": by_namespace,
            "total": 1
        })) {
            Ok(_) => panic!("oversized locked-user namespace list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        let mut mount_accessors = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            mount_accessors.push(serde_json::json!({
                "mount_accessor": format!("auth_userpass_{index}"),
                "counts": 1,
                "alias_identifiers": []
            }));
        }
        let error = match serde_json::from_value::<LockedUsers>(serde_json::json!({
            "by_namespace": [{
                "namespace_id": "root",
                "namespace_path": "",
                "counts": 1,
                "mount_accessors": mount_accessors
            }],
            "total": 1
        })) {
            Ok(_) => panic!("oversized locked-user mount accessor list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn raft_requests_validate_and_redact_secrets() {
        let join = RaftJoinRequest::new("https://leader.example.com:8200")
            .with_leader_client_key(SecretString::from(["leader-", "client-key"].concat()))
            .with_auto_join(SecretString::from(["provider-", "metadata"].concat()));
        assert!(join.validate().is_ok());
        let debug = format!("{join:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("leader-client-key"));
        assert!(!debug.contains("provider-metadata"));

        let mut invalid_join = RaftJoinRequest::new("");
        assert!(invalid_join.validate().is_err());
        invalid_join.leader_api_addr = "http://leader.example.com:8200".to_owned();
        assert!(invalid_join.validate().is_err());
        invalid_join.leader_api_addr = "https://leader.example.com:8200".to_owned();
        invalid_join.auto_join_scheme = Some("http".to_owned());
        assert!(invalid_join.validate().is_err());
        invalid_join.leader_api_addr = "https://leader.example.com:8200".to_owned();
        invalid_join.auto_join_scheme = Some("ftp".to_owned());
        assert!(invalid_join.validate().is_err());

        let peer = RaftPeerRequest::new("raft-1")
            .with_dr_operation_token(SecretString::from(["dr-", "operation-token"].concat()));
        assert!(peer.validate().is_ok());
        let debug = format!("{peer:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("dr-operation-token"));
        assert!(validate_raft_server_id("").is_err());
        assert!(validate_raft_server_id("raft\n1").is_err());
        assert!(validate_raft_snapshot(b"snapshot").is_ok());
        assert!(validate_raft_snapshot(b"").is_err());
        assert!(validate_raft_snapshot_length(super::MAX_RAFT_SNAPSHOT_BYTES).is_ok());
        assert!(validate_raft_snapshot_length(super::MAX_RAFT_SNAPSHOT_BYTES + 1).is_err());
        assert_eq!(
            super::RaftPeerOperation::Remove.as_path_segment(),
            "remove-peer"
        );
        assert_eq!(
            super::RaftPeerOperation::Promote.as_path_segment(),
            "promote"
        );
        assert_eq!(super::RaftPeerOperation::Demote.as_path_segment(), "demote");
    }

    #[test]
    fn raft_configuration_and_autopilot_are_bounded_and_validated() {
        let config: RaftConfiguration = serde_json::from_value(serde_json::json!({
            "config": {
                "index": 24,
                "servers": [{
                    "address": "127.0.0.1:8201",
                    "leader": true,
                    "node_id": "raft1",
                    "protocol_version": "\u{3}",
                    "voter": true
                }]
            }
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.config.index, 24);
        assert!(config.config.servers[0].leader);

        let mut servers = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            servers.push(serde_json::json!({
                "address": format!("127.0.0.{index}:8201"),
                "leader": false,
                "node_id": format!("raft-{index}"),
                "protocol_version": "\u{3}",
                "voter": true
            }));
        }
        let error = match serde_json::from_value::<RaftConfiguration>(serde_json::json!({
            "config": { "index": 24, "servers": servers }
        })) {
            Ok(_) => panic!("oversized Raft server list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        let autopilot: RaftAutopilotConfig = serde_json::from_value(serde_json::json!({
            "last_contact_threshold": "10s",
            "max_trailing_logs": 1000,
            "min_quorum": "3",
            "server_stabilization_time": "10s"
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(autopilot.max_trailing_logs.as_deref(), Some("1000"));
        assert!(autopilot.validate().is_ok());
        assert!(
            RaftAutopilotConfig::new()
                .try_with_last_contact_threshold("10s")
                .and_then(|config| config.try_with_server_stabilization_time("30s"))
                .is_ok()
        );
        assert!(
            RaftAutopilotConfig::new()
                .try_with_last_contact_threshold("0s")
                .is_err()
        );
        assert!(
            RaftAutopilotConfig::new()
                .try_with_server_stabilization_time("0s")
                .is_err()
        );

        let invalid = RaftAutopilotConfig::new().with_last_contact_threshold("0s");
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn ha_status_and_remount_are_bounded_and_validated() {
        let status: HaStatus = serde_json::from_value(serde_json::json!({
            "Nodes": [{
                "hostname": "node1",
                "api_address": "https://10.0.0.2:8200",
                "cluster_address": "https://10.0.0.2:8201",
                "active_node": true,
                "last_echo": null,
                "version": "2.5.4"
            }]
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status.nodes.len(), 1);
        assert!(status.nodes[0].active_node);

        let mut nodes = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            nodes.push(serde_json::json!({
                "hostname": format!("node-{index}"),
                "api_address": format!("https://10.0.0.{index}:8200"),
                "cluster_address": format!("https://10.0.0.{index}:8201"),
                "active_node": false,
                "version": "2.5.4"
            }));
        }
        let error = match serde_json::from_value::<HaStatus>(serde_json::json!({
            "nodes": nodes
        })) {
            Ok(_) => panic!("oversized HA node list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        assert!(
            RemountRequest::new("secret", "new-secret")
                .validate()
                .is_ok()
        );
        assert!(
            RemountRequest::new("ns1/auth/approle", "ns2/auth/new-approle")
                .validate()
                .is_ok()
        );
        assert!(RemountRequest::new("", "new-secret").validate().is_err());
        assert!(RemountRequest::new("secret", "secret").validate().is_err());
        assert!(
            RemountRequest::new("secret?x=1", "new-secret")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn cors_config_lists_are_bounded_and_validated() {
        let config: CorsConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "allowed_origins": ["https://app.example.com"],
            "allowed_headers": ["X-Custom-Header"]
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(config.enabled);
        assert_eq!(config.allowed_origins, ["https://app.example.com"]);
        assert_eq!(config.allowed_headers, ["X-Custom-Header"]);

        let mut origins = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            origins.push(format!("https://app-{index}.example.com"));
        }
        let error = match serde_json::from_value::<CorsConfig>(serde_json::json!({
            "allowed_origins": origins
        })) {
            Ok(_) => panic!("oversized CORS origin list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        assert!(
            CorsConfigRequest::new(["https://app.example.com"])
                .with_allowed_header("X-Custom-Header")
                .validate()
                .is_ok()
        );
        assert!(CorsConfigRequest::new(["*"]).validate().is_err());
        assert!(CorsConfigRequest::new([""]).validate().is_err());
        assert!(
            CorsConfigRequest::new(["https://app.example.com\n"])
                .validate()
                .is_err()
        );
        assert!(CorsConfigRequest::new(["null"]).validate().is_err());
        assert!(
            CorsConfigRequest::new(["http://app.example.com"])
                .validate()
                .is_err()
        );
        assert!(
            CorsConfigRequest::new(["javascript:alert(1)"])
                .validate()
                .is_err()
        );
        assert!(
            CorsConfigRequest::new(["https://app.example.com/path"])
                .validate()
                .is_err()
        );
        assert!(
            CorsConfigRequest::new([" https://app.example.com"])
                .validate()
                .is_err()
        );
        assert!(
            CorsConfigRequest::new(["https://app.example.com"])
                .with_allowed_header("bad header")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn audited_request_headers_are_bounded_and_validated() {
        let headers: AuditedRequestHeaders = serde_json::from_value(serde_json::json!({
            "headers": {
                "X-Forwarded-For": { "hmac": true }
            }
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            headers
                .headers
                .get("X-Forwarded-For")
                .is_some_and(|config| config.hmac)
        );

        let mut entries = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            entries.insert(format!("X-Test-{index}"), serde_json::json!({"hmac": true}));
        }
        let error = match serde_json::from_value::<AuditedRequestHeaders>(serde_json::json!({
            "headers": entries
        })) {
            Ok(_) => panic!("oversized audited header map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        assert_eq!(
            audited_request_header_path("X-Forwarded-For")
                .unwrap_or_else(|error| panic!("{error}")),
            "sys/config/auditing/request-headers/x-forwarded-for"
        );
        assert!(audited_request_header_path("").is_err());
        assert!(audited_request_header_path("Bad Header").is_err());
        assert!(audited_request_header_path("bad/header").is_err());
    }

    #[test]
    fn ui_namespace_and_mount_lists_are_bounded_and_validated() {
        let namespaces: UiNamespaces = serde_json::from_value(serde_json::json!({
            "namespaces": ["team/", "team/app/"]
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(namespaces.namespaces, ["team/", "team/app/"]);

        let mounts: UiMounts = serde_json::from_value(serde_json::json!({
            "auth": {
                "github/": {
                    "description": "GitHub auth",
                    "type": "github"
                }
            },
            "secret": {
                "custom-secrets/": {
                    "description": "Custom secrets",
                    "type": "kv",
                    "options": { "version": "2" }
                }
            }
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            mounts
                .secret
                .get("custom-secrets/")
                .and_then(|mount| mount.options.as_ref())
                .and_then(|options| options.get("version"))
                .map(String::as_str),
            Some("2")
        );

        let mut secret = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            secret.insert(
                format!("secret-{index}/"),
                serde_json::json!({"type": "kv"}),
            );
        }
        let error = match serde_json::from_value::<UiMounts>(serde_json::json!({
            "secret": secret
        })) {
            Ok(_) => panic!("oversized UI mount map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        assert_eq!(
            internal_ui_mount_path("secret/path/to/item").unwrap_or_else(|error| panic!("{error}")),
            "sys/internal/ui/mounts/secret/path/to/item"
        );
        assert!(internal_ui_mount_path("").is_err());
        assert!(internal_ui_mount_path("../secret").is_err());
        assert!(internal_ui_mount_path("secret?x=1").is_err());
    }

    #[test]
    fn mount_config_header_lists_are_bounded() {
        let mut headers = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            headers.push(format!("x-header-{index}"));
        }
        let value = serde_json::json!({ "allowed_response_headers": headers });
        let error = match serde_json::from_value::<super::MountConfig>(value) {
            Ok(_) => panic!("oversized mount header list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn audit_device_options_are_bounded() {
        let mut options = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            options.insert(format!("option-{index}"), serde_json::json!("value"));
        }
        let value = serde_json::json!({
            "type": "file",
            "options": options,
        });
        let error = match serde_json::from_value::<super::AuditDevice>(value) {
            Ok(_) => panic!("oversized audit options unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn capabilities_path_map_is_bounded() {
        let mut value = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            value.insert(format!("secret/data/{index}"), serde_json::json!(["read"]));
        }
        let error =
            match serde_json::from_value::<super::Capabilities>(serde_json::Value::Object(value)) {
                Ok(_) => panic!("oversized capabilities map unexpectedly decoded"),
                Err(error) => error,
            };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn mfa_validate_request_and_auth_redact_secrets() {
        let request = MfaValidateRequest::new("mfa-request-id")
            .with_passcode("method-id", SecretString::from("123456"));
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("123456"));

        let payload = serde_json::to_value(&request).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(payload["mfa_request_id"], "mfa-request-id");
        assert_eq!(payload["mfa_payload"]["method-id"][0], "123456");

        let auth = serde_json::from_value::<MfaValidateAuth>(serde_json::json!({
            "client_token": "client-token",
            "accessor": "token-accessor",
            "policies": ["default"],
            "token_policies": ["default"],
            "metadata": { "username": "alice" },
            "lease_duration": 3600,
            "renewable": true
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(auth.client_token.expose_secret(), "client-token");
        let debug = format!("{auth:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("client-token"));
        assert!(!debug.contains("token-accessor"));
    }

    #[test]
    fn mount_and_audit_maps_are_bounded() {
        let mut mounts = serde_json::Map::new();
        let mut audits = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            mounts.insert(
                format!("secret-{index}/"),
                serde_json::json!({ "type": "kv", "config": {} }),
            );
            audits.insert(
                format!("file-{index}/"),
                serde_json::json!({ "type": "file", "options": {} }),
            );
        }

        let error = match serde_json::from_value::<super::MountInfoMap>(serde_json::Value::Object(
            mounts,
        )) {
            Ok(_) => panic!("oversized mount map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        let error = match serde_json::from_value::<super::AuditDeviceMap>(
            serde_json::Value::Object(audits),
        ) {
            Ok(_) => panic!("oversized audit device map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn plugin_sha256_is_validated() {
        assert!(
            validate_sha256_hex(
                "d130b9a0fbfddef9709d8ff92e5e6053ccd246b78632fc03b8548457026961e9",
                "sha256"
            )
            .is_ok()
        );
        assert!(validate_sha256_hex("", "sha256").is_err());
        assert!(validate_sha256_hex("not-a-sha256", "sha256").is_err());
        assert!(
            validate_sha256_hex(
                "g130b9a0fbfddef9709d8ff92e5e6053ccd246b78632fc03b8548457026961e9",
                "sha256"
            )
            .is_err()
        );
        assert!(
            validate_sha256_hex(
                "D130B9A0FBFDDEF9709D8FF92E5E6053CCD246B78632FC03B8548457026961E9",
                "sha256"
            )
            .is_err()
        );
    }

    #[test]
    fn request_constructors_fill_required_fields() {
        assert_eq!(MountEnableRequest::new("pki").backend_type, "pki");
        assert_eq!(MountEnableRequest::kv2().backend_type, "kv");
        assert_eq!(
            MountEnableRequest::kv2()
                .options
                .get("version")
                .map(String::as_str),
            Some("2")
        );
        let mount = MountEnableRequest::kv2()
            .with_default_lease_ttl("1h")
            .and_then(|request| request.with_max_lease_ttl("24h"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            mount.config.as_ref().and_then(|config| config.default_lease_ttl.as_ref()),
            Some(LeaseDuration::Duration(ttl)) if ttl == "1h"
        ));
        assert!(
            MountEnableRequest::kv2()
                .with_default_lease_ttl("never")
                .is_err()
        );
        assert_eq!(
            AuthEnableRequest::new("kubernetes")
                .with_description("cluster auth")
                .description
                .as_deref(),
            Some("cluster auth")
        );
        let auth = AuthEnableRequest::new("approle")
            .with_default_lease_ttl("30m")
            .and_then(|request| request.with_max_lease_ttl("2h"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            auth.config.as_ref().and_then(|config| config.max_lease_ttl.as_ref()),
            Some(LeaseDuration::Duration(ttl)) if ttl == "2h"
        ));
        assert_eq!(
            AuditEnableRequest::new("file")
                .with_description("audit log")
                .description
                .as_deref(),
            Some("audit log")
        );
        assert_eq!(
            PolicyWriteRequest::new("path \"secret/*\" { capabilities = [\"read\"] }").ttl,
            None
        );
        let conflicting_policy = PolicyWriteRequest {
            expiration: Some("2030-01-01T00:00:00Z".to_owned()),
            ttl: Some("1h".to_owned()),
            ..PolicyWriteRequest::new("path \"secret/*\" {}")
        };
        let error = conflicting_policy
            .validate()
            .err()
            .unwrap_or_else(|| panic!("conflicting policy lifetime unexpectedly accepted"));
        assert!(error.to_string().contains("mutually exclusive"));
        assert!(!error.to_string().contains("2030"));
        let strict_create = PolicyWriteRequest {
            cas: Some(-1),
            ..PolicyWriteRequest::new("path \"secret/*\" {}")
        };
        assert!(strict_create.validate().is_ok());

        assert!(PolicyPatchRequest::new().validate().is_err());
        let patch = PolicyPatchRequest::new().with_policy("path \"secret/*\" {}");
        assert!(patch.validate().is_ok());
        assert!(!format!("{patch:?}").contains("secret/*"));
        let conflicting_patch = PolicyPatchRequest {
            expiration: Some("2030-01-01T00:00:00Z".to_owned()),
            ttl: Some("1h".to_owned()),
            ..PolicyPatchRequest::new()
        };
        assert!(conflicting_patch.validate().is_err());
        for cas in [i64::MIN, -1, 0] {
            let invalid_cas = PolicyPatchRequest {
                cas: Some(cas),
                ..PolicyPatchRequest::new()
            };
            assert!(invalid_cas.validate().is_err());
        }
        let valid_cas = PolicyPatchRequest {
            cas: Some(1),
            ..PolicyPatchRequest::new()
        };
        assert!(valid_cas.validate().is_ok());
        assert!(
            !format!(
                "{:?}",
                PolicyWriteRequest::new("path \"secret/private\" {}")
            )
            .contains("secret/private")
        );
    }

    #[test]
    fn plugin_detail_list_is_bounded() {
        let mut detailed = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            detailed.push(serde_json::json!({
                "name": format!("plugin-{index}"),
                "type": "secret",
            }));
        }
        let value = serde_json::json!({ "detailed": detailed });
        let error = match serde_json::from_value::<super::PluginCatalog>(value) {
            Ok(_) => panic!("oversized plugin detail list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn plugin_reload_request_is_validated() {
        assert!(
            super::validate_plugin_reload_request(&super::PluginReloadRequest {
                plugin: Some("database-plugin".to_owned()),
                mounts: Vec::new(),
                scope: Some("global".to_owned()),
            })
            .is_ok()
        );
        assert!(
            super::validate_plugin_reload_request(&super::PluginReloadRequest {
                plugin: None,
                mounts: vec!["secret".to_owned()],
                scope: None,
            })
            .is_ok()
        );
        assert!(
            super::validate_plugin_reload_request(&super::PluginReloadRequest {
                plugin: None,
                mounts: Vec::new(),
                scope: None,
            })
            .is_err()
        );
        assert!(
            super::validate_plugin_reload_request(&super::PluginReloadRequest {
                plugin: Some("database-plugin".to_owned()),
                mounts: vec!["secret".to_owned()],
                scope: None,
            })
            .is_err()
        );
    }

    #[cfg(feature = "monitor-stream")]
    struct ReadyChunks(VecDeque<Bytes>);

    #[cfg(feature = "monitor-stream")]
    impl Stream for ReadyChunks {
        type Item = core::result::Result<Bytes, reqwest::Error>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front().map(Ok))
        }
    }

    #[cfg(feature = "monitor-stream")]
    struct AlwaysReadyEmptyChunks(Arc<AtomicUsize>);

    #[cfg(feature = "monitor-stream")]
    impl Stream for AlwaysReadyEmptyChunks {
        type Item = core::result::Result<Bytes, reqwest::Error>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok(Bytes::new())))
        }
    }

    #[cfg(feature = "monitor-stream")]
    struct DropProbeStream(Arc<AtomicBool>);

    #[cfg(feature = "monitor-stream")]
    impl Stream for DropProbeStream {
        type Item = core::result::Result<Bytes, reqwest::Error>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    #[cfg(feature = "monitor-stream")]
    impl Drop for DropProbeStream {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[cfg(feature = "monitor-stream")]
    fn test_monitor_stream(chunks: &[&[u8]], max_frame_bytes: usize) -> MonitorStream {
        MonitorStream {
            body: Box::pin(ReadyChunks(
                chunks
                    .iter()
                    .map(|chunk| Bytes::copy_from_slice(chunk))
                    .collect(),
            )),
            chunk: None,
            chunk_offset: 0,
            pending: sanitization::SecretVec::empty(),
            format: MonitorLogFormat::Json,
            max_frame_bytes,
            terminal: false,
        }
    }

    #[cfg(feature = "monitor-stream")]
    fn poll_monitor(stream: &mut MonitorStream) -> Option<crate::Result<super::MonitorFrame>> {
        let mut context = Context::from_waker(Waker::noop());
        match Pin::new(stream).poll_next(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("ready test stream unexpectedly pending"),
        }
    }

    #[cfg(feature = "monitor-stream")]
    #[test]
    fn monitor_stream_bounds_and_redacts_frames() {
        let mut stream =
            test_monitor_stream(&[b"{\"message\":\"caf\xc3", b"\xa9\"}\nnext\nlast"], 64);

        let first = poll_monitor(&mut stream)
            .and_then(core::result::Result::ok)
            .unwrap_or_else(|| panic!("missing first monitor frame"));
        assert_eq!(first.format(), MonitorLogFormat::Json);
        let first_text = first
            .with_str(str::to_owned)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_text, "{\"message\":\"café\"}");
        assert!(!format!("{first:?}").contains("caf"));

        let second = poll_monitor(&mut stream)
            .and_then(core::result::Result::ok)
            .unwrap_or_else(|| panic!("missing second monitor frame"));
        let second_text = second
            .with_str(str::to_owned)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_text, "next");
        let last = poll_monitor(&mut stream)
            .and_then(core::result::Result::ok)
            .unwrap_or_else(|| panic!("missing final monitor frame"));
        let last_text = last
            .with_str(str::to_owned)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(last_text, "last");
        assert!(poll_monitor(&mut stream).is_none());
    }

    #[cfg(feature = "monitor-stream")]
    #[test]
    fn monitor_stream_stops_after_oversized_frame() {
        let mut stream = test_monitor_stream(&[b"1234", b"5\nignored\n"], 4);
        let error = poll_monitor(&mut stream)
            .and_then(core::result::Result::err)
            .unwrap_or_else(|| panic!("oversized monitor frame unexpectedly succeeded"));
        assert!(error.to_string().contains("exceeds configured limit"));
        assert!(!error.to_string().contains("12345"));
        assert!(poll_monitor(&mut stream).is_none());
    }

    #[cfg(feature = "monitor-stream")]
    #[test]
    fn monitor_stream_rejects_oversized_transport_chunks() {
        let oversized = vec![b'x'; super::MAX_MONITOR_TRANSPORT_CHUNK_BYTES + 1];
        let mut stream = test_monitor_stream(&[&oversized], super::MAX_MONITOR_FRAME_BYTES);
        let error = poll_monitor(&mut stream)
            .and_then(core::result::Result::err)
            .unwrap_or_else(|| panic!("oversized monitor chunk unexpectedly succeeded"));
        assert!(
            error
                .to_string()
                .contains("transport chunk exceeds internal limit")
        );
        assert!(poll_monitor(&mut stream).is_none());
    }

    #[cfg(feature = "monitor-stream")]
    #[test]
    fn monitor_stream_yields_after_bounded_ready_empty_chunks() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut stream = MonitorStream {
            body: Box::pin(AlwaysReadyEmptyChunks(Arc::clone(&polls))),
            chunk: None,
            chunk_offset: 0,
            pending: sanitization::SecretVec::empty(),
            format: MonitorLogFormat::Json,
            max_frame_bytes: 64,
            terminal: false,
        };
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut context),
            Poll::Pending
        ));
        assert_eq!(
            polls.load(Ordering::SeqCst),
            super::MAX_MONITOR_CHUNKS_PER_POLL
        );
    }

    #[cfg(feature = "monitor-stream")]
    #[test]
    fn monitor_options_reject_unbounded_frame_limits() {
        assert!(MonitorOptions::default().with_max_frame_bytes(0).is_err());
        assert!(
            MonitorOptions::default()
                .with_max_frame_bytes(super::MAX_MONITOR_FRAME_BYTES + 1)
                .is_err()
        );
    }

    #[cfg(feature = "monitor-stream")]
    #[test]
    fn dropping_monitor_stream_cancels_owned_body() {
        let dropped = Arc::new(AtomicBool::new(false));
        let stream = MonitorStream {
            body: Box::pin(DropProbeStream(Arc::clone(&dropped))),
            chunk: None,
            chunk_offset: 0,
            pending: sanitization::SecretVec::empty(),
            format: MonitorLogFormat::Standard,
            max_frame_bytes: 64,
            terminal: false,
        };
        drop(stream);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn policy_identity_template_overrides_decode_as_readback_state() {
        let policy: super::PolicyInfoDetails = serde_json::from_str(
            r#"{
                "name":"templated",
                "policy":"path {{identity.entity.name}} {}",
                "allow_slashes_in_identity_templates":true,
                "allow_wildcards_in_identity_templates":true
            }"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(policy.allow_slashes_in_identity_templates);
        assert!(policy.allow_wildcards_in_identity_templates);
        assert!(!format!("{policy:?}").contains("identity.entity.name"));
    }

    #[cfg(feature = "identity-template-overrides-acknowledged")]
    #[test]
    fn acknowledged_policy_template_overrides_serialize_only_selected_flags() {
        let request = PolicyWriteRequest::new("path \"secret/data/app\" {}");
        let ordinary = serde_json::to_value(&request).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            ordinary
                .get("allow_slashes_in_identity_templates")
                .is_none()
        );
        assert!(
            ordinary
                .get("allow_wildcards_in_identity_templates")
                .is_none()
        );

        let overrides = super::AclIdentityTemplateOverrides::acknowledge_slashes();
        let payload = super::PolicyWriteWithIdentityTemplateOverrides {
            request: &request,
            allow_slashes_in_identity_templates: overrides.allow_slashes,
            allow_wildcards_in_identity_templates: overrides.allow_wildcards,
        };
        let value = serde_json::to_value(payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(value["allow_slashes_in_identity_templates"], true);
        assert!(value.get("allow_wildcards_in_identity_templates").is_none());

        let both = super::AclIdentityTemplateOverrides::acknowledge_slashes_and_wildcards();
        assert!(both.allow_slashes);
        assert!(both.allow_wildcards);
        let wildcards = super::AclIdentityTemplateOverrides::acknowledge_wildcards();
        assert!(!wildcards.allow_slashes);
        assert!(wildcards.allow_wildcards);
    }
}

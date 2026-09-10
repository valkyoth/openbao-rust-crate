use std::{io::Read, net::TcpStream, time::Duration};

const MAX_MOCK_HTTP_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_READ_CHUNK_BYTES: usize = 4096;

#[allow(dead_code)]
pub fn read_http_request(stream: &mut TcpStream) -> String {
    read_http_request_with_chunk_limit(stream, DEFAULT_READ_CHUNK_BYTES).0
}

pub fn read_http_request_with_chunk_limit(
    stream: &mut TcpStream,
    chunk_limit: usize,
) -> (String, usize) {
    assert!(chunk_limit > 0 && chunk_limit <= DEFAULT_READ_CHUNK_BYTES);
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap_or_else(|error| panic!("failed to set mock request timeout: {error}"));

    let mut request = Vec::new();
    let mut buffer = [0_u8; DEFAULT_READ_CHUNK_BYTES];
    let mut reads = 0;
    loop {
        assert!(
            request.len() < MAX_MOCK_HTTP_REQUEST_BYTES,
            "incomplete or oversized mock HTTP request"
        );
        let remaining = MAX_MOCK_HTTP_REQUEST_BYTES - request.len();
        let read_limit = chunk_limit.min(remaining);
        let bytes = stream
            .read(&mut buffer[..read_limit])
            .unwrap_or_else(|error| panic!("failed to read mock HTTP request: {error}"));
        assert!(
            bytes > 0,
            "mock HTTP request ended before framing completed"
        );
        reads += 1;
        request.extend_from_slice(&buffer[..bytes]);
        if http_request_is_complete(&request) {
            break;
        }
    }

    let request = String::from_utf8(request).unwrap_or_else(|error| {
        let bytes = error.into_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    });
    (request, reads)
}

fn http_request_is_complete(request: &[u8]) -> bool {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    body_start
        .checked_add(content_length)
        .is_some_and(|complete_length| request.len() >= complete_length)
}

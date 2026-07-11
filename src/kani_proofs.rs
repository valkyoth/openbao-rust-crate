use crate::{
    compatibility::{
        OpenBaoCapabilityEvidence, OpenBaoCapabilityRange, OpenBaoVersion, select_capability_range,
        version_in_closed_interval,
    },
    path::path_byte_is_forbidden,
    validation::{parse_duration_component, validate_duration_string},
};

#[kani::proof]
fn closed_version_interval_matches_ordering() {
    let version = OpenBaoVersion::new(kani::any(), kani::any(), kani::any());
    let minimum = OpenBaoVersion::new(kani::any(), kani::any(), kani::any());
    let maximum = OpenBaoVersion::new(kani::any(), kani::any(), kani::any());

    assert!(
        version_in_closed_interval(version, minimum, maximum)
            == (version >= minimum && version <= maximum)
    );
}

#[kani::proof]
fn capability_selection_never_escapes_selected_interval() {
    let version = OpenBaoVersion::new(kani::any(), kani::any(), kani::any());
    let first_minimum = OpenBaoVersion::new(2, 0, 0);
    let first_maximum = OpenBaoVersion::new(2, 2, 2);
    let second_minimum = OpenBaoVersion::new(2, 3, 1);
    let second_maximum = OpenBaoVersion::new(2, 5, 5);
    let ranges = [
        OpenBaoCapabilityRange::generated(
            first_minimum,
            first_maximum,
            OpenBaoCapabilityEvidence::TaggedDocumentation,
        ),
        OpenBaoCapabilityRange::generated(
            second_minimum,
            second_maximum,
            OpenBaoCapabilityEvidence::LockedOpenApi,
        ),
    ];

    if let Some(selected) = select_capability_range(&ranges, version) {
        assert!(version >= selected.minimum());
        assert!(version <= selected.maximum());
    }
}

#[kani::proof]
fn path_forbidden_byte_helper_matches_documented_policy() {
    let byte = kani::any::<u8>();
    let expected = byte.is_ascii_control() || matches!(byte, b' ' | b'%' | b'\\' | b'?' | b'#');

    assert!(path_byte_is_forbidden(byte) == expected);
}

#[kani::proof]
fn duration_component_parser_accepts_single_digits() {
    let digit = b'0' + (kani::any::<u8>() % 10);
    let parsed = parse_duration_component(&[digit]);

    assert!(parsed == Some(u64::from(digit - b'0')));
}

#[kani::proof]
fn duration_component_parser_accepts_two_digits() {
    let tens = b'0' + (kani::any::<u8>() % 10);
    let ones = b'0' + (kani::any::<u8>() % 10);
    let parsed = parse_duration_component(&[tens, ones]);
    let expected = u64::from(tens - b'0') * 10 + u64::from(ones - b'0');

    assert!(parsed == Some(expected));
}

#[kani::proof]
fn duration_component_parser_rejects_non_digits() {
    let byte = kani::any::<u8>();
    kani::assume(!byte.is_ascii_digit());

    assert!(parse_duration_component(&[byte]).is_none());
}

#[kani::proof]
fn duration_component_parser_rejects_empty_input() {
    assert!(parse_duration_component(&[]).is_none());
}

#[kani::proof]
fn duration_parser_accepts_documented_examples() {
    assert!(validate_duration_string("30s", false));
    assert!(validate_duration_string("5m", false));
    assert!(validate_duration_string("1h30m", false));
    assert!(!validate_duration_string("", false));
    assert!(!validate_duration_string("0s", false));
    assert!(!validate_duration_string("1m1h", false));
    assert!(!validate_duration_string("-1h", false));
}

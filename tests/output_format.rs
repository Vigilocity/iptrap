//! Integration tests for JSON output format
//!
//! These tests verify that the output JSON structure matches the expected format
//! with base64-encoded payloads and TCP flags.

use base64::{Engine as _, engine::general_purpose};
use rustc_serialize::json::Json;
use std::collections::HashMap;

/// Simulates the JSON record creation from main.rs log_tcp_ack function
fn create_json_record(
    ts: u64,
    ip_src: [u8; 4],
    dport: u16,
    tcp_flags: u8,
    tcp_data: &[u8],
) -> String {
    let payload_b64 = general_purpose::STANDARD.encode(tcp_data);
    let mut record: HashMap<String, Json> = HashMap::with_capacity(5);
    record.insert("ts".to_owned(), Json::U64(ts));
    record.insert(
        "ip_src".to_owned(),
        Json::String(format!("{}.{}.{}.{}", ip_src[0], ip_src[1], ip_src[2], ip_src[3])),
    );
    record.insert("dport".to_owned(), Json::U64(dport as u64));
    record.insert("tcp_flags".to_owned(), Json::U64(tcp_flags as u64));
    record.insert("payload".to_owned(), Json::String(payload_b64));

    Json::Object(record.into_iter().collect()).to_string()
}

#[test]
fn test_json_output_structure() {
    let json_str = create_json_record(
        1703241600,
        [192, 168, 1, 100],
        443,
        0x18, // ACK + PSH
        b"Hello, World!",
    );

    let json = Json::from_str(&json_str).expect("Should parse JSON");
    let obj = json.as_object().expect("Should be object");

    assert!(obj.contains_key("ts"));
    assert!(obj.contains_key("ip_src"));
    assert!(obj.contains_key("dport"));
    assert!(obj.contains_key("tcp_flags"));
    assert!(obj.contains_key("payload"));
}

#[test]
fn test_base64_payload_encoding() {
    let original_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let json_str = create_json_record(
        1703241600,
        [192, 168, 1, 100],
        80,
        0x18,
        original_payload,
    );

    let json = Json::from_str(&json_str).expect("Should parse JSON");
    let payload_b64 = json.find("payload")
        .and_then(|v| v.as_string())
        .expect("payload should be string");

    let decoded = general_purpose::STANDARD
        .decode(payload_b64)
        .expect("Should decode base64");

    assert_eq!(decoded, original_payload.to_vec());
}

#[test]
fn test_binary_payload_preserved() {
    // TLS Client Hello header (binary data that would be corrupted by UTF-8 lossy)
    let binary_payload: Vec<u8> = vec![
        0x16, 0x03, 0x01, 0x02, 0x00, // TLS record header
        0x01, 0x00, 0x01, 0xfc,       // Handshake header
        0x03, 0x03,                   // TLS version
        // Random bytes with high bit set (would be corrupted by UTF-8 lossy)
        0x80, 0x81, 0x82, 0x83, 0xff, 0xfe, 0xfd, 0xfc,
    ];

    let json_str = create_json_record(
        1703241600,
        [45, 33, 32, 156],
        443,
        0x18,
        &binary_payload,
    );

    let json = Json::from_str(&json_str).expect("Should parse JSON");
    let payload_b64 = json.find("payload")
        .and_then(|v| v.as_string())
        .expect("payload should be string");

    let decoded = general_purpose::STANDARD
        .decode(payload_b64)
        .expect("Should decode base64");

    assert_eq!(decoded, binary_payload, "Binary payload should be preserved exactly");
}

#[test]
fn test_empty_payload() {
    let json_str = create_json_record(
        1703241600,
        [192, 168, 1, 100],
        443,
        0x10, // ACK only
        &[],
    );

    let json = Json::from_str(&json_str).expect("Should parse JSON");
    let payload_b64 = json.find("payload")
        .and_then(|v| v.as_string())
        .expect("payload should be string");

    assert_eq!(payload_b64, "", "Empty payload should encode to empty string");
}

#[test]
fn test_tcp_flags_values() {
    // Test various TCP flag combinations
    let test_cases = vec![
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x12, "SYN+ACK"),
        (0x18, "ACK+PSH"),
        (0x14, "ACK+RST"),
        (0x11, "ACK+FIN"),
    ];

    for (flags, _name) in test_cases {
        let json_str = create_json_record(1703241600, [192, 168, 1, 100], 443, flags, b"test");

        let json = Json::from_str(&json_str).expect("Should parse JSON");
        let tcp_flags = json.find("tcp_flags")
            .and_then(|v| v.as_u64())
            .expect("tcp_flags should be u64");

        assert_eq!(tcp_flags, flags as u64);
    }
}

#[test]
fn test_ip_address_formatting() {
    let test_cases = vec![
        ([0, 0, 0, 0], "0.0.0.0"),
        ([127, 0, 0, 1], "127.0.0.1"),
        ([192, 168, 1, 100], "192.168.1.100"),
        ([255, 255, 255, 255], "255.255.255.255"),
        ([10, 0, 0, 1], "10.0.0.1"),
    ];

    for (ip, expected) in test_cases {
        let json_str = create_json_record(1703241600, ip, 443, 0x10, b"test");

        let json = Json::from_str(&json_str).expect("Should parse JSON");
        let ip_src = json.find("ip_src")
            .and_then(|v| v.as_string())
            .expect("ip_src should be string");

        assert_eq!(ip_src, expected);
    }
}

#[test]
fn test_port_values() {
    let test_cases = vec![80u16, 443, 8080, 22, 65535, 1];

    for port in test_cases {
        let json_str = create_json_record(1703241600, [192, 168, 1, 100], port, 0x10, b"test");

        let json = Json::from_str(&json_str).expect("Should parse JSON");
        let dport = json.find("dport")
            .and_then(|v| v.as_u64())
            .expect("dport should be u64");

        assert_eq!(dport, port as u64);
    }
}

#[test]
fn test_timestamp_values() {
    let test_cases = vec![0u64, 1703241600, u64::MAX];

    for ts in test_cases {
        let json_str = create_json_record(ts, [192, 168, 1, 100], 443, 0x10, b"test");

        let json = Json::from_str(&json_str).expect("Should parse JSON");
        let timestamp = json.find("ts")
            .and_then(|v| v.as_u64())
            .expect("ts should be u64");

        assert_eq!(timestamp, ts);
    }
}

#[test]
fn test_large_payload() {
    // Test with a larger payload (64KB)
    let large_payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

    let json_str = create_json_record(
        1703241600,
        [192, 168, 1, 100],
        443,
        0x18,
        &large_payload,
    );

    let json = Json::from_str(&json_str).expect("Should parse JSON");
    let payload_b64 = json.find("payload")
        .and_then(|v| v.as_string())
        .expect("payload should be string");

    let decoded = general_purpose::STANDARD
        .decode(payload_b64)
        .expect("Should decode base64");

    assert_eq!(decoded.len(), 65536);
    assert_eq!(decoded, large_payload);
}

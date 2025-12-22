use std::hash::{Hash, Hasher};

use rand;
use siphasher;

use self::siphasher::sip::SipHasher13;

#[derive(Copy, Clone)]
pub struct SipHashKey {
    k1: u64,
    k2: u64,
}

impl SipHashKey {
    pub fn new() -> SipHashKey {
        SipHashKey {
            k1: rand::random(),
            k2: rand::random(),
        }
    }
}

#[derive(Hash)]
struct CookieInput {
    ip_src: [u8; 4],
    ip_dst: [u8; 4],
    th_sport: u16,
    th_dport: u16,
    uts: u64,
}

#[allow(unused_must_use)]
pub fn tcp(
    ip_src: [u8; 4],
    ip_dst: [u8; 4],
    th_sport: u16,
    th_dport: u16,
    sk: SipHashKey,
    uts: u64,
) -> u32 {
    let input = CookieInput {
        ip_src,
        ip_dst,
        th_sport,
        th_dport,
        uts,
    };
    let sip = &mut SipHasher13::new_with_keys(sk.k1, sk.k2);
    input.hash(sip);
    sip.finish() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SipHashKey {
        SipHashKey {
            k1: 0x0706050403020100,
            k2: 0x0f0e0d0c0b0a0908,
        }
    }

    #[test]
    fn test_cookie_deterministic() {
        let sk = test_key();
        let ip_src = [192, 168, 1, 100];
        let ip_dst = [10, 0, 0, 1];
        let th_sport = 54321u16.to_be();
        let th_dport = 443u16.to_be();
        let uts = 1703241600u64;

        let cookie1 = tcp(ip_src, ip_dst, th_sport, th_dport, sk, uts);
        let cookie2 = tcp(ip_src, ip_dst, th_sport, th_dport, sk, uts);

        assert_eq!(cookie1, cookie2, "Same inputs should produce same cookie");
    }

    #[test]
    fn test_cookie_different_ips() {
        let sk = test_key();
        let ip_dst = [10, 0, 0, 1];
        let th_sport = 54321u16.to_be();
        let th_dport = 443u16.to_be();
        let uts = 1703241600u64;

        let cookie1 = tcp([192, 168, 1, 100], ip_dst, th_sport, th_dport, sk, uts);
        let cookie2 = tcp([192, 168, 1, 101], ip_dst, th_sport, th_dport, sk, uts);

        assert_ne!(cookie1, cookie2, "Different source IPs should produce different cookies");
    }

    #[test]
    fn test_cookie_different_ports() {
        let sk = test_key();
        let ip_src = [192, 168, 1, 100];
        let ip_dst = [10, 0, 0, 1];
        let uts = 1703241600u64;

        let cookie1 = tcp(ip_src, ip_dst, 54321u16.to_be(), 443u16.to_be(), sk, uts);
        let cookie2 = tcp(ip_src, ip_dst, 54322u16.to_be(), 443u16.to_be(), sk, uts);

        assert_ne!(cookie1, cookie2, "Different ports should produce different cookies");
    }

    #[test]
    fn test_cookie_different_timestamps() {
        let sk = test_key();
        let ip_src = [192, 168, 1, 100];
        let ip_dst = [10, 0, 0, 1];
        let th_sport = 54321u16.to_be();
        let th_dport = 443u16.to_be();

        let cookie1 = tcp(ip_src, ip_dst, th_sport, th_dport, sk, 1703241600);
        let cookie2 = tcp(ip_src, ip_dst, th_sport, th_dport, sk, 1703241664);

        assert_ne!(cookie1, cookie2, "Different timestamps should produce different cookies");
    }

    #[test]
    fn test_siphash_key_random() {
        let key1 = SipHashKey::new();
        let key2 = SipHashKey::new();

        // Keys should be different (extremely unlikely to be the same)
        assert!(key1.k1 != key2.k1 || key1.k2 != key2.k2, "Random keys should differ");
    }
}

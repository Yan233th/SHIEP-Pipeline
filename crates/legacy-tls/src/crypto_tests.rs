use super::*;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn prfs_match_independent_openssl_vectors_including_odd_secret_split() {
    let mut out = [0; 100];
    prf(
        Version::Tls12,
        &hex("9bbe436ba940f017b17652849a71db35"),
        b"test label",
        &hex("a0ba9f936cda311827a6f796ffd5198c"),
        &mut out,
    );
    assert_eq!(
        out.as_slice(),
        hex(concat!(
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a",
            "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab",
            "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
        ))
    );
    let mut out = [0; 64];
    prf(
        Version::Tls11,
        &[1, 2, 3, 4, 5],
        b"test label",
        &[6, 7, 8, 9],
        &mut out,
    );
    assert_eq!(
        out.as_slice(),
        hex(concat!(
            "0c7c93613cbe6c21ad489f69df66e70bd36b6ae224ced4068cf3233f22b22b89",
            "1e479d55d161770e987bc416d74764dd6e970981577921d669803c1cf249471c"
        ))
    );
}

#[test]
fn hidden_length_sha1_matches_hmac_for_every_padding_length_and_hash_boundary() {
    let key = [0x42; 20];
    for size in [32, 48, 64, 80, 128, 256, 272, 288, 512, 16_416] {
        for padding in 1..=256.min(size - 20) {
            let len = size - 20 - padding;
            let mut data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected = record_mac(&key, 0x123456789, 23, Version::Tls11, &data);
            data.extend_from_slice(&expected);
            data.resize(size, (padding - 1) as u8);
            let actual = hidden_length_mac(
                &key,
                &header(0x123456789, 23, Version::Tls11, len),
                &data,
                len,
            );
            assert_eq!(actual, expected, "size={size}, padding={padding}");
            assert_eq!(
                verify_cbc_mac(&key, 0x123456789, 23, Version::Tls11, &data).unwrap(),
                len
            );
            data[len] ^= 1;
            assert!(matches!(
                verify_cbc_mac(&key, 0x123456789, 23, Version::Tls11, &data),
                Err(Error::BadRecordMac)
            ));
        }
    }
}

#[test]
fn all_invalid_padding_values_have_the_same_mac_error() {
    let key = [9; 20];
    let mut data = vec![7; 16];
    data.extend_from_slice(&record_mac(&key, 0, 23, Version::Tls12, &data));
    data.resize(48, 11);
    assert_eq!(
        verify_cbc_mac(&key, 0, 23, Version::Tls12, &data).unwrap(),
        16
    );
    for value in 0..=255 {
        if value == 11 {
            continue;
        }
        let mut broken = data.clone();
        broken[47] = value;
        assert!(matches!(
            verify_cbc_mac(&key, 0, 23, Version::Tls12, &broken),
            Err(Error::BadRecordMac)
        ));
    }
    for position in 36..48 {
        let mut broken = data.clone();
        broken[position] ^= 1;
        assert!(matches!(
            verify_cbc_mac(&key, 0, 23, Version::Tls12, &broken),
            Err(Error::BadRecordMac)
        ));
    }
}

#[test]
fn cbc_compression_work_does_not_depend_on_decrypted_padding() {
    for size in [32, 64, 256, 512, 16_416] {
        let mut data = vec![0; size];
        let mut expected = None;
        for padding_byte in 0..=255 {
            data[size - 1] = padding_byte;
            COMPRESSIONS.with(|count| count.set(0));
            let _ = verify_cbc_mac(&[0; 20], 0, 23, Version::Tls11, &data);
            let actual = COMPRESSIONS.with(|count| count.get());
            assert!(actual > 0);
            assert_eq!(actual, *expected.get_or_insert(actual));
        }
    }
}

#[test]
#[ignore = "manual release-mode timing diagnostic; host noise prevents a CI threshold"]
#[allow(clippy::assertions_on_constants)] // Runtime guard for an explicitly selected diagnostic.
fn cbc_rejection_timing() {
    use std::hint::black_box;
    use std::time::Instant;

    assert!(!cfg!(debug_assertions), "run with --release");
    #[derive(Default, Clone, Copy)]
    struct Samples {
        count: f64,
        mean: f64,
        m2: f64,
    }
    impl Samples {
        fn push(&mut self, sample: f64) {
            self.count += 1.0;
            let delta = sample - self.mean;
            self.mean += delta / self.count;
            self.m2 += delta * (sample - self.mean);
        }
        fn variance_of_mean(self) -> f64 {
            self.m2 / (self.count - 1.0) / self.count
        }
    }

    for size in [48, 256, 512] {
        // Both classes must fail; only the padding validity differs. Comparing
        // accepted vs rejected records would measure the public return path.
        let mut bad_mac = vec![0; size];
        bad_mac[size - 12..].fill(11);
        let mut bad_padding = bad_mac.clone();
        bad_padding[size - 1] ^= 1;
        let inputs = [bad_mac, bad_padding];
        let mut samples = [Samples::default(); 2];
        let mut state = 0xb427_0159u32;
        for iteration in 0..101_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let class = (state & 1) as usize;
            let input = black_box(inputs[class].as_slice());
            let start = Instant::now();
            let result = black_box(verify_cbc_mac(
                black_box(&[9; 20]),
                0,
                23,
                Version::Tls11,
                input,
            ));
            let elapsed = start.elapsed().as_nanos() as f64;
            assert!(matches!(result, Err(Error::BadRecordMac)));
            if iteration >= 1_000 {
                samples[class].push(elapsed);
            }
        }
        let [a, b] = samples;
        let t = (a.mean - b.mean) / (a.variance_of_mean() + b.variance_of_mean()).sqrt();
        eprintln!(
            "CBC {size} bytes: bad MAC {:.0} ns, bad padding {:.0} ns; Welch t {t:.2}; samples {:.0}/{:.0}",
            a.mean, b.mean, a.count, b.count
        );
    }
}

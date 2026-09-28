use super::*;
use std::io::{self, Cursor};

#[test]
fn both_ciphers_and_mac_modes_reject_tampering_replay_and_wrong_type() {
    for suite in [CipherSuite::Aes128Sha, CipherSuite::Aes256Sha] {
        for etm in [false, true] {
            let key = vec![0x73; suite.key_len()];
            let fresh = || Keys::new(suite, &key, &[0x37; 20], etm);
            for size in [0, 1, 15, 16, 17, 255, MAX_PLAINTEXT] {
                let plain = vec![0xac; size];
                let encrypted = fresh().seal(23, Version::Tls11, &plain).unwrap();
                let mut receiver = fresh();
                assert_eq!(
                    *receiver.open(23, Version::Tls11, &encrypted).unwrap(),
                    plain
                );
                assert!(matches!(
                    receiver.open(23, Version::Tls11, &encrypted),
                    Err(Error::BadRecordMac)
                ));
                assert!(matches!(
                    fresh().open(22, Version::Tls11, &encrypted),
                    Err(Error::BadRecordMac)
                ));
                for index in [0, 15, 16, encrypted.len() - 1] {
                    let mut broken = encrypted.clone();
                    broken[index] ^= 1;
                    assert!(matches!(
                        fresh().open(23, Version::Tls11, &broken),
                        Err(Error::BadRecordMac)
                    ));
                }
            }
        }
    }
}

struct InterruptedRead {
    data: Cursor<Vec<u8>>,
    stop: usize,
    fired: bool,
}
impl Read for InterruptedRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.data.position() as usize == self.stop && !self.fired {
            self.fired = true;
            return Err(io::ErrorKind::TimedOut.into());
        }
        let limit = out.len().min(1);
        self.data.read(&mut out[..limit])
    }
}

#[test]
fn record_reads_resume_after_timeout_at_every_header_and_payload_position() {
    let mut wire = Vec::new();
    write(&mut wire, 23, Version::Tls12, b"fragmented ciphertext").unwrap();
    for stop in 0..wire.len() {
        let mut input = InterruptedRead {
            data: Cursor::new(wire.clone()),
            stop,
            fired: false,
        };
        let mut reader = Reader::default();
        assert!(
            matches!(reader.read(&mut input), Err(Error::Io(err)) if err.kind() == io::ErrorKind::TimedOut)
        );
        let (kind, version, body) = reader.read(&mut input).unwrap();
        assert_eq!((kind, version), (23, 0x0303));
        assert_eq!(body, b"fragmented ciphertext");
    }
}

#[test]
fn record_reader_rejects_oversize_and_truncated_records() {
    assert!(
        Reader::default()
            .read(&mut Cursor::new([23, 3, 3, 255, 255]))
            .is_err()
    );
    for bytes in [&b""[..], &[23], &[23, 3, 3, 0, 5, 0]] {
        assert!(
            matches!(Reader::default().read(&mut Cursor::new(bytes)), Err(Error::Io(err)) if err.kind() == io::ErrorKind::UnexpectedEof)
        );
    }
}

#[test]
fn sequence_numbers_never_wrap() {
    let mut keys = Keys::new(CipherSuite::Aes128Sha, &[0; 16], &[0; 20], false);
    keys.sequence = u64::MAX;
    assert!(keys.seal(23, Version::Tls11, b"test").is_err());
}

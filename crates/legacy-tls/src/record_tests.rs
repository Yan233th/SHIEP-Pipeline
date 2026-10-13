use super::*;
use std::io::{self, Cursor};

#[test]
fn both_ciphers_and_mac_modes_reject_tampering_replay_and_wrong_type() {
    for suite in [CipherSuite::Aes128Sha, CipherSuite::Aes256Sha] {
        for etm in [false, true] {
            let key = vec![0x73; suite.key_len()];
            let fresh = || Keys::new(suite, &key, &[0x37; 20], etm);
            for version in [Version::Tls11, Version::Tls12] {
                for size in [0, 1, 15, 16, 17, 255, MAX_PLAINTEXT] {
                    let plain = vec![0xac; size];
                    let wire = fresh().seal_record(23, version, &plain).unwrap();
                    assert_eq!(
                        u16::from_be_bytes([wire[3], wire[4]]) as usize,
                        wire.len() - 5
                    );
                    let mut input = wire.as_slice();
                    let (kind, record_version, encrypted) =
                        Reader::default().read(&mut input).unwrap();
                    assert_eq!((kind, record_version), (23, version as u16));
                    assert!(input.is_empty());
                    let mut receiver = fresh();
                    let mut buffer = Zeroizing::new(encrypted.clone());
                    let allocation = buffer.as_ptr();
                    let content = receiver.open_in_place(23, version, &mut buffer).unwrap();
                    assert_eq!(buffer.as_ptr(), allocation);
                    assert_eq!(buffer[content], plain);
                    assert!(matches!(
                        receiver.open_in_place(23, version, &mut Zeroizing::new(encrypted.clone())),
                        Err(Error::BadRecordMac)
                    ));
                    assert!(matches!(
                        fresh().open_in_place(22, version, &mut Zeroizing::new(encrypted.clone())),
                        Err(Error::BadRecordMac)
                    ));
                    for index in [0, 15, 16, encrypted.len() - 1] {
                        let mut broken = Zeroizing::new(encrypted.clone());
                        broken[index] ^= 1;
                        assert!(matches!(
                            fresh().open_in_place(23, version, &mut broken),
                            Err(Error::BadRecordMac)
                        ));
                    }
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
    assert!(keys.seal_record(23, Version::Tls11, b"test").is_err());
}

#[test]
fn oversize_plaintext_does_not_consume_a_sequence_number() {
    for etm in [false, true] {
        let mut keys = Keys::new(CipherSuite::Aes128Sha, &[0; 16], &[0; 20], etm);
        assert!(matches!(
            keys.seal_record(23, Version::Tls12, &vec![0; MAX_PLAINTEXT + 1]),
            Err(Error::Protocol("TLS plaintext too large"))
        ));
        assert_eq!(keys.sequence, 0);
    }
}

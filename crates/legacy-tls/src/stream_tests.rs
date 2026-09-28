use super::*;
use std::io::Cursor;

fn stream<S>(io: S) -> TlsStream<S> {
    let keys = || record::Keys::new(CipherSuite::Aes128Sha, &[7; 16], &[9; 20], false);
    TlsStream {
        io,
        reader: record::Reader::default(),
        read_keys: keys(),
        write_keys: keys(),
        version: Version::Tls11,
        suite: CipherSuite::Aes128Sha,
        session_id: Vec::new(),
        extended_master_secret: false,
        encrypt_then_mac: false,
        plain: Zeroizing::new(Vec::new()),
        offset: 0,
        received_close: false,
        sent_close: false,
        failed: false,
        control: Control::default(),
    }
}

#[test]
fn a_corrupt_record_never_releases_plaintext_and_terminates_the_stream() {
    let mut keys = record::Keys::new(CipherSuite::Aes128Sha, &[7; 16], &[9; 20], false);
    let mut encrypted = keys
        .seal(23, Version::Tls11, b"authenticated message")
        .unwrap();
    encrypted[0] ^= 1;
    let mut wire = Vec::new();
    record::write(&mut wire, 23, Version::Tls11, &encrypted).unwrap();
    let mut stream = stream(Cursor::new(wire));
    let mut out = [0x44; 128];
    assert_eq!(
        stream.read(&mut out).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(out, [0x44; 128]);
    assert_eq!(
        stream.read(&mut out).unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(stream.write_all(b"after failure").is_err());
    assert!(stream.flush().is_err());
}

#[test]
fn short_application_reads_preserve_data_and_close_notify_is_idempotent() {
    let mut keys = record::Keys::new(CipherSuite::Aes128Sha, &[7; 16], &[9; 20], false);
    let mut wire = Vec::new();
    for (kind, plain) in [(23, b"hello".as_slice()), (21, &[1, 0])] {
        let body = keys.seal(kind, Version::Tls11, plain).unwrap();
        record::write(&mut wire, kind, Version::Tls11, &body).unwrap();
    }
    let mut stream = stream(Cursor::new(wire));
    let mut byte = [0];
    for expected in b"hello" {
        assert_eq!(stream.read(&mut byte).unwrap(), 1);
        assert_eq!(byte[0], *expected);
    }
    assert_eq!(stream.read(&mut byte).unwrap(), 0);
    assert_eq!(stream.read(&mut byte).unwrap(), 0);
    assert!(stream.write_all(b"closed").is_err());
}

struct PartialWrite {
    written: Vec<u8>,
}
impl Read for PartialWrite {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl Write for PartialWrite {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.written.is_empty() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.written.extend_from_slice(&bytes[..3]);
        Ok(3)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn partial_write_failure_does_not_replay_or_accept_more_plaintext() {
    let mut stream = stream(PartialWrite {
        written: Vec::new(),
    });
    assert_eq!(
        stream.write(b"request").unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        stream.write(b"request").unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(stream.get_ref().written.len(), 3);
}

struct FailedFlush {
    written: Vec<u8>,
}
impl Read for FailedFlush {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl Write for FailedFlush {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::TimedOut.into())
    }
}

#[test]
fn failed_flush_cannot_be_retried_as_a_successful_close() {
    for close in [false, true] {
        let mut stream = stream(FailedFlush {
            written: Vec::new(),
        });
        let error = if close {
            stream.close().unwrap_err()
        } else {
            stream.write_all(b"buffered request").unwrap();
            stream.flush().unwrap_err().into()
        };
        assert!(matches!(error, Error::Io(err) if err.kind() == io::ErrorKind::TimedOut));
        let written = stream.get_ref().written.len();
        assert!(stream.close().is_err());
        assert!(stream.write_all(b"more").is_err());
        assert!(stream.read(&mut [0; 1]).is_err());
        assert!(stream.flush().is_err());
        assert_eq!(stream.get_ref().written.len(), written);
    }
}

#[derive(Default)]
struct Duplex {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    timeout_at: Option<u64>,
}
impl Read for Duplex {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.timeout_at == Some(self.input.position()) {
            self.timeout_at = None;
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.input.read(out)
    }
}
impl Write for Duplex {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn incoming(records: &[(u8, &[u8])]) -> Duplex {
    let mut io = Duplex::default();
    let mut keys = record::Keys::new(CipherSuite::Aes128Sha, &[7; 16], &[9; 20], false);
    for (kind, bytes) in records {
        let sealed = keys.seal(*kind, Version::Tls11, bytes).unwrap();
        record::write(io.input.get_mut(), *kind, Version::Tls11, &sealed).unwrap();
    }
    io
}

#[test]
fn peer_close_gets_one_authenticated_reply_and_discards_later_data() {
    let mut stream = stream(incoming(&[(21, &[1, 0]), (23, b"after close")]));
    let mut byte = [0xff];
    assert_eq!(stream.read(&mut byte).unwrap(), 0);
    assert_eq!(byte, [0xff]);
    let reply = stream.get_ref().output.clone();
    assert!(!reply.is_empty());
    let mut cursor = reply.as_slice();
    let (kind, version, ciphertext) = record::Reader::default().read(&mut cursor).unwrap();
    assert_eq!((kind, version), (21, 0x0302));
    let mut keys = record::Keys::new(CipherSuite::Aes128Sha, &[7; 16], &[9; 20], false);
    assert_eq!(
        keys.open(kind, Version::Tls11, &ciphertext)
            .unwrap()
            .as_slice(),
        &[1, 0]
    );
    assert!(cursor.is_empty());
    stream.close().unwrap();
    assert_eq!(stream.read(&mut byte).unwrap(), 0);
    assert!(stream.write_all(b"after close").is_err());
    assert_eq!(stream.get_ref().output, reply);
}

#[test]
fn invalid_control_records_and_unsolicited_ccs_poison_the_stream() {
    for (kind, bytes) in [
        (20, &[1][..]),
        (21, &[]),
        (21, &[3, 0]),
        (22, &[20, 0, 0, 0]),
    ] {
        let mut stream = stream(incoming(&[(kind, bytes)]));
        assert!(stream.read(&mut [0; 1]).is_err());
        assert!(stream.write_all(b"must not send").is_err());
        assert!(stream.get_ref().output.is_empty());
    }
}

#[test]
fn empty_record_limit_does_not_discard_the_following_application_data() {
    for empty_count in [32, 33] {
        let mut records = vec![(23, &b""[..]); empty_count];
        records.push((23, b"a"));
        let mut stream = stream(incoming(&records));
        let mut out = [0];
        if empty_count == 32 {
            assert_eq!(stream.read(&mut out).unwrap(), 1);
            assert_eq!(out, *b"a");
        } else {
            assert!(stream.read(&mut out).is_err());
            assert_eq!(out, [0]);
        }
    }
}

#[test]
fn fragmented_close_and_fragmented_or_coalesced_hello_requests_are_processed() {
    for boundary in 1..4 {
        let hello = [0; 4];
        let mut stream = stream(incoming(&[
            (22, &hello[..boundary]),
            (22, &hello[boundary..]),
            (22, &[0; 8]),
            (23, b"ok"),
            (21, &[1]),
            (21, &[0]),
        ]));
        let mut out = Vec::new();
        stream.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"ok");
        let mut wire = stream.get_ref().output.as_slice();
        let mut reader = record::Reader::default();
        let mut keys = record::Keys::new(CipherSuite::Aes128Sha, &[7; 16], &[9; 20], false);
        for expected in [&[1, 100][..], &[1, 100], &[1, 100], &[1, 0]] {
            let (kind, _, body) = reader.read(&mut wire).unwrap();
            assert_eq!(kind, 21);
            assert_eq!(
                keys.open(kind, Version::Tls11, &body).unwrap().as_slice(),
                expected
            );
        }
        assert!(wire.is_empty());
    }
}

#[test]
fn incomplete_control_messages_never_release_interleaved_application_data() {
    for records in [
        vec![(22, &[0, 0][..]), (23, b"bad")],
        vec![(21, &[1][..]), (23, b"bad")],
        vec![(22, &[0, 0][..]), (21, &[1, 0])],
        vec![(22, &[0, 0][..])],
        vec![(21, &[1][..])],
    ] {
        let mut stream = stream(incoming(&records));
        let mut out = [0xfe; 16];
        assert!(stream.read(&mut out).is_err());
        assert_eq!(out, [0xfe; 16]);
    }
}

#[test]
fn read_timeout_preserves_an_alert_split_across_tls_records() {
    let mut io = incoming(&[(21, &[1]), (21, &[0])]);
    let header = io.input.get_ref();
    io.timeout_at = Some(u64::from(u16::from_be_bytes([header[3], header[4]])) + 5);
    let mut stream = stream(io);
    assert_eq!(
        stream.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(stream.get_ref().output.is_empty());
    assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
    assert!(!stream.get_ref().output.is_empty());
}

#[test]
fn renegotiation_after_local_close_cannot_write_another_record() {
    let mut stream = stream(incoming(&[(22, &[0; 4])]));
    stream.close().unwrap();
    let written = stream.get_ref().output.clone();
    assert!(stream.read(&mut [0; 1]).is_err());
    assert_eq!(stream.get_ref().output, written);
}

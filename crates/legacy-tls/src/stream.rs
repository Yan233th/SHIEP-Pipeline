use crate::{CipherSuite, Error, Version, record};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

/// An established blocking TLS connection with bounded record buffering.
///
/// Read timeouts preserve partially received records and may be retried.
/// A failed write terminates this connection because the transport may have
/// accepted a partial record. No background tasks or implicit reconnects exist.
pub struct TlsStream<S> {
    pub(crate) io: S,
    pub(crate) reader: record::Reader,
    pub(crate) read_keys: record::Keys,
    pub(crate) write_keys: record::Keys,
    pub(crate) version: Version,
    pub(crate) suite: CipherSuite,
    pub(crate) session_id: Vec<u8>,
    pub(crate) extended_master_secret: bool,
    pub(crate) encrypt_then_mac: bool,
    pub(crate) plain: Zeroizing<Vec<u8>>,
    pub(crate) offset: usize,
    pub(crate) received_close: bool,
    pub(crate) sent_close: bool,
    pub(crate) failed: bool,
}

impl<S> TlsStream<S> {
    /// Access the transport for socket options and shutdown.
    pub fn get_ref(&self) -> &S {
        &self.io
    }
    /// Access the transport mutably. Bypassing TLS for I/O will corrupt it.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }
    /// The version authenticated by the completed handshake.
    pub fn version(&self) -> Version {
        self.version
    }
    /// The negotiated cipher suite.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.suite
    }
    /// The server's opaque TLS session identifier. No resumption secret is kept.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
    /// Whether RFC 7627 extended master secret was negotiated.
    pub fn extended_master_secret(&self) -> bool {
        self.extended_master_secret
    }
    /// Whether RFC 7366 encrypt-then-MAC was negotiated.
    pub fn encrypt_then_mac(&self) -> bool {
        self.encrypt_then_mac
    }
}

impl<S: Read + Write> TlsStream<S> {
    fn send(&mut self, kind: u8, data: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TLS connection has failed",
            )
            .into());
        }
        let result = self
            .write_keys
            .seal(kind, self.version, data)
            .and_then(|body| record::write(&mut self.io, kind, self.version, &body));
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Sends close_notify once, without waiting for the peer or closing the
    /// underlying transport. Dropping a stream never performs blocking I/O.
    pub fn close(&mut self) -> Result<(), Error> {
        if !self.sent_close {
            self.send(21, &[1, 0])?;
            self.sent_close = true;
            self.io.flush()?;
        }
        Ok(())
    }

    fn receive(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TLS connection has failed",
            )
            .into());
        }
        let mut empty_records = 0;
        loop {
            if self.offset < self.plain.len() {
                let n = out.len().min(self.plain.len() - self.offset);
                out[..n].copy_from_slice(&self.plain[self.offset..self.offset + n]);
                self.offset += n;
                if self.offset == self.plain.len() {
                    self.plain.fill(0);
                    self.plain.clear();
                    self.offset = 0;
                }
                return Ok(n);
            }
            if self.received_close {
                return Ok(0);
            }
            let (kind, version, body) = self.reader.read(&mut self.io)?;
            if version != self.version as u16 {
                return Err(Error::Protocol("TLS record version changed"));
            }
            let plain = self.read_keys.open(kind, self.version, &body)?;
            match kind {
                23 => self.plain = plain,
                21 if plain.as_slice() == [1, 0] => self.received_close = true,
                21 if plain.len() == 2 => return Err(Error::Alert(plain[1])),
                // A request to renegotiate has no transcript state. Decline it
                // rather than silently accepting a new handshake mid-stream.
                22 if plain.as_slice() == [0, 0, 0, 0] => self.send(21, &[1, 100])?,
                _ => return Err(Error::Protocol("unexpected TLS application record")),
            }
            empty_records += 1;
            if empty_records > 32 {
                return Err(Error::Protocol("too many empty TLS records"));
            }
        }
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self.receive(out) {
            Ok(n) => Ok(n),
            Err(Error::Io(err))
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Err(err)
            }
            Err(err) => {
                self.failed = true;
                Err(to_io(err))
            }
        }
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.sent_close || self.received_close {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let len = data.len().min(record::MAX_PLAINTEXT);
        self.send(23, &data[..len]).map_err(to_io)?;
        Ok(len)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

fn to_io(error: Error) -> io::Error {
    match error {
        Error::Io(err) => err,
        err => io::Error::new(io::ErrorKind::InvalidData, err),
    }
}

#[cfg(test)]
mod tests {
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
}

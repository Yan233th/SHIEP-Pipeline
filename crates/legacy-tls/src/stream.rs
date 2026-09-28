use crate::{CipherSuite, Error, Version, record};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

/// An established blocking TLS connection with bounded record buffering.
///
/// Read timeouts preserve partially received records and may be retried.
/// A failed write terminates this connection because the transport may have
/// accepted a partial record. No background tasks or implicit reconnects exist.
/// Reads can write responses to close_notify and renegotiation requests.
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
    pub(crate) control: Control,
}

// Only alerts (2 bytes) and HelloRequest (4 bytes) are legal after the
// handshake. Keep their cross-record fragments without allocating a queue.
#[derive(Default)]
pub(crate) struct Control {
    kind: u8,
    bytes: [u8; 4],
    filled: usize,
}

impl Control {
    fn consume(&mut self, kind: u8, input: &mut &[u8]) -> Result<Option<[u8; 4]>, Error> {
        if self.filled != 0 && self.kind != kind {
            return Err(Error::Protocol("interleaved TLS control messages"));
        }
        self.kind = kind;
        let size = if kind == 21 { 2 } else { 4 };
        let count = input.len().min(size - self.filled);
        self.bytes[self.filled..self.filled + count].copy_from_slice(&input[..count]);
        self.filled += count;
        *input = &input[count..];
        if self.filled == size {
            self.filled = 0;
            Ok(Some(self.bytes))
        } else {
            Ok(None)
        }
    }
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
            self.flush()?;
            self.sent_close = true;
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
        let mut controls = 0;
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
                23 if self.control.filled != 0 => {
                    return Err(Error::Protocol(
                        "application data interrupts TLS control message",
                    ));
                }
                23 if !plain.is_empty() => {
                    self.plain = plain;
                    continue;
                }
                23 => {}
                21 | 22 if !plain.is_empty() => {
                    let mut input = plain.as_slice();
                    while !input.is_empty() {
                        if let Some(message) = self.control.consume(kind, &mut input)? {
                            match (kind, message) {
                                (21, [1, 0, ..]) => {
                                    self.received_close = true;
                                    self.close()?;
                                    return Ok(0);
                                }
                                (21, [1 | 2, code, ..]) => return Err(Error::Alert(code)),
                                // Decline renegotiation without creating a new transcript.
                                (22, [0, 0, 0, 0]) => {
                                    if self.sent_close {
                                        return Err(Error::Protocol(
                                            "TLS handshake after close_notify",
                                        ));
                                    }
                                    self.send(21, &[1, 100])?;
                                    self.flush()?;
                                }
                                _ => return Err(Error::Protocol("unexpected TLS control message")),
                            }
                            controls += 1;
                            if controls > 32 {
                                return Err(Error::Protocol("too many TLS control messages"));
                            }
                        }
                    }
                }
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
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TLS connection has failed",
            ));
        }
        let result = self.io.flush();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

fn to_io(error: Error) -> io::Error {
    match error {
        Error::Io(err) => err,
        err => io::Error::new(io::ErrorKind::InvalidData, err),
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;

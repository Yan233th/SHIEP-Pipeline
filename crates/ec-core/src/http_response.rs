use std::io::{self, BufRead, ErrorKind, Read};
use std::time::Instant;

const MAX_HEADER_SIZE: usize = 16 * 1024;
const MAX_BODY_SIZE: usize = 8 * 1024 * 1024;

pub(crate) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

// Keep the caller's BufReader across pipelined responses. TLS record boundaries
// and connection closure do not delimit a length-framed HTTP message.
pub(crate) fn read_response(reader: &mut impl BufRead, deadline: Instant) -> io::Result<Response> {
    for _ in 0..16 {
        let mut budget = MAX_HEADER_SIZE;
        let status_line = read_line(reader, &mut budget, deadline)?;
        let mut words = status_line.split_whitespace();
        if !matches!(words.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
            return Err(invalid("invalid HTTP response version"));
        }
        let status = words
            .next()
            .filter(|code| code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|code| code.parse::<u16>().ok())
            .filter(|code| (100..600).contains(code))
            .ok_or_else(|| invalid("invalid HTTP response status"))?;
        let mut length = None;
        let mut chunked = false;
        loop {
            let line = read_line(reader, &mut budget, deadline)?;
            if line.is_empty() {
                break;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| invalid("invalid HTTP response header"))?;
            if name.eq_ignore_ascii_case("content-length") {
                let value = value.trim();
                let size = value
                    .parse::<usize>()
                    .ok()
                    .filter(|_| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
                    .ok_or_else(|| invalid("invalid HTTP Content-Length"))?;
                if length.is_some_and(|previous| previous != size) {
                    return Err(invalid("conflicting HTTP Content-Length headers"));
                }
                length = Some(size);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                    return Err(invalid("unsupported HTTP Transfer-Encoding"));
                }
                chunked = true;
            }
        }
        if chunked && length.is_some() {
            return Err(invalid("conflicting HTTP response framing"));
        }
        if status == 101 {
            return Err(invalid("unexpected HTTP protocol upgrade"));
        }
        if status < 200 {
            continue;
        }
        let mut body = Vec::new();
        if status == 204 || status == 304 {
            return Ok(Response { status, body });
        }
        if chunked {
            loop {
                let mut line_budget = MAX_HEADER_SIZE;
                let line = read_line(reader, &mut line_budget, deadline)?;
                let size = line.split(';').next().unwrap_or_default();
                if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(invalid("invalid HTTP chunk size"));
                }
                let size = usize::from_str_radix(size, 16)
                    .map_err(|_| invalid("invalid HTTP chunk size"))?;
                if size == 0 {
                    let mut trailer_budget = MAX_HEADER_SIZE;
                    while !read_line(reader, &mut trailer_budget, deadline)?.is_empty() {}
                    break;
                }
                read_body(reader, &mut body, Some(size), deadline)?;
                let mut ending = [0; 2];
                reader.read_exact(&mut ending)?;
                if ending != *b"\r\n" {
                    return Err(invalid("invalid HTTP chunk ending"));
                }
            }
        } else {
            read_body(reader, &mut body, length, deadline)?;
        }
        return Ok(Response { status, body });
    }
    Err(invalid("too many informational HTTP responses"))
}

fn read_line(
    reader: &mut impl BufRead,
    budget: &mut usize,
    deadline: Instant,
) -> io::Result<String> {
    check_deadline(deadline)?;
    let mut line = Vec::new();
    let count = reader
        .take((*budget + 1) as u64)
        .read_until(b'\n', &mut line)?;
    if count > *budget {
        return Err(invalid("HTTP response headers too large"));
    }
    *budget -= count;
    if !line.ends_with(b"\r\n") {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "incomplete HTTP response line",
        ));
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|_| invalid("invalid HTTP response header encoding"))
}

fn read_body(
    reader: &mut impl Read,
    body: &mut Vec<u8>,
    length: Option<usize>,
    deadline: Instant,
) -> io::Result<()> {
    if length.is_some_and(|length| length > MAX_BODY_SIZE - body.len()) {
        return Err(invalid("HTTP response body too large"));
    }
    let mut remaining = length;
    let mut buf = [0; 4096];
    while remaining != Some(0) {
        check_deadline(deadline)?;
        let count = remaining.unwrap_or(buf.len()).min(buf.len());
        let count = match reader.read(&mut buf[..count]) {
            Ok(0) if remaining.is_none() => break,
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "incomplete HTTP response body",
                ));
            }
            Ok(count) => count,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if count > MAX_BODY_SIZE - body.len() {
            return Err(invalid("HTTP response body too large"));
        }
        body.extend_from_slice(&buf[..count]);
        if let Some(remaining) = &mut remaining {
            *remaining -= count;
        }
    }
    Ok(())
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            ErrorKind::TimedOut,
            "HTTP response timed out",
        ))
    } else {
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};
    use std::time::Duration;

    struct UncleanEof(Cursor<Vec<u8>>);

    impl Read for UncleanEof {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.0.position() as usize == self.0.get_ref().len() {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "TLS close_notify missing",
                ));
            }
            self.0.read(out)
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    #[test]
    fn complete_length_framed_response_does_not_read_tls_eof() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n<Resource/>";
        for capacity in 1..=response.len() {
            let mut reader =
                BufReader::with_capacity(capacity, UncleanEof(Cursor::new(response.to_vec())));
            let response = read_response(&mut reader, deadline()).unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"<Resource/>");
        }
    }

    #[test]
    fn chunked_response_preserves_pipelined_response_and_skips_interim_headers() {
        let bytes = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;extension=yes\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: value\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
        for capacity in 1..=bytes.len() {
            let mut reader =
                BufReader::with_capacity(capacity, UncleanEof(Cursor::new(bytes.to_vec())));
            let first = read_response(&mut reader, deadline()).unwrap();
            assert_eq!(first.body, b"abcde");
            let second = read_response(&mut reader, deadline()).unwrap();
            assert_eq!(second.status, 204);
            assert!(second.body.is_empty());
        }
    }

    #[test]
    fn missing_length_requires_clean_eof_and_timeouts_never_complete_a_body() {
        let bytes = b"HTTP/1.0 200 OK\r\n\r\nbody";
        assert_eq!(
            read_response(&mut &bytes[..], deadline()).unwrap().body,
            b"body"
        );
        let mut reader = BufReader::new(UncleanEof(Cursor::new(bytes.to_vec())));
        assert_eq!(
            read_response(&mut reader, deadline()).err().unwrap().kind(),
            ErrorKind::UnexpectedEof
        );
        let error = read_response(&mut &bytes[..], Instant::now())
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn every_truncated_length_or_chunk_framed_response_is_rejected() {
        for bytes in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"
                .as_slice(),
        ] {
            for end in 0..bytes.len() {
                assert!(
                    read_response(&mut &bytes[..end], deadline()).is_err(),
                    "end={end}"
                );
            }
        }
    }

    #[test]
    fn invalid_or_ambiguous_framing_is_rejected() {
        for headers in [
            "Content-Length: nope\r\n",
            "Content-Length: +4\r\n",
            "Content-Length: 4\r\nContent-Length: 5\r\n",
            "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: gzip\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            "Missing-Colon\r\n",
            "Content-Length: 9999999999999999999999999999999\r\n",
        ] {
            let bytes = format!("HTTP/1.1 200 OK\r\n{headers}\r\nbody");
            assert!(
                read_response(&mut bytes.as_bytes(), deadline()).is_err(),
                "{headers}"
            );
        }
        for chunks in ["z\r\n", "4\r\nbodyXX", "0\r\n", "800001\r\n"] {
            let bytes = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}");
            assert!(
                read_response(&mut bytes.as_bytes(), deadline()).is_err(),
                "{chunks}"
            );
        }
    }

    #[test]
    fn response_limits_are_checked_before_unbounded_allocation() {
        for bytes in [
            format!(
                "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n",
                "a".repeat(MAX_HEADER_SIZE)
            ),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                MAX_BODY_SIZE + 1
            ),
            "HTTP/1.1 100 Continue\r\n\r\n".repeat(17),
        ] {
            assert!(read_response(&mut bytes.as_bytes(), deadline()).is_err());
        }
    }
}

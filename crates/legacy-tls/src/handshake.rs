use crate::crypto::{Transcript, prf, random};
use crate::{CipherSuite, ClientConfig, Error, TlsStream, Version, record};
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use std::io::{Read, Write};
use subtle::ConstantTimeEq;
use x509_cert::der::{Decode, Encode};
use zeroize::Zeroizing;

const MAX_HANDSHAKE: usize = 1024 * 1024;

pub(crate) fn connect<S: Read + Write>(
    config: &ClientConfig,
    mut io: S,
) -> Result<TlsStream<S>, Error> {
    validate(config)?;
    let mut client_random = [0; 32];
    random(&mut client_random)?;
    let hello = client_hello(config, &client_random)?;
    let mut transcript = Transcript::new();
    transcript.update(&hello);
    record::write(&mut io, 22, config.max_version, &hello)?;
    io.flush()?;

    let mut reader = record::Reader::default();
    let mut messages = Messages::default();
    let hello = messages.next(&mut reader, &mut io, None, None)?;
    let negotiated = server_hello(config, message_body(&hello, 2)?)?;
    transcript.update(&hello);
    let version = negotiated.version;

    let certs = messages.next(&mut reader, &mut io, Some(version), None)?;
    let certificates = certificates(message_body(&certs, 11)?)?;
    config
        .verifier
        .verify(&certificates, config.server_name.as_deref())?;
    let certificate =
        x509_cert::Certificate::from_der(&certificates[0]).map_err(|_| Error::Certificate)?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::Certificate)?;
    let public_key = RsaPublicKey::from_public_key_der(&spki).map_err(|_| Error::Certificate)?;
    if !(2048..=RsaPublicKey::MAX_SIZE).contains(&public_key.n().bits()) {
        return Err(Error::Protocol("unsupported RSA certificate key size"));
    }
    transcript.update(&certs);
    let done = messages.next(&mut reader, &mut io, Some(version), None)?;
    if !message_body(&done, 14)?.is_empty() || !messages.pending.is_empty() {
        return Err(Error::Protocol("invalid ServerHelloDone"));
    }
    transcript.update(&done);

    let mut premaster = Zeroizing::new([0u8; 48]);
    random(premaster.as_mut())?;
    premaster[..2].copy_from_slice(&(config.max_version as u16).to_be_bytes());
    let encrypted = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, premaster.as_ref())
        .map_err(|_| Error::Protocol("RSA key exchange failed"))?;
    let mut exchange = Vec::new();
    vector16(&mut exchange, &encrypted)?;
    let exchange = message(16, &exchange)?;
    transcript.update(&exchange);
    record::write(&mut io, 22, version, &exchange)?;

    let mut master = Zeroizing::new([0u8; 48]);
    if negotiated.ems {
        prf(
            version,
            premaster.as_ref(),
            b"extended master secret",
            &transcript.hash(version),
            master.as_mut(),
        );
    } else {
        let mut seed = client_random.to_vec();
        seed.extend_from_slice(&negotiated.random);
        prf(
            version,
            premaster.as_ref(),
            b"master secret",
            &seed,
            master.as_mut(),
        );
    }
    let key_len = negotiated.suite.key_len();
    let mut key_block = Zeroizing::new(vec![0; 40 + 2 * key_len]);
    let mut seed = negotiated.random.to_vec();
    seed.extend_from_slice(&client_random);
    prf(
        version,
        master.as_ref(),
        b"key expansion",
        &seed,
        &mut key_block,
    );
    let mut write_keys = record::Keys::new(
        negotiated.suite,
        &key_block[40..40 + key_len],
        &key_block[..20],
        negotiated.etm,
    );
    let mut read_keys = record::Keys::new(
        negotiated.suite,
        &key_block[40 + key_len..],
        &key_block[20..40],
        negotiated.etm,
    );

    record::write(&mut io, 20, version, &[1])?;
    let mut verify = Zeroizing::new([0; 12]);
    prf(
        version,
        master.as_ref(),
        b"client finished",
        &transcript.hash(version),
        verify.as_mut(),
    );
    let finished = message(20, verify.as_ref())?;
    let encrypted = write_keys.seal(22, version, &finished)?;
    record::write(&mut io, 22, version, &encrypted)?;
    transcript.update(&finished);
    io.flush()?;

    let (kind, record_version, ccs) = reader.read(&mut io)?;
    if kind == 21 {
        return Err(alert(&ccs));
    }
    if kind != 20 || record_version != version as u16 || ccs != [1] {
        return Err(Error::Protocol("expected TLS ChangeCipherSpec"));
    }
    let finished = messages.next(&mut reader, &mut io, Some(version), Some(&mut read_keys))?;
    let body = message_body(&finished, 20)?;
    prf(
        version,
        master.as_ref(),
        b"server finished",
        &transcript.hash(version),
        verify.as_mut(),
    );
    if !bool::from(verify.as_slice().ct_eq(body)) || !messages.pending.is_empty() {
        return Err(Error::Protocol("TLS Finished verification failed"));
    }

    Ok(TlsStream {
        io,
        reader,
        read_keys,
        write_keys,
        version,
        suite: negotiated.suite,
        session_id: negotiated.session_id,
        extended_master_secret: negotiated.ems,
        encrypt_then_mac: negotiated.etm,
        plain: Zeroizing::new(Vec::new()),
        offset: 0,
        received_close: false,
        sent_close: false,
        failed: false,
    })
}

fn validate(config: &ClientConfig) -> Result<(), Error> {
    if config.min_version > config.max_version {
        return Err(Error::Protocol("invalid TLS version range"));
    }
    if config.session_id.len() > 32 {
        return Err(Error::Protocol("TLS session identifier exceeds 32 bytes"));
    }
    if config.cipher_suites.is_empty() || config.cipher_suites.len() > 2 {
        return Err(Error::Protocol("invalid TLS cipher list"));
    }
    if let Some(name) = &config.server_name {
        if name.is_empty()
            || name.len() > 253
            || name.parse::<std::net::IpAddr>().is_ok()
            || !name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(Error::Protocol("invalid TLS server name"));
        }
    }
    Ok(())
}

fn client_hello(config: &ClientConfig, random: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    body.extend_from_slice(&(config.max_version as u16).to_be_bytes());
    body.extend_from_slice(random);
    body.push(config.session_id.len() as u8);
    body.extend_from_slice(&config.session_id);
    let ciphers: Vec<u8> = config
        .cipher_suites
        .iter()
        .flat_map(|suite| (*suite as u16).to_be_bytes())
        .collect();
    vector16(&mut body, &ciphers)?;
    body.extend_from_slice(&[1, 0]);
    let mut extensions = Vec::new();
    extension(&mut extensions, 0xff01, &[0])?;
    extension(&mut extensions, 23, &[])?;
    if config.encrypt_then_mac {
        extension(&mut extensions, 22, &[])?;
    }
    if config.max_version == Version::Tls12 {
        extension(&mut extensions, 13, &[0, 6, 4, 1, 5, 1, 2, 1])?;
    }
    if let Some(name) = &config.server_name {
        let mut item = vec![0];
        vector16(&mut item, name.as_bytes())?;
        let mut names = Vec::new();
        vector16(&mut names, &item)?;
        extension(&mut extensions, 0, &names)?;
    }
    vector16(&mut body, &extensions)?;
    message(1, &body)
}

struct Negotiated {
    version: Version,
    random: [u8; 32],
    session_id: Vec<u8>,
    suite: CipherSuite,
    ems: bool,
    etm: bool,
}

fn server_hello(config: &ClientConfig, body: &[u8]) -> Result<Negotiated, Error> {
    let mut cursor = Cursor(body);
    let version = match cursor.u16()? {
        0x0302 => Version::Tls11,
        0x0303 => Version::Tls12,
        _ => return Err(Error::Protocol("unsupported TLS version")),
    };
    if version < config.min_version || version > config.max_version {
        return Err(Error::Protocol("TLS version outside configured range"));
    }
    let random = cursor.take(32)?.try_into().expect("server random length");
    let id_len = cursor.u8()? as usize;
    if id_len > 32 {
        return Err(Error::Protocol("invalid server session identifier"));
    }
    let session_id = cursor.take(id_len)?.to_vec();
    if !session_id.is_empty() && session_id == config.session_id {
        return Err(Error::Protocol("TLS session resumption is unsupported"));
    }
    let suite = match cursor.u16()? {
        0x002f => CipherSuite::Aes128Sha,
        0x0035 => CipherSuite::Aes256Sha,
        _ => return Err(Error::Protocol("unsupported TLS cipher")),
    };
    if !config.cipher_suites.contains(&suite) {
        return Err(Error::Protocol("server selected an unoffered cipher"));
    }
    if cursor.u8()? != 0 {
        return Err(Error::Protocol("TLS compression is unsupported"));
    }
    let mut ems = false;
    let mut etm = false;
    if !cursor.0.is_empty() {
        let mut extensions = Cursor(cursor.vector16()?);
        cursor.end()?;
        let mut seen = Vec::new();
        while !extensions.0.is_empty() {
            let kind = extensions.u16()?;
            let value = extensions.vector16()?;
            if seen.contains(&kind) {
                return Err(Error::Protocol("duplicate TLS extension"));
            }
            seen.push(kind);
            match kind {
                0xff01 if value == [0] => {}
                23 if value.is_empty() => ems = true,
                22 if value.is_empty() && config.encrypt_then_mac => etm = true,
                0 if value.is_empty() && config.server_name.is_some() => {}
                _ => return Err(Error::Protocol("invalid or unsolicited TLS extension")),
            }
        }
    }
    if config.require_extended_master_secret && !ems {
        return Err(Error::Protocol("extended master secret required"));
    }
    Ok(Negotiated {
        version,
        random,
        session_id,
        suite,
        ems,
        etm,
    })
}

fn certificates(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut outer = Cursor(body);
    let mut cursor = Cursor(outer.vector24()?);
    outer.end()?;
    let mut chain = Vec::new();
    while !cursor.0.is_empty() {
        if chain.len() >= 16 {
            return Err(Error::Protocol("TLS certificate chain too long"));
        }
        let cert = cursor.vector24()?;
        if cert.is_empty() {
            return Err(Error::Certificate);
        }
        chain.push(cert.to_vec());
    }
    if chain.is_empty() {
        return Err(Error::Certificate);
    }
    Ok(chain)
}

#[derive(Default)]
struct Messages {
    pending: Vec<u8>,
    total: usize,
}

impl Messages {
    fn next<S: Read>(
        &mut self,
        reader: &mut record::Reader,
        io: &mut S,
        version: Option<Version>,
        mut keys: Option<&mut record::Keys>,
    ) -> Result<Vec<u8>, Error> {
        let mut empty = 0;
        loop {
            if self.pending.len() >= 4 {
                let len = u32::from_be_bytes([0, self.pending[1], self.pending[2], self.pending[3]])
                    as usize;
                if len > MAX_HANDSHAKE {
                    return Err(Error::Protocol("TLS handshake message too large"));
                }
                if self.pending.len() >= len + 4 {
                    return Ok(self.pending.drain(..len + 4).collect());
                }
            }
            let (kind, wire_version, body) = reader.read(io)?;
            if version.is_some_and(|version| version as u16 != wire_version) {
                return Err(Error::Protocol("TLS record version changed"));
            }
            let plain = if let Some(keys) = keys.as_mut() {
                keys.open(
                    kind,
                    version.expect("encrypted record has a negotiated version"),
                    &body,
                )?
            } else {
                if body.len() > record::MAX_PLAINTEXT {
                    return Err(Error::Protocol("TLS plaintext too large"));
                }
                Zeroizing::new(body)
            };
            if kind == 21 {
                return Err(alert(&plain));
            }
            if kind != 22 {
                return Err(Error::Protocol("unexpected TLS handshake record"));
            }
            self.total += plain.len();
            if self.total > 4 * MAX_HANDSHAKE {
                return Err(Error::Protocol("TLS handshake too large"));
            }
            if plain.is_empty() {
                empty += 1;
            }
            if empty > 32 {
                return Err(Error::Protocol("too many empty TLS records"));
            }
            self.pending.extend_from_slice(&plain);
        }
    }
}

fn alert(body: &[u8]) -> Error {
    if body.len() == 2 {
        Error::Alert(body[1])
    } else {
        Error::Protocol("invalid TLS alert")
    }
}

fn message_body(message: &[u8], expected: u8) -> Result<&[u8], Error> {
    if message.first() != Some(&expected) {
        return Err(Error::Protocol("unexpected TLS handshake message"));
    }
    Ok(&message[4..])
}

fn message(kind: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > MAX_HANDSHAKE {
        return Err(Error::Protocol("TLS handshake message too large"));
    }
    let mut result = Vec::with_capacity(body.len() + 4);
    result.push(kind);
    result.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    result.extend_from_slice(body);
    Ok(result)
}

fn extension(out: &mut Vec<u8>, kind: u16, value: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(&kind.to_be_bytes());
    vector16(out, value)
}

fn vector16(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::Protocol("TLS vector too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.0.len() {
            return Err(Error::Protocol("truncated TLS message"));
        }
        let (taken, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(taken)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("u16 length"),
        ))
    }
    fn vector16(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u16()?;
        self.take(len as usize)
    }
    fn vector24(&mut self) -> Result<&'a [u8], Error> {
        let len = self.take(3)?;
        let len = u32::from_be_bytes([0, len[0], len[1], len[2]]) as usize;
        self.take(len)
    }
    fn end(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol("trailing TLS message data"))
        }
    }
}

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod tests;

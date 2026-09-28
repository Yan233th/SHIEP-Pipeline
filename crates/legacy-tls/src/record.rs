use crate::crypto::{check_padding, random, record_mac, verify_cbc_mac};
use crate::{CipherSuite, Error, Version};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use std::io::{Read, Write};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const MAX_PLAINTEXT: usize = 16_384;
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 2048;

enum Cipher {
    Aes128(Box<Aes128>),
    Aes256(Box<Aes256>),
}

pub(crate) struct Keys {
    cipher: Cipher,
    mac: Zeroizing<[u8; 20]>,
    sequence: u64,
    etm: bool,
}

impl Keys {
    pub(crate) fn new(suite: CipherSuite, key: &[u8], mac: &[u8], etm: bool) -> Self {
        let cipher = match suite {
            CipherSuite::Aes128Sha => Cipher::Aes128(Box::new(
                Aes128::new_from_slice(key).expect("AES128 key length"),
            )),
            CipherSuite::Aes256Sha => Cipher::Aes256(Box::new(
                Aes256::new_from_slice(key).expect("AES256 key length"),
            )),
        };
        Self {
            cipher,
            mac: Zeroizing::new(mac.try_into().expect("SHA1 MAC key length")),
            sequence: 0,
            etm,
        }
    }

    fn next_sequence(&mut self) -> Result<u64, Error> {
        let current = self.sequence;
        self.sequence = current
            .checked_add(1)
            .ok_or(Error::Protocol("TLS record sequence exhausted"))?;
        Ok(current)
    }

    pub(crate) fn seal(
        &mut self,
        kind: u8,
        version: Version,
        plain: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if plain.len() > MAX_PLAINTEXT {
            return Err(Error::Protocol("TLS plaintext too large"));
        }
        let seq = self.next_sequence()?;
        let mut body = Zeroizing::new(plain.to_vec());
        if !self.etm {
            body.extend_from_slice(&record_mac(self.mac.as_ref(), seq, kind, version, plain));
        }
        let padding = 15 - body.len() % 16;
        let padded_len = body.len() + padding + 1;
        body.resize(padded_len, padding as u8);
        let mut iv = [0; 16];
        random(&mut iv)?;
        let mut result = Vec::with_capacity(16 + body.len() + 20);
        result.extend_from_slice(&iv);
        for chunk in body.chunks_exact_mut(16) {
            for (byte, previous) in chunk.iter_mut().zip(iv) {
                *byte ^= previous;
            }
            let block = aes::cipher::Block::<Aes128>::from_mut_slice(chunk);
            match &self.cipher {
                Cipher::Aes128(cipher) => cipher.encrypt_block(block),
                Cipher::Aes256(cipher) => cipher.encrypt_block(block),
            }
            iv.copy_from_slice(chunk);
            result.extend_from_slice(chunk);
        }
        if self.etm {
            let mac = record_mac(self.mac.as_ref(), seq, kind, version, &result);
            result.extend_from_slice(&mac);
        }
        Ok(result)
    }

    pub(crate) fn open(
        &mut self,
        kind: u8,
        version: Version,
        wire: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let seq = self.next_sequence()?;
        let encrypted = if self.etm {
            if wire.len() < 52 {
                return Err(Error::BadRecordMac);
            }
            let (body, mac) = wire.split_at(wire.len() - 20);
            let expected = record_mac(self.mac.as_ref(), seq, kind, version, body);
            if !bool::from(expected.ct_eq(mac)) {
                return Err(Error::BadRecordMac);
            }
            body
        } else {
            wire
        };
        if encrypted.len() < 32 || encrypted.len() % 16 != 0 {
            return Err(Error::BadRecordMac);
        }
        let mut iv: [u8; 16] = encrypted[..16].try_into().expect("IV length");
        let mut body = Zeroizing::new(encrypted[16..].to_vec());
        for chunk in body.chunks_exact_mut(16) {
            let next: [u8; 16] = chunk.try_into().expect("CBC block length");
            let block = aes::cipher::Block::<Aes128>::from_mut_slice(chunk);
            match &self.cipher {
                Cipher::Aes128(cipher) => cipher.decrypt_block(block),
                Cipher::Aes256(cipher) => cipher.decrypt_block(block),
            }
            for (byte, previous) in chunk.iter_mut().zip(iv) {
                *byte ^= previous;
            }
            iv = next;
        }
        let content_len = if self.etm {
            let (count, valid) = check_padding(&body);
            if !bool::from(valid) {
                return Err(Error::BadRecordMac);
            }
            body.len() - count
        } else {
            verify_cbc_mac(&self.mac, seq, kind, version, &body)?
        };
        if content_len > MAX_PLAINTEXT {
            return Err(Error::Protocol("TLS plaintext too large"));
        }
        body.truncate(content_len);
        Ok(body)
    }
}

#[derive(Default)]
pub(crate) struct Reader {
    header: [u8; 5],
    header_read: usize,
    body: Vec<u8>,
    body_read: usize,
}

impl Reader {
    // Preserve the exact record position when a blocking read times out. A
    // resumed read must not mistake the remaining ciphertext for a new header.
    pub(crate) fn read<S: Read>(&mut self, io: &mut S) -> Result<(u8, u16, Vec<u8>), Error> {
        fill(io, &mut self.header, &mut self.header_read)?;
        let version = u16::from_be_bytes([self.header[1], self.header[2]]);
        if !(0x0301..=0x0303).contains(&version) {
            return Err(Error::Protocol("invalid TLS record version"));
        }
        let len = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
        if len > MAX_CIPHERTEXT {
            return Err(Error::Protocol("TLS record too large"));
        }
        self.body.resize(len, 0);
        fill(io, &mut self.body, &mut self.body_read)?;
        let kind = self.header[0];
        self.header_read = 0;
        self.body_read = 0;
        Ok((kind, version, std::mem::take(&mut self.body)))
    }
}

fn fill<S: Read>(io: &mut S, out: &mut [u8], filled: &mut usize) -> Result<(), Error> {
    while *filled < out.len() {
        match io.read(&mut out[*filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "TLS transport closed without close_notify",
                )
                .into());
            }
            Ok(n) => *filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

pub(crate) fn write<S: Write>(
    io: &mut S,
    kind: u8,
    version: Version,
    body: &[u8],
) -> Result<(), Error> {
    let len = u16::try_from(body.len()).map_err(|_| Error::Protocol("TLS record too large"))?;
    let version = (version as u16).to_be_bytes();
    let len = len.to_be_bytes();
    let mut wire = Vec::with_capacity(5 + body.len());
    wire.extend_from_slice(&[kind, version[0], version[1], len[0], len[1]]);
    wire.extend_from_slice(body);
    io.write_all(&wire)?;
    Ok(())
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;

use crate::{Error, Version};
use hmac::{Hmac, Mac};
use md5::Md5;
use rsa::rand_core::{OsRng, RngCore};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn random(bytes: &mut [u8]) -> Result<(), Error> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|_| Error::Protocol("OS randomness unavailable"))
}

macro_rules! p_hash {
    ($name:ident, $hash:ty) => {
        fn $name(secret: &[u8], seed: &[u8], out: &mut [u8]) {
            let base = Hmac::<$hash>::new_from_slice(secret).expect("HMAC accepts any key length");
            let mut mac = base.clone();
            mac.update(seed);
            let mut a = mac.finalize().into_bytes();
            for chunk in out.chunks_mut(a.len()) {
                let mut mac = base.clone();
                mac.update(&a);
                mac.update(seed);
                let mut block = mac.finalize().into_bytes();
                chunk.copy_from_slice(&block[..chunk.len()]);
                block.as_mut_slice().zeroize();
                let mut mac = base.clone();
                mac.update(&a);
                a = mac.finalize().into_bytes();
            }
            a.as_mut_slice().zeroize();
        }
    };
}

p_hash!(p_md5, Md5);
p_hash!(p_sha1, Sha1);
p_hash!(p_sha256, Sha256);

pub(crate) fn prf(version: Version, secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    let mut input = Zeroizing::new(Vec::with_capacity(label.len() + seed.len()));
    input.extend_from_slice(label);
    input.extend_from_slice(seed);
    match version {
        Version::Tls12 => p_sha256(secret, &input, out),
        Version::Tls11 => {
            let half = secret.len().div_ceil(2);
            p_md5(&secret[..half], &input, out);
            let mut sha = Zeroizing::new(vec![0; out.len()]);
            p_sha1(&secret[secret.len() - half..], &input, &mut sha);
            for (dst, other) in out.iter_mut().zip(sha.iter()) {
                *dst ^= other;
            }
        }
    }
}

pub(crate) struct Transcript {
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
}

impl Transcript {
    pub(crate) fn new() -> Self {
        Self {
            md5: Md5::new(),
            sha1: Sha1::new(),
            sha256: Sha256::new(),
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.md5.update(bytes);
        self.sha1.update(bytes);
        self.sha256.update(bytes);
    }

    pub(crate) fn hash(&self, version: Version) -> Vec<u8> {
        match version {
            Version::Tls11 => {
                let mut hash = self.md5.clone().finalize().to_vec();
                hash.extend_from_slice(&self.sha1.clone().finalize());
                hash
            }
            Version::Tls12 => self.sha256.clone().finalize().to_vec(),
        }
    }
}

pub(crate) fn record_mac(
    key: &[u8],
    seq: u64,
    kind: u8,
    version: Version,
    data: &[u8],
) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&header(seq, kind, version, data.len()));
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn header(seq: u64, kind: u8, version: Version, len: usize) -> [u8; 13] {
    let mut header = [0; 13];
    header[..8].copy_from_slice(&seq.to_be_bytes());
    header[8] = kind;
    header[9..11].copy_from_slice(&(version as u16).to_be_bytes());
    header[11..].copy_from_slice(&(len as u16).to_be_bytes());
    header
}

const SHA1_INITIAL: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

#[cfg(test)]
std::thread_local! {
    static COMPRESSIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    #[cfg(test)]
    COMPRESSIONS.with(|count| count.set(count.get() + 1));
    sha1::compress(state, &[(*block).into()]);
}

fn ct_lt(a: usize, b: usize) -> Choice {
    (a as u64).ct_lt(&(b as u64))
}

// SHA-1 HMAC with a hidden content length. Every read address, loop bound and
// compression count depends only on the public record size. Select the inner
// digest at the true end without indexing or slicing by the padding length.
fn hidden_length_mac(key: &[u8; 20], header: &[u8; 13], data: &[u8], len: usize) -> [u8; 20] {
    let mut state = Zeroizing::new(SHA1_INITIAL);
    let mut block = Zeroizing::new([0x36; 64]);
    for (dst, key) in block.iter_mut().zip(key) {
        *dst ^= key;
    }
    compress(&mut state, &block);

    let min_len = data.len().saturating_sub(276);
    let max_len = data.len() - 21;
    let end = 13 + len;
    let final_block = (end + 8) / 64;
    let encoded_len = ((64 + end) as u64 * 8).to_be_bytes();
    let mut selected = Zeroizing::new([0u32; 5]);
    for block_index in 0..=(13 + max_len + 8) / 64 {
        let base = block_index * 64;
        for (offset, dst) in block.iter_mut().enumerate() {
            let pos = base + offset;
            let byte = if pos < 13 {
                header[pos]
            } else {
                data.get(pos - 13).copied().unwrap_or(0)
            };
            let mut value = u8::conditional_select(&0, &byte, ct_lt(pos, end));
            value |= u8::conditional_select(&0, &0x80, pos.ct_eq(&end));
            if offset >= 56 {
                value |= u8::conditional_select(
                    &0,
                    &encoded_len[offset - 56],
                    block_index.ct_eq(&final_block),
                );
            }
            *dst = value;
        }
        compress(&mut state, &block);
        // The lower bound is public, and avoids needless selections over the
        // long prefix that is certainly application data.
        if block_index >= (13 + min_len + 8) / 64 {
            for (dst, word) in selected.iter_mut().zip(state.iter()) {
                *dst = u32::conditional_select(dst, word, block_index.ct_eq(&final_block));
            }
        }
    }

    *state = SHA1_INITIAL;
    block.fill(0x5c);
    for (dst, key) in block.iter_mut().zip(key) {
        *dst ^= key;
    }
    compress(&mut state, &block);
    block.fill(0);
    for (chunk, word) in block[..20].chunks_exact_mut(4).zip(selected.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    block[20] = 0x80;
    block[56..].copy_from_slice(&(84u64 * 8).to_be_bytes());
    compress(&mut state, &block);
    let mut result = [0; 20];
    for (chunk, word) in result.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    result
}

pub(crate) fn check_padding(data: &[u8]) -> (usize, Choice) {
    let padding = *data.last().expect("nonempty decrypted CBC record");
    let count = usize::from(padding) + 1;
    let mut valid = !ct_lt(data.len(), count);
    for offset in 0..data.len().min(256) {
        valid &= !ct_lt(offset, count) | data[data.len() - 1 - offset].ct_eq(&padding);
    }
    (count, valid)
}

pub(crate) fn verify_cbc_mac(
    key: &[u8; 20],
    seq: u64,
    kind: u8,
    version: Version,
    data: &[u8],
) -> Result<usize, Error> {
    if data.len() < 32 {
        return Err(Error::BadRecordMac);
    }
    let (padding, mut valid) = check_padding(data);
    valid &= !ct_lt(data.len(), 20 + padding);
    let candidate = data.len().wrapping_sub(20 + padding);
    let len = u64::conditional_select(&0, &(candidate as u64), valid) as usize;
    let mut expected = hidden_length_mac(key, &header(seq, kind, version, len), data, len);
    let mut received = [0; 20];
    for pos in data.len().saturating_sub(276)..data.len() - 20 {
        let take = pos.ct_eq(&len);
        for (offset, dst) in received.iter_mut().enumerate() {
            *dst |= u8::conditional_select(&0, &data[pos + offset], take);
        }
    }
    valid &= expected.ct_eq(&received);
    expected.zeroize();
    received.zeroize();
    if bool::from(valid) {
        Ok(len)
    } else {
        Err(Error::BadRecordMac)
    }
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;

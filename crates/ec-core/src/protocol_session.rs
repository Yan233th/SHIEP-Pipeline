use crate::error::{EcError, EcResult};
use der::asn1::{AnyRef, ContextSpecific, OctetStringRef};
use der::{Encode, Tag, TagMode, TagNumber};
use openssl::ssl::{Ssl, SslSession};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn apply_l3ip_session_id(ssl: &mut Ssl, session_version: u16) -> EcResult<()> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EcError::Runtime(format!("read session creation time failed: {e}")))?
        .as_secs();
    let mut master_key = [0u8; 48];
    openssl::rand::rand_bytes(&mut master_key)
        .map_err(|e| EcError::Runtime(format!("generate l3ip session secret failed: {e}")))?;
    let encoded = l3ip_session_der(session_version, time, &master_key)
        .map_err(|e| EcError::Runtime(format!("encode l3ip session failed: {e}")))?;
    let session = SslSession::from_der(&encoded)
        .map_err(|e| EcError::Runtime(format!("import l3ip session failed: {e}")))?;

    // This synthetic session only carries the L3IP marker, never a shared secret.
    // It belongs exclusively to this connection; SSL retains its own reference.
    unsafe {
        ssl.set_session(&session)
            .map_err(|e| EcError::Runtime(format!("SSL_set_session failed: {e}")))?;
    }
    Ok(())
}

fn l3ip_session_der(version: u16, time: u64, master_key: &[u8; 48]) -> der::Result<Vec<u8>> {
    // AWS-LC's SSLSession schema (ssl/ssl_asn1.cc). A client session must have
    // a valid cipher, creation time, timeout and isServer=false to reach the wire.
    let mut fields = Vec::with_capacity(128);
    1u8.encode_to_vec(&mut fields)?;
    version.encode_to_vec(&mut fields)?;
    OctetStringRef::new(&[0x00, 0x2f])?.encode_to_vec(&mut fields)?; // AES128-SHA
    OctetStringRef::new(&l3ip_session_id())?.encode_to_vec(&mut fields)?;
    OctetStringRef::new(master_key)?.encode_to_vec(&mut fields)?;
    ContextSpecific {
        tag_number: TagNumber::N1,
        tag_mode: TagMode::Explicit,
        value: time,
    }
    .encode_to_vec(&mut fields)?;
    ContextSpecific {
        tag_number: TagNumber::N2,
        tag_mode: TagMode::Explicit,
        value: 300u16,
    }
    .encode_to_vec(&mut fields)?;
    ContextSpecific {
        tag_number: TagNumber::N22,
        tag_mode: TagMode::Explicit,
        value: false,
    }
    .encode_to_vec(&mut fields)?;
    AnyRef::new(Tag::Sequence, &fields)?.to_der()
}

fn l3ip_session_id() -> [u8; 32] {
    let mut sid = [0u8; 32];
    sid[0] = b'L';
    sid[1] = b'3';
    sid[2] = b'I';
    sid[3] = b'P';
    sid
}

#[cfg(test)]
mod tests {
    use super::{apply_l3ip_session_id, l3ip_session_id};
    use openssl::ssl::{Ssl, SslContext, SslMethod};

    #[test]
    fn imported_session_retains_l3ip_fields_after_installation_and_replacement() {
        let context = SslContext::builder(SslMethod::tls_client())
            .unwrap()
            .build();
        let mut ssl = Ssl::new(&context).unwrap();
        apply_l3ip_session_id(&mut ssl, 0x0303).unwrap();
        let retained = ssl.session().unwrap().to_owned();
        assert_eq!(retained.id(), l3ip_session_id());
        assert_eq!(retained.master_key_len(), 48);
        let mut master_key = [0u8; 48];
        assert_eq!(retained.master_key(&mut master_key), master_key.len());
        assert_ne!(master_key, [0; 48]);
        let original_key = master_key;

        apply_l3ip_session_id(&mut ssl, 0x0302).unwrap();
        assert_eq!(ssl.session().unwrap().id(), l3ip_session_id());
        ssl.session().unwrap().master_key(&mut master_key);
        assert_ne!(master_key, original_key);
        drop(ssl);
        assert_eq!(retained.master_key(&mut master_key), master_key.len());
        assert_eq!(master_key, original_key);
    }
}

use crate::error::{EcError, EcResult};
use foreign_types::ForeignType;
use openssl::error::ErrorStack;
use openssl::ssl::{Ssl, SslSession};
use openssl_sys as ffi;
use std::ffi::c_uint;

unsafe extern "C" {
    fn SSL_SESSION_new() -> *mut ffi::SSL_SESSION;
    fn SSL_SESSION_set_protocol_version(session: *mut ffi::SSL_SESSION, version: i32) -> i32;
    fn SSL_SESSION_set1_master_key(
        session: *mut ffi::SSL_SESSION,
        key: *const u8,
        len: usize,
    ) -> i32;
    fn SSL_SESSION_set1_id(session: *mut ffi::SSL_SESSION, sid: *const u8, len: c_uint) -> i32;
}

pub(crate) fn apply_l3ip_session_id(ssl: &mut Ssl, session_version: i32) -> EcResult<()> {
    let sid = l3ip_session_id();
    let master_key = l3ip_master_key();
    unsafe {
        let session = SSL_SESSION_new();
        if session.is_null() {
            return Err(EcError::Runtime(format!(
                "create SSL_SESSION failed: {}",
                ErrorStack::get()
            )));
        }
        // Own the fresh allocation so every early return releases it exactly once.
        let session = SslSession::from_ptr(session);

        let set_proto_rc = SSL_SESSION_set_protocol_version(session.as_ptr(), session_version);
        if set_proto_rc != 1 {
            return Err(EcError::Runtime(format!(
                "SSL_SESSION_set_protocol_version failed: {}",
                ErrorStack::get()
            )));
        }

        let set_master_rc =
            SSL_SESSION_set1_master_key(session.as_ptr(), master_key.as_ptr(), master_key.len());
        if set_master_rc != 1 {
            return Err(EcError::Runtime(format!(
                "SSL_SESSION_set1_master_key failed: {}",
                ErrorStack::get()
            )));
        }

        let set_id_rc = SSL_SESSION_set1_id(session.as_ptr(), sid.as_ptr(), sid.len() as c_uint);
        if set_id_rc != 1 {
            return Err(EcError::Runtime(format!(
                "SSL_SESSION_set1_id failed: {}",
                ErrorStack::get()
            )));
        }

        // This session is not shared with another SSL context; SSL retains its own reference.
        ssl.set_session(&session)
            .map_err(|e| EcError::Runtime(format!("SSL_set_session failed: {e}")))?;
    }
    Ok(())
}

fn l3ip_session_id() -> [u8; 32] {
    let mut sid = [0u8; 32];
    sid[0] = b'L';
    sid[1] = b'3';
    sid[2] = b'I';
    sid[3] = b'P';
    sid
}

fn l3ip_master_key() -> [u8; 48] {
    let mut key = [0u8; 48];
    for (i, v) in key.iter_mut().enumerate() {
        *v = ((i as u8) ^ 0x5a).wrapping_add(0x11);
    }
    key
}

#[cfg(test)]
mod tests {
    use super::{apply_l3ip_session_id, l3ip_master_key, l3ip_session_id};
    use openssl::ssl::{Ssl, SslContext, SslMethod, SslVersion};

    #[test]
    fn native_session_retains_l3ip_fields_after_installation_and_replacement() {
        let context = SslContext::builder(SslMethod::tls_client())
            .unwrap()
            .build();
        let mut ssl = Ssl::new(&context).unwrap();
        apply_l3ip_session_id(&mut ssl, 0x0303).unwrap();
        let retained = ssl.session().unwrap().to_owned();
        assert_eq!(retained.id(), l3ip_session_id());
        assert_eq!(retained.protocol_version(), SslVersion::TLS1_2);
        assert_eq!(retained.master_key_len(), 48);
        let mut master_key = [0u8; 48];
        assert_eq!(retained.master_key(&mut master_key), master_key.len());
        assert_eq!(master_key, l3ip_master_key());

        apply_l3ip_session_id(&mut ssl, 0x0302).unwrap();
        assert_eq!(
            ssl.session().unwrap().protocol_version(),
            SslVersion::TLS1_1
        );
        assert_eq!(ssl.session().unwrap().id(), l3ip_session_id());
        drop(ssl);
        assert_eq!(retained.protocol_version(), SslVersion::TLS1_2);
        assert_eq!(retained.master_key(&mut master_key), master_key.len());
        assert_eq!(master_key, l3ip_master_key());
    }
}

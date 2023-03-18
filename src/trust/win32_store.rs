use windows::core::*;
use windows::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertCloseStore, CertOpenSystemStoreW,
    CERT_STORE_ADD_USE_EXISTING, HCERTSTORE, HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING,
};

use crate::certgen::Certificate;
use crate::error::AppResult;

pub struct TrustStore {
    store: HCERTSTORE,
}

impl TrustStore {
    pub fn open() -> AppResult<Self> {
        let root_store = unsafe { CertOpenSystemStoreW(HCRYPTPROV_LEGACY::default(), w!("ROOT")) }?;
        Ok(Self { store: root_store })
    }

    pub fn install(&self, cert: &Certificate) -> AppResult<bool> {
        assert!(matches!(cert, Certificate::RootCertificate(_)));
        let cert_der = cert.cert_der()?;

        let result = unsafe {
            CertAddEncodedCertificateToStore(
                self.store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                &cert_der,
                CERT_STORE_ADD_USE_EXISTING,
                None,
            );
        };

        Ok(result)
    }
}

impl Drop for TrustStore {
    fn drop(&mut self) {
        unsafe {
            CertCloseStore(self.store, 0);
        }
    }
}

use crate::{certgen::Certificate, error::AppResult};
use std::path::{Path, PathBuf};

pub struct CertStore {
    path: PathBuf,
}

impl CertStore {
    pub const DEFAULT_PROFILE: &str = "default";
    pub const ROOT_CERT_NAME: &str = "__devcert_root";

    pub fn new(root: &Path, profile: &str) -> AppResult<Self> {
        use std::fs;

        let path = {
            let mut buf: PathBuf = root.into();
            buf.push(format!("stores/{}", profile));
            buf
        };

        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn root_cert(&self) -> AppResult<Certificate> {
        use std::fs;

        let cert_pem = fs::read_to_string({
            let mut root_cert_path = self.path.clone();
            root_cert_path.push(format!("{}.pem", Self::ROOT_CERT_NAME));
            root_cert_path
        })?;

        let key_pem = fs::read_to_string({
            let mut root_key_path = self.path.clone();
            root_key_path.push(format!("{}.key.pem", Self::ROOT_CERT_NAME));
            root_key_path
        })?;

        use rcgen::{CertificateParams, KeyPair};
        let params = CertificateParams::from_ca_cert_pem(&cert_pem, KeyPair::from_pem(&key_pem)?)?;
        Ok(Certificate::RootCertificate(
            rcgen::Certificate::from_params(params)?,
        ))
    }

    pub fn add(&self, cert: &Certificate) -> AppResult<()> {
        use std::fs;

        fs::write(
            {
                let mut path = self.path.clone();
                path.push(format!("{}.pem", cert.name()));
                println!("{}", path.display());
                path
            },
            cert.cert_pem()?,
        )?;

        fs::write(
            {
                let mut path = self.path.clone();
                path.push(format!("{}.key.pem", cert.name()));
                println!("{}", path.display());
                path
            },
            cert.key_pem(),
        )?;

        Ok(())
    }
}

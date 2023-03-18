use crate::{certgen::Certificate, error::AppResult};
use std::path::{Path, PathBuf};

pub struct CertStore {
    path: PathBuf,
}

impl CertStore {
    pub const DEFAULT_PROFILE: &str = "default";
    const ROOT_CERT_NAME: &str = "root.pem";
    const ROOT_KEY_NAME: &str = "root.key.pem";

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

    pub fn add(&self, cert: impl Certificate) -> AppResult<()> {
        if cert.is_root_cert() {
            use std::fs;

            fs::write(
                {
                    let mut path = self.path.clone();
                    path.push(Self::ROOT_CERT_NAME);
                    path
                },
                cert.cert_pem()?,
            )?;

            fs::write(
                {
                    let mut path = self.path.clone();
                    path.push(Self::ROOT_KEY_NAME);
                    path
                },
                cert.key_pem(),
            )?;
        }

        Ok(())
    }
}

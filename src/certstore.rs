use std::path::PathBuf;

use directories::BaseDirs;

use crate::{
    certgen::Certificate,
    error::{AppResult, DevcertError},
};

pub struct CertStore {
    path: PathBuf,
}

impl CertStore {
    const DEFAULT_NAME: &str = "default";
    const ROOT_CERT_NAME: &str = "root.pem";
    const ROOT_KEY_NAME: &str = "root.key.pem";

    pub fn try_default() -> AppResult<Self> {
        Self::new(Self::DEFAULT_NAME.to_owned())
    }

    pub fn new(name: String) -> AppResult<Self> {
        use std::fs;
        let base_dirs = BaseDirs::new().ok_or_else(|| DevcertError::Basedir("failed to find base directory storage. It might be that your system is unsupported by devcert.".to_owned()))?;
        let path: PathBuf = {
            let mut path: PathBuf = base_dirs.config_dir().into();
            path.push(format!("direnv/stores/{}", name));
            path
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

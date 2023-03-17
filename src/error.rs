use std::io;

use rcgen::RcgenError;
use thiserror::Error;

pub type AppResult<T> = Result<T, DevcertError>;

#[derive(Error, Debug)]
pub enum DevcertError {
    #[error("error while creating a certificate: {0}")]
    Cert(#[from] RcgenError),
    #[error("error while initializing certificate store: {0}")]
    Basedir(String),
    #[error("error while interacting with certificate store: {0}")]
    CertStore(#[from] io::Error),
}

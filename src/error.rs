use std::io;

use rcgen::RcgenError;
use thiserror::Error;

pub type AppResult<T> = Result<T, DevcertError>;

#[derive(Error, Debug)]
pub enum DevcertError {
    #[error("error while creating a certificate: {0}")]
    CertError(#[from] RcgenError),
    #[error("error while initializing certificate store: {0}")]
    BasedirError(String),
    #[error("error while interacting with certificate store: {0}")]
    CertStoreError(#[from] io::Error),
}

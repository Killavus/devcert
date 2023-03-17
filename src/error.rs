use rcgen::RcgenError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DevcertError {
    #[error("error while creating a certificate: {0}")]
    CertError(#[from] RcgenError),
}

use crate::{certgen::Certificate, error::AppResult};

#[cfg(windows)]
pub mod win32_store;

pub fn install_cert_on_machine(cert: &Certificate) -> AppResult<()> {
    #[cfg(windows)]
    {
        let store = win32_store::TrustStore::open()?;
        store.install(cert)?;
    }

    Ok(())
}

use crate::{certgen::Certificate, error::AppResult};

pub mod firefox_store;
#[cfg(windows)]
pub mod win32_store;

pub fn install_cert_on_machine(cert: &Certificate) -> AppResult<()> {
    #[cfg(windows)]
    {
        let store = win32_store::TrustStore::open()?;
        store.install(cert)?;
    }

    let ff_store = firefox_store::FirefoxStore::open();

    match ff_store {
        Ok(ff_store) => {
            println!("{:?}", ff_store);
        }
        Err(err) => {
            eprintln!("Skipping the installation of certificate for Firefox: {err}");
        }
    }

    Ok(())
}

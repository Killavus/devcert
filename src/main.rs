use std::path::PathBuf;

use certgen::create_host_certificate;
use certstore::CertStore;
use clap::{Parser, Subcommand};
use directories::BaseDirs;
use error::DevcertError;

mod certgen;
mod certstore;
mod error;
mod trust;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct CommandLine {
    /// Profile you want to interact with. Defaults to "default" profile
    #[arg(short, long)]
    profile: Option<String>,

    /// Root directory of your certificate store
    #[arg(short, long)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    action: CommandLineAction,
}

#[derive(Subcommand)]
enum CommandLineAction {
    /// Install certificate store for a given profile
    Install,

    /// Add a dev domain or IP to the certificate store
    Add {
        #[arg(value_name = "IP OR HOSTNAME")]
        value: String,
    },
}

use color_eyre::eyre::Result;
use trust::install_cert_on_machine;

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = CommandLine::parse();
    let root = cli.root.map(Ok).unwrap_or_else(|| {
        BaseDirs::new().ok_or_else(|| DevcertError::Basedir("failed to find base directory storage. It might be that your system is unsupported by devcert.".to_owned())).map(|base_dirs| {
            let mut path: PathBuf = base_dirs.config_dir().into();
            path.push("direnv");
            path
        })
    })?;
    let profile = cli
        .profile
        .unwrap_or_else(|| CertStore::DEFAULT_PROFILE.to_owned());

    let store = CertStore::new(&root, &profile)?;

    match cli.action {
        CommandLineAction::Install => {
            let ca_cert = certgen::create_root_ca_certificate(&profile)?;
            store.add(&ca_cert)?;
            install_cert_on_machine(&ca_cert)?;
        }
        CommandLineAction::Add { value } => {
            let ca_cert = store.root_cert()?;
            let host_cert = create_host_certificate(&profile, &value, &ca_cert)?;
            store.add(&host_cert)?;
        }
    }

    Ok(())
}

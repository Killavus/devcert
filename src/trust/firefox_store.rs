use std::path::PathBuf;

use directories::UserDirs;
use os_info::Type;

use crate::error::{AppResult, DevcertError};

#[derive(Debug)]
pub struct FirefoxStore {
    cert_profiles: Vec<PathBuf>,
}

fn find_cert_profiles(root: PathBuf) -> AppResult<Vec<PathBuf>> {
    let mut result = vec![];
    for profile in std::fs::read_dir(root)? {
        let profile = profile?;
        let profile_type = profile.file_type()?;

        if profile_type.is_dir() {
            let is_valid = std::fs::read_dir(profile.path())?.any(|profile_file| {
                profile_file
                    .map(|file| file.file_name() == "cert9.db" || file.file_name() == "cert8.db")
                    .unwrap_or(false)
            });

            if is_valid {
                result.push(profile.path());
            }
        }
    }

    Ok(result)
}

impl FirefoxStore {
    pub fn open() -> AppResult<Self> {
        let os = os_info::get();

        match os.os_type() {
            Type::Windows => {
                let profiles_path = UserDirs::new()
                    .map(|base_dir| {
                        let mut ff_path = base_dir.home_dir().to_owned();
                        ff_path.push("AppData");
                        ff_path.push("Roaming");
                        ff_path.push("Mozilla");
                        ff_path.push("Firefox");
                        ff_path.push("Profiles");
                        ff_path
                    })
                    .ok_or_else(|| {
                        DevcertError::Firefox(
                            "Failed to find location of Firefox profiles".to_owned(),
                        )
                    })?;

                if !profiles_path.exists() {
                    Err(DevcertError::Firefox(format!(
                        "Path of Firefox profiles does not exist: {}",
                        profiles_path.display()
                    )))
                } else {
                    let cert_profiles = find_cert_profiles(profiles_path)?;
                    Ok(Self { cert_profiles })
                }
            }
            _ => Err(DevcertError::Firefox(format!(
                "Unsupported operating system for Firefox store: {}",
                os.os_type()
            ))),
        }
    }
}

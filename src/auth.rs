//! Parsed authentication specifier.

use anyhow::ensure;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct Authentication {
    pub username: String,
    pub password: String,
}

impl FromStr for Authentication {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (username, password) = s.split_once(':').unwrap_or((s, ""));
        ensure!(username.len() < 256, "username is too long");
        ensure!(password.len() < 256, "password is too long");

        Ok(Self {
            username: username.to_owned(),
            password: password.to_owned(),
        })
    }
}

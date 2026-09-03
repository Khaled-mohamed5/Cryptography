//! MECARD format for WiFi credentials.
//!
//! Spec:
//! <https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android-ios-11>
use crate::upstream::mecard::{parse_bool, parse_field, parse_string};
use crate::upstream::mecard;
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{fail, map},
    IResult,
};
use std::{
    fmt::{self, Debug},
    ops::Deref,
    str,
};

/// WiFi network credentials.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Credentials {
    /// Authentication type.
    pub auth: Auth,
    /// Network SSID.
    pub ssid: String,
    /// Password.
    pub psk: Option<Password>,
    /// Whether the network SSID is hidden.
    pub hidden: bool,
}

/// Authentication type.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
pub enum Auth {
    /// WEP encryption.
    Wep,
    /// WPA encryption.
    Wpa,
    /// Pure WPA3-SAE.
    Sae,
    /// Unencrypted.
    #[default]
    Nopass,
}

/// Newtype on `String` to prevent printing in plaintext.
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Password(pub String);

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Password(value.to_string())
    }
}

impl Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl Deref for Password {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<&str> for Password {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl Credentials {
    pub fn parse(input: &str) -> Result<Credentials, String> {
        match Self::parse_internal(input) {
            Err(e) => Err(format!("{e}")),
            Ok((_, c)) => Ok(c),
        }
    }

    /// Parses WiFi credentials encoded in MECARD format.
    pub(crate) fn parse_internal(input: &str) -> IResult<&str, Self> {
        let (mut input, _) = tag("WIFI:")(input)?;

        mecard::parse_fields! { input;
            Auth::parse => auth_type,
            parse_ssid => ssid,
            parse_password => password,
            parse_hidden => hidden,
        }

        let ssid = ssid.filter(|ssid| !ssid.is_empty());
        let (password, auth_type) = password
            .filter(|pwd| !pwd.is_empty())
            .map_or((None, Some(Auth::Nopass)), |pwd| {
                (Some(Password(pwd)), auth_type)
            });

        // ssid is actually not optional.
        if ssid.is_none() {
            let (_, ()) = fail(input)?;
        }

        let auth_type = auth_type.unwrap_or_default();
        let ssid = ssid.unwrap_or_default();
        let hidden = hidden.unwrap_or_default();

        Ok((
            input,
            Self {
                auth: auth_type,
                ssid,
                psk: password,
                hidden,
            },
        ))
    }
}

impl Auth {
    pub fn parse(input: &str) -> IResult<&str, Self> {
        parse_field(input, "T", |input| {
            let wep = map(tag("WEP"), |_| Self::Wep);
            let wpa = map(tag("WPA"), |_| Self::Wpa);
            let sae = map(tag("SAE"), |_| Self::Sae);
            let nopass = map(alt((tag("nopass"), tag(""))), |_| Self::Nopass);
            alt((wep, wpa, sae, nopass))(input)
        })
    }
}

pub fn parse_ssid(input: &str) -> IResult<&str, String> {
    parse_field(input, "S", parse_string)
}

pub fn parse_password(input: &str) -> IResult<&str, String> {
    parse_field(input, "P", parse_string)
}

pub fn parse_hidden(input: &str) -> IResult<&str, bool> {
    parse_field(input, "H", parse_bool)
}


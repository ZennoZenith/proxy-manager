use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

/// [https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Redirections]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, strum_macros::Display)]
pub enum RedirectHttpCode {
    /// 300
    MultipleChoice,

    /// 301
    MovedPermanently,

    /// 302
    Found,

    /// 303
    SeeOther,

    /// 304
    NotModified,

    /// 307
    TemporaryRedirect,

    /// 308
    ParmanentRedirect,
}

impl RedirectHttpCode {
    pub fn new(code: u16) -> Option<Self> {
        match code {
            300 => Some(Self::MultipleChoice),
            301 => Some(Self::MovedPermanently),
            302 => Some(Self::Found),
            303 => Some(Self::SeeOther),
            304 => Some(Self::NotModified),
            307 => Some(Self::TemporaryRedirect),
            308 => Some(Self::ParmanentRedirect),
            _ => None,
        }
    }
}

impl Default for RedirectHttpCode {
    fn default() -> Self {
        todo!()
    }
}

impl TryFrom<u16> for RedirectHttpCode {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value).ok_or("value must be non-zero")
    }
}

impl TryFrom<&u16> for RedirectHttpCode {
    type Error = &'static str;

    fn try_from(value: &u16) -> Result<Self, Self::Error> {
        Self::new(*value).ok_or("value must be non-zero")
    }
}

impl From<RedirectHttpCode> for u16 {
    fn from(value: RedirectHttpCode) -> Self {
        match value {
            RedirectHttpCode::MultipleChoice => 300,
            RedirectHttpCode::MovedPermanently => 301,
            RedirectHttpCode::Found => 302,
            RedirectHttpCode::SeeOther => 303,
            RedirectHttpCode::NotModified => 304,
            RedirectHttpCode::TemporaryRedirect => 307,
            RedirectHttpCode::ParmanentRedirect => 308,
        }
    }
}

impl From<&RedirectHttpCode> for u16 {
    fn from(value: &RedirectHttpCode) -> Self {
        (*value).into()
    }
}

impl<'de> Deserialize<'de> for RedirectHttpCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let code = u16::deserialize(deserializer)?;
        RedirectHttpCode::try_from(code)
            .map_err(|_| D::Error::custom(format!("unsupported redirect HTTP code: {}", code)))
    }
}

impl Serialize for RedirectHttpCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u16(self.into())
    }
}

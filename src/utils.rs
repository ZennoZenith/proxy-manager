use std::{
    collections::HashSet,
    fmt,
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Deserializer, de};

pub fn first_non_unique_ref<'a, I, T>(iter: I) -> Option<&'a T>
where
    I: IntoIterator<Item = &'a T>,
    T: Eq + std::hash::Hash + ?Sized,
{
    let mut seen: HashSet<&'a T> = HashSet::new();

    iter.into_iter()
        .find(|&item| !seen.insert(item))
        .map(|v| v as _)
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, PartialOrd, Hash, Eq)]
#[serde(transparent)]
pub struct Port(u16);

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl DerefMut for Port {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for Port {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u16> for Port {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Port> for u16 {
    fn from(value: Port) -> Self {
        value.0
    }
}

#[derive(Clone, Default, PartialEq, PartialOrd, Hash, Eq)]
pub struct TrimedStr(Box<str>);

impl fmt::Debug for TrimedStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}
impl fmt::Display for TrimedStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TrimedStr {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TrimedStrVisitor;

        impl<'de> de::Visitor<'de> for TrimedStrVisitor {
            type Value = TrimedStr;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TrimedStr(v.trim().into()))
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TrimedStr(v.trim().into()))
            }
        }

        deserializer.deserialize_string(TrimedStrVisitor)
    }
}

impl DerefMut for TrimedStr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for TrimedStr {
    type Target = Box<str>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Box<str>> for TrimedStr {
    fn from(s: Box<str>) -> Self {
        TrimedStr(s.trim().into())
    }
}

impl From<&str> for TrimedStr {
    fn from(s: &str) -> Self {
        TrimedStr(s.trim().into())
    }
}

impl From<String> for TrimedStr {
    fn from(s: String) -> Self {
        TrimedStr(s.trim().into())
    }
}

impl TrimedStr {
    #[allow(unused)]
    pub fn new(value: &str) -> Self {
        Self(value.trim().into())
    }
}

#[derive(Clone, PartialEq, PartialOrd, Hash, Eq)]
pub struct NonEmptyTrimedStr(TrimedStr);

impl From<NonEmptyTrimedStr> for Box<str> {
    fn from(val: NonEmptyTrimedStr) -> Self {
        val.0.0.clone()
    }
}

impl From<&NonEmptyTrimedStr> for Box<str> {
    fn from(val: &NonEmptyTrimedStr) -> Self {
        val.0.0.clone()
    }
}

impl fmt::Debug for NonEmptyTrimedStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}
impl fmt::Display for NonEmptyTrimedStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NonEmptyTrimedStr {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TrimedStrVisitor;

        impl<'de> de::Visitor<'de> for TrimedStrVisitor {
            type Value = NonEmptyTrimedStr;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.trim().is_empty() {
                    Err(de::Error::custom("empty string after trimming"))
                } else {
                    Ok(NonEmptyTrimedStr(v.trim().into()))
                }
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.trim().is_empty() {
                    Err(de::Error::custom("empty string after trimming"))
                } else {
                    Ok(NonEmptyTrimedStr(v.trim().into()))
                }
            }
        }

        deserializer.deserialize_string(TrimedStrVisitor)
    }
}

impl DerefMut for NonEmptyTrimedStr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for NonEmptyTrimedStr {
    type Target = Box<str>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl NonEmptyTrimedStr {
    pub fn try_new(value: &str) -> std::result::Result<Self, &'static str> {
        if value.trim().is_empty() {
            Err("empty string after trimming")
        } else {
            Ok(Self(value.trim().into()))
        }
    }
}

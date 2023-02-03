use std::error::Error as StdError;
use std::fmt::{self, Display};

use crate::intent::Intent;

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

impl Error {
    pub fn kind(&self) -> &Kind {
        &self.kind
    }
}

impl Error {
    fn new(kind: Kind) -> Self {
        Self { kind }
    }
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut fun = |kind, inner| Display::fmt(&format!("[{kind}] {inner}"), fmt);
        match &self.kind {
            Kind::Forbidden(inner) => fun("Forbidden", inner),
            Kind::Network(inner) => fun("Network", inner),
            Kind::Internal(inner) => fun("Internal", inner),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum Kind {
    Forbidden(IntentError),
    Network(IntentError),
    Internal(IntentError),
}

impl From<Kind> for Error {
    fn from(value: Kind) -> Self {
        Self::new(value)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct IntentError {
    intent: Intent,
    detail: String,
}

impl StdError for IntentError {}

impl IntentError {
    pub(crate) fn new<T: AsRef<str>>(intent: Intent, detail: T) -> Self {
        Self {
            intent,
            detail: detail.as_ref().to_owned(),
        }
    }
}

impl Display for IntentError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(
            &format!("{} has been forbidden, {}", &self.intent, &self.detail),
            fmt,
        )
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct ConfigurationError(String);

impl ConfigurationError {
    pub fn new(detail: &str) -> Self {
        Self(detail.to_owned())
    }
}

impl StdError for ConfigurationError {}

impl Display for ConfigurationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

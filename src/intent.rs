use std::fmt;
use svc_authn::AccountId;

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub(crate) struct Intent {
    subject: AccountId,
    object: Vec<String>,
    action: String,
}

impl Intent {
    pub(crate) fn new(subject: AccountId, object: Vec<String>, action: &str) -> Self {
        Self {
            subject,
            object,
            action: action.to_owned(),
        }
    }

    pub(crate) fn action(&self) -> &str {
        &self.action
    }
}

impl fmt::Display for Intent {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(
            &format!(
                "action = '{}' to the object = '{}' for the subject = '{}'",
                &self.action,
                &self.object.join("."),
                self.subject,
            ),
            fmt,
        )
    }
}

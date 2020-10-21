use std::fmt;
use svc_authn::AccountId;

////////////////////////////////////////////////////////////////////////////////

pub trait Object: Send + Sync {
    fn to_ban_key(&self) -> Option<Vec<String>>;
    fn to_vec(&self) -> Vec<String>;
    fn box_clone(&self) -> Box<dyn Object>;
}

impl Clone for Box<dyn Object> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

impl fmt::Debug for Box<dyn Object> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.to_vec(), fmt)
    }
}

#[derive(Clone, Debug)]
pub struct Intent {
    subject: AccountId,
    object: Box<dyn Object>,
    action: String,
}

impl Intent {
    pub(crate) fn new(subject: AccountId, object: Box<dyn Object>, action: &str) -> Self {
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
                "intent::{}::{}::{}",
                self.subject,
                &self.object.to_vec().join("/"),
                &self.action,
            ),
            fmt,
        )
    }
}

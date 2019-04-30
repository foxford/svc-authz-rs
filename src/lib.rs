use jsonwebtoken::Algorithm;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;
use svc_authn::{token::jws_compact, AccountId};

use crate::error::{ConfigurationError, IntentError};
use crate::intent::Intent;

////////////////////////////////////////////////////////////////////////////////

pub type ConfigMap = HashMap<String, Config>;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum Config {
    None(NoneConfig),
    Local(LocalConfig),
    Http(HttpConfig),
}

////////////////////////////////////////////////////////////////////////////////

trait Authorize: Sync + Send {
    fn authorize(&self, subject: &AccountId, object: Vec<&str>, action: &str) -> Result<(), Error>;
    fn box_clone(&self) -> Box<dyn Authorize>;
}

////////////////////////////////////////////////////////////////////////////////

type Client = Box<dyn Authorize>;

impl fmt::Debug for Client {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Client").finish()
    }
}

impl Clone for Client {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

trait IntoClient {
    fn into_client<A>(self, me: &A, audience: &str) -> Result<Client, ConfigurationError>
    where
        A: Authenticable;
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct ClientMap {
    inner: HashMap<String, Client>,
}

impl ClientMap {
    pub fn new<A>(me: &A, m: ConfigMap) -> Result<Self, ConfigurationError>
    where
        A: Authenticable,
    {
        let mut inner: HashMap<String, Client> = HashMap::new();
        for (audience, config) in m {
            match config {
                Config::None(config) => {
                    let client = config.into_client(me, &audience)?;
                    inner.insert(audience, client);
                }
                Config::Local(config) => {
                    let client = config.into_client(me, &audience)?;
                    inner.insert(audience, client);
                }
                Config::Http(config) => {
                    let client = config.into_client(me, &audience)?;
                    inner.insert(audience, client);
                }
            }
        }

        Ok(Self { inner })
    }

    pub fn authorize<A>(
        &self,
        audience: &str,
        subject: &A,
        object: Vec<&str>,
        action: &str,
    ) -> Result<(), Error>
    where
        A: Authenticable,
    {
        let client = self.inner.get(audience).ok_or_else(|| {
            ErrorKind::Forbidden(IntentError::new(
                Intent::new(
                    subject.as_account_id().clone(),
                    object.iter().map(|&s| s.into()).collect(),
                    action,
                ),
                &format!(
                    "no authorization configuration for the audience = {}",
                    audience
                ),
            ))
        })?;

        client.authorize(subject.as_account_id(), object, action)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Deserialize)]
pub struct NoneConfig {}

impl IntoClient for NoneConfig {
    fn into_client<A>(self, _me: &A, _audience: &str) -> Result<Client, ConfigurationError>
    where
        A: Authenticable,
    {
        Ok(Box::new(NoneClient {}))
    }
}

#[derive(Debug, Clone)]
struct NoneClient {}

impl Authorize for NoneClient {
    fn authorize(
        &self,
        _subject: &AccountId,
        _object: Vec<&str>,
        _action: &str,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn box_clone(&self) -> Box<dyn Authorize> {
        Box::new(self.clone())
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Deserialize)]
pub struct LocalConfig {
    #[serde(default)]
    trusted: HashSet<AccountId>,
}

impl IntoClient for LocalConfig {
    fn into_client<A>(self, _me: &A, _audience: &str) -> Result<Client, ConfigurationError>
    where
        A: Authenticable,
    {
        Ok(Box::new(LocalClient {
            trusted: self.trusted,
        }))
    }
}

#[derive(Debug, Clone)]
struct LocalClient {
    trusted: HashSet<AccountId>,
}

impl Authorize for LocalClient {
    fn authorize(&self, subject: &AccountId, object: Vec<&str>, action: &str) -> Result<(), Error> {
        // Allow access if the subject in the trusted list
        if let true = self.trusted.contains(subject) {
            return Ok(());
        }

        Err(ErrorKind::Forbidden(IntentError::new(
            Intent::new(
                subject.clone(),
                object.iter().map(|&s| s.into()).collect(),
                action,
            ),
            "the subject isn't in a trusted list",
        ))
        .into())
    }

    fn box_clone(&self) -> Box<dyn Authorize> {
        Box::new(self.clone())
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    uri: String,
    #[serde(default)]
    trusted: HashSet<AccountId>,
    #[serde(deserialize_with = "svc_authn::serde::algorithm")]
    algorithm: Algorithm,
    #[serde(deserialize_with = "svc_authn::serde::file")]
    key: Vec<u8>,
    timeout: Option<u64>,
}

impl HttpConfig {
    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    pub fn key(&self) -> &Vec<u8> {
        &self.key
    }
}

impl IntoClient for HttpConfig {
    fn into_client<A>(self, me: &A, audience: &str) -> Result<Client, ConfigurationError>
    where
        A: Authenticable,
    {
        let issuer = me.as_account_id().audience();
        let mapped_me = AccountId::new(
            me.as_account_id().label(),
            &format!("{}:{}", me.as_account_id().audience(), audience),
        );

        let token = jws_compact::TokenBuilder::new()
            .issuer(issuer)
            .subject(&mapped_me)
            .key(self.algorithm, &self.key)
            .build()
            .map_err(|err| {
                ConfigurationError::new(&format!(
                    "error converting an authorization config for audience = '{}' into client, {}",
                    audience, &err,
                ))
            })?;

        Ok(Box::new(HttpClient {
            object_ns: me.as_account_id().to_string(),
            uri: self.uri,
            timeout: Duration::from_secs(self.timeout.unwrap_or(5)),
            trusted: self.trusted,
            token,
        }))
    }
}

#[derive(Debug, Clone)]
struct HttpClient {
    object_ns: String,
    uri: String,
    timeout: Duration,
    trusted: HashSet<AccountId>,
    token: String,
}

impl Authorize for HttpClient {
    fn authorize(&self, subject: &AccountId, object: Vec<&str>, action: &str) -> Result<(), Error> {
        // Allow access if the subject in the trusted list
        if let true = self.trusted.contains(subject) {
            return Ok(());
        }

        let payload = HttpRequest::new(
            HttpRequestEntity::new(subject.audience(), vec!["accounts", subject.label()]),
            HttpRequestEntity::new(&self.object_ns, object.clone()),
            action,
        );

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| {
                ErrorKind::Network(IntentError::new(
                    Intent::new(
                        subject.clone(),
                        object.iter().map(|&s| s.into()).collect(),
                        action,
                    ),
                    &format!("error initializing HTTP client, {}", &e),
                ))
            })?;

        let resp: Vec<String> = client
            .post(&self.uri)
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .map_err(|e| {
                ErrorKind::Network(IntentError::new(
                    Intent::new(
                        subject.clone(),
                        object.iter().map(|&s| s.into()).collect(),
                        action,
                    ),
                    &format!("error sending the authorization request, {}", &e),
                ))
            })?
            .json()
            .map_err(|_| {
                ErrorKind::Network(IntentError::new(
                    Intent::new(
                        subject.clone(),
                        object.iter().map(|&s| s.into()).collect(),
                        action,
                    ),
                    &format!(
                        "invalid format of the authorization response on the request = '{}'",
                        serde_json::to_string(&payload)
                            .unwrap_or_else(|_| format!("{:?}", &payload))
                    ),
                ))
            })?;

        if !resp.contains(&action.to_owned()) {
            return Err(ErrorKind::Forbidden(IntentError::new(
                Intent::new(
                    subject.clone(),
                    object.iter().map(|&s| s.into()).collect(),
                    action,
                ),
                "the action forbidden by tenant",
            ))
            .into());
        }

        Ok(())
    }

    fn box_clone(&self) -> Box<dyn Authorize> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Serialize)]
struct HttpRequest<'a> {
    subject: HttpRequestEntity<'a>,
    object: HttpRequestEntity<'a>,
    action: &'a str,
}

impl<'a> HttpRequest<'a> {
    fn new(subject: HttpRequestEntity<'a>, object: HttpRequestEntity<'a>, action: &'a str) -> Self {
        Self {
            subject,
            object,
            action,
        }
    }
}

#[derive(Debug, Serialize)]
struct HttpRequestEntity<'a> {
    namespace: &'a str,
    value: Vec<&'a str>,
}

impl<'a> HttpRequestEntity<'a> {
    fn new(namespace: &'a str, value: Vec<&'a str>) -> Self {
        Self { namespace, value }
    }
}

////////////////////////////////////////////////////////////////////////////////

pub use svc_authn::Authenticable;

pub use self::error::{Error, Kind as ErrorKind};
pub mod error;
pub mod intent;

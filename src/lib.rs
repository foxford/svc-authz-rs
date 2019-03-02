use failure::{format_err, Error};
use jsonwebtoken::Algorithm;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use svc_authn::{token::jws_compact, AccountId};

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
    fn authorize(&self, subject: &AccountId, object: Entity, action: &str) -> Result<(), Error>;
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
    fn into_client<A>(self, me: &A, audience: &str) -> Result<Client, Error>
    where
        A: Authenticable;
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct ClientMap {
    object_ns: String,
    inner: HashMap<String, Client>,
}

impl ClientMap {
    pub fn new<A>(me: &A, m: ConfigMap) -> Result<Self, Error>
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

        Ok(Self {
            object_ns: me.as_account_id().to_string(),
            inner,
        })
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
        let client = self
            .inner
            .get(audience)
            .ok_or_else(|| format_err!("no authz configuration for the audience = {}", audience))?;

        client.authorize(
            subject.as_account_id(),
            Entity::new(&self.object_ns, object),
            action,
        )
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Serialize)]
struct Intent<'a> {
    subject: Entity<'a>,
    object: Entity<'a>,
    action: &'a str,
}

impl<'a> Intent<'a> {
    fn new(subject: Entity<'a>, object: Entity<'a>, action: &'a str) -> Self {
        Self {
            subject,
            object,
            action,
        }
    }

    fn action(&self) -> &str {
        self.action
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Serialize)]
struct Entity<'a> {
    namespace: &'a str,
    value: Vec<&'a str>,
}

impl<'a> Entity<'a> {
    fn new(namespace: &'a str, value: Vec<&'a str>) -> Self {
        Self { namespace, value }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Deserialize)]
pub struct NoneConfig {}

impl IntoClient for NoneConfig {
    fn into_client<A>(self, _me: &A, _audience: &str) -> Result<Client, Error>
    where
        A: Authenticable,
    {
        Ok(Box::new(NoneClient {}))
    }
}

#[derive(Debug, Clone)]
struct NoneClient {}

impl Authorize for NoneClient {
    fn authorize(&self, _subject: &AccountId, _object: Entity, _action: &str) -> Result<(), Error> {
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
    fn into_client<A>(self, _me: &A, _audience: &str) -> Result<Client, Error>
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
    fn authorize(&self, subject: &AccountId, _object: Entity, _action: &str) -> Result<(), Error> {
        // Allow access if the subject in the trusted list
        if let true = self.trusted.contains(subject) {
            return Ok(());
        }

        Err(format_err!("subject = '{}' isn't trusted", &subject))
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
    fn into_client<A>(self, me: &A, audience: &str) -> Result<Client, Error>
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
                format_err!(
                    "error converting authz config for audience = '{}' into client – {}",
                    audience,
                    &err,
                )
            })?;

        Ok(Box::new(HttpClient {
            uri: self.uri,
            trusted: self.trusted,
            token,
        }))
    }
}

#[derive(Debug, Clone)]
struct HttpClient {
    uri: String,
    trusted: HashSet<AccountId>,
    token: String,
}

impl Authorize for HttpClient {
    fn authorize(&self, subject: &AccountId, object: Entity, action: &str) -> Result<(), Error> {
        use reqwest;

        // Allow access if the subject in the trusted list
        if let true = self.trusted.contains(subject) {
            return Ok(());
        }

        let intent = Intent::new(
            Entity::new(subject.audience(), vec!["accounts", subject.label()]),
            object,
            action,
        );

        let client = reqwest::Client::new();
        let resp: Vec<String> = client
            .post(&self.uri)
            .bearer_auth(&self.token)
            .json(&intent)
            .send()
            .map_err(|err| format_err!("error sending the authorization request, {}", &err))?
            .json()
            .map_err(|_| {
                format_err!(
                    "invalid format of the authorization response, intent = '{}'",
                    serde_json::to_string(&intent).unwrap_or_else(|_| format!("{:?}", &intent)),
                )
            })?;

        if !resp.contains(&intent.action().to_owned()) {
            return Err(format_err!("action = {} is not allowed", &intent.action()));
        }

        Ok(())
    }

    fn box_clone(&self) -> Box<dyn Authorize> {
        Box::new(self.clone())
    }
}

////////////////////////////////////////////////////////////////////////////////

pub use svc_authn::Authenticable;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::future::{self, Either};
use futures_timer::Delay;
use jsonwebtoken::Algorithm;
use serde_derive::{Deserialize, Serialize};
use svc_authn::{token::jws_compact, AccountId};

use crate::cache::{Cache, Response as CacheResponse};
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
    LocalWhitelist(LocalWhitelistConfig),
}

////////////////////////////////////////////////////////////////////////////////

#[async_trait]
trait Authorize: Sync + Send {
    async fn authorize(
        &self,
        subject: &AccountId,
        object: Vec<&str>,
        action: &str,
    ) -> Result<(), Error>;

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
    fn into_client<A>(
        self,
        me: &A,
        cache: Option<Cache>,
        audience: &str,
    ) -> Result<Client, ConfigurationError>
    where
        A: Authenticable;
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct ClientMap {
    inner: HashMap<String, Client>,
}

impl ClientMap {
    pub fn new<A>(me: &A, cache: Option<Cache>, m: ConfigMap) -> Result<Self, ConfigurationError>
    where
        A: Authenticable,
    {
        let mut inner: HashMap<String, Client> = HashMap::new();
        for (audience, config) in m {
            match config {
                Config::None(config) => {
                    let client = config.into_client(me, cache.clone(), &audience)?;
                    inner.insert(audience, client);
                }
                Config::Local(config) => {
                    let client = config.into_client(me, cache.clone(), &audience)?;
                    inner.insert(audience, client);
                }
                Config::Http(config) => {
                    let client = config.into_client(me, cache.clone(), &audience)?;
                    inner.insert(audience, client);
                }
                Config::LocalWhitelist(config) => {
                    let client = config.into_client(me, cache.clone(), &audience)?;
                    inner.insert(audience, client);
                }
            }
        }

        Ok(Self { inner })
    }

    pub async fn authorize<A>(
        &self,
        audience: &str,
        subject: &A,
        object: Vec<&str>,
        action: &str,
    ) -> Result<Duration, Error>
    where
        A: Authenticable,
    {
        let start_time = Instant::now();

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

        client
            .authorize(subject.as_account_id(), object, action)
            .await
            .map(|()| Instant::now().duration_since(start_time))
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Deserialize)]
pub struct NoneConfig {}

impl IntoClient for NoneConfig {
    fn into_client<A>(
        self,
        _me: &A,
        _cache: Option<Cache>,
        _audience: &str,
    ) -> Result<Client, ConfigurationError>
    where
        A: Authenticable,
    {
        Ok(Box::new(NoneClient {}))
    }
}

#[derive(Debug, Clone)]
struct NoneClient {}

#[async_trait]
impl Authorize for NoneClient {
    async fn authorize(
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
    fn into_client<A>(
        self,
        _me: &A,
        _cache: Option<Cache>,
        _audience: &str,
    ) -> Result<Client, ConfigurationError>
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

#[async_trait]
impl Authorize for LocalClient {
    async fn authorize(
        &self,
        subject: &AccountId,
        object: Vec<&str>,
        action: &str,
    ) -> Result<(), Error> {
        // Allow access if the subject in the trusted list
        if self.trusted.contains(subject) {
            Ok(())
        } else {
            let intent_err = IntentError::new(
                Intent::new(
                    subject.clone(),
                    object.iter().map(|&s| s.into()).collect(),
                    action,
                ),
                "the subject isn't in a trusted list",
            );

            Err(ErrorKind::Forbidden(intent_err).into())
        }
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
    fn into_client<A>(
        self,
        me: &A,
        cache: Option<Cache>,
        audience: &str,
    ) -> Result<Client, ConfigurationError>
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
            trusted: self.trusted,
            token,
            cache,
            timeout: Duration::from_secs(self.timeout.unwrap_or(5)),
        }))
    }
}

#[derive(Debug, Clone)]
struct HttpClient {
    object_ns: String,
    uri: String,
    trusted: HashSet<AccountId>,
    token: String,
    cache: Option<Cache>,
    timeout: Duration,
}

#[async_trait]
impl Authorize for HttpClient {
    async fn authorize(
        &self,
        subject: &AccountId,
        object: Vec<&str>,
        action: &str,
    ) -> Result<(), Error> {
        // Allow access if the subject in the trusted list
        if let true = self.trusted.contains(subject) {
            return Ok(());
        }

        let intent = Intent::new(
            subject.clone(),
            object.iter().map(|&s| s.into()).collect(),
            action,
        );

        // Return a result from the cache if available
        let cache = self.cache.clone();
        if let Some(ref cache) = cache {
            if let CacheResponse::Hit(result) = cache.get(&intent.to_string()) {
                return match result {
                    true => Ok(()),
                    false => Err(ErrorKind::Forbidden(IntentError::new(
                        intent,
                        "the action forbidden by tenant (cache hit)",
                    ))
                    .into()),
                };
            }
        }

        let payload = HttpRequest::new(
            HttpRequestEntity::new(subject.audience(), vec!["accounts", subject.label()]),
            HttpRequestEntity::new(&self.object_ns, object.clone()),
            action,
        );

        let request = surf::post(&self.uri)
            .set_header("Authorization", format!("Bearer {}", self.token))
            .body_json(&payload);

        match request {
            Ok(req) => {
                match future::select(req, Delay::new(self.timeout)).await {
                    Either::Left((Ok(mut resp), _)) => {
                        match resp.body_json::<Vec<String>>().await {
                            Ok(data) => {
                                if !data.contains(&intent.action().to_owned()) {
                                    // Store the failure result into the cache
                                    cache.map(|cache| cache.set(&intent.to_string(), false));

                                    let intent_err =
                                        IntentError::new(intent, "the action forbidden by tenant");

                                    Err(ErrorKind::Forbidden(intent_err).into())
                                } else {
                                    // Store the success result into the cache
                                    cache.map(|cache| cache.set(&intent.to_string(), true));
                                    Ok(())
                                }
                            }
                            Err(_) => {
                                let intent_err = IntentError::new(
                                    intent,
                                    "invalid format of the authorization response",
                                );

                                Err(ErrorKind::Network(intent_err).into())
                            }
                        }
                    }
                    Either::Left((Err(err), _)) => {
                        let intent_err = IntentError::new(
                            intent,
                            &format!("error sending the authorization request, {}", &err),
                        );

                        Err(ErrorKind::Network(intent_err).into())
                    }
                    Either::Right((_, _)) => {
                        let intent_err = IntentError::new(
                            intent,
                            &format!("timed out sending the authorization request"),
                        );

                        Err(ErrorKind::Network(intent_err).into())
                    }
                }
            }
            Err(err) => {
                let intent_err = IntentError::new(
                    intent,
                    &format!("failed to build authorization request, {}", &err),
                );

                Err(ErrorKind::Internal(intent_err).into())
            }
        }
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

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LocalWhitelistRecord {
    subject_account_id: AccountId,
    object: Vec<String>,
    action: String,
}

impl LocalWhitelistRecord {
    pub fn new<A: Authenticable>(subject: &A, object: Vec<&str>, action: &str) -> Self {
        Self {
            subject_account_id: subject.as_account_id().to_owned(),
            object: object.iter().map(|x| x.to_string()).collect(),
            action: action.to_string(),
        }
    }

    fn subject_account_id(&self) -> &AccountId {
        &self.subject_account_id
    }

    fn object(&self) -> Vec<&str> {
        self.object.iter().map(|x| &**x).collect()
    }

    fn action(&self) -> &str {
        self.action.as_ref()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalWhitelistConfig {
    records: Vec<LocalWhitelistRecord>,
}

impl LocalWhitelistConfig {
    pub fn new(records: Vec<LocalWhitelistRecord>) -> Self {
        Self { records }
    }
}

impl IntoClient for LocalWhitelistConfig {
    fn into_client<A>(
        self,
        _me: &A,
        _cache: Option<Cache>,
        _audience: &str,
    ) -> Result<Client, ConfigurationError>
    where
        A: Authenticable,
    {
        Ok(Box::new(LocalWhitelistClient {
            records: self.records,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct LocalWhitelistClient {
    records: Vec<LocalWhitelistRecord>,
}

#[async_trait]
impl Authorize for LocalWhitelistClient {
    async fn authorize(
        &self,
        subject: &AccountId,
        object: Vec<&str>,
        action: &str,
    ) -> Result<(), Error> {
        let record = LocalWhitelistRecord::new(subject, object, action);

        match self.records.iter().find(|&r| r == &record) {
            Some(_) => Ok(()),
            None => {
                let intent = Intent::new(
                    record.subject_account_id().clone(),
                    record.object().iter().map(|&s| s.into()).collect(),
                    record.action(),
                );

                let err = ErrorKind::Forbidden(IntentError::new(intent, "Not allowed"));
                Err(err.into())
            }
        }
    }

    fn box_clone(&self) -> Box<dyn Authorize> {
        Box::new(self.clone())
    }
}

////////////////////////////////////////////////////////////////////////////////

pub use svc_authn::Authenticable;

pub use self::error::{Error, Kind as ErrorKind};
pub mod cache;
pub mod error;
pub mod intent;

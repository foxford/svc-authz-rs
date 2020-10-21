use std::collections::{HashMap, HashSet};
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use futures::future::{self, Either};
use futures_timer::Delay;
use jsonwebtoken::Algorithm;
use serde_derive::{Deserialize, Serialize};
use svc_authn::{token::jws_compact, AccountId};

use crate::cache::{AuthzCache, Response as CacheResponse};
use crate::error::{ConfigurationError, IntentError};
use crate::intent::Intent;

////////////////////////////////////////////////////////////////////////////////

pub type BanCallback = Arc<
    dyn Fn(AccountId, Box<dyn IntentObject>) -> Pin<Box<dyn futures::Future<Output = bool> + Send>>
        + Send
        + Sync,
>;
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
        subject: AccountId,
        object: Box<dyn IntentObject>,
        action: String,
    ) -> Result<(), Error>;

    async fn ban(
        &self,
        subject: AccountId,
        object: Box<dyn IntentObject>,
        value: bool,
        seconds: usize,
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
        cache: Option<Box<dyn AuthzCache>>,
        audience: &str,
        ban_f: BanCallback,
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
    pub fn new<A>(
        me: &A,
        cache: Option<Box<dyn AuthzCache>>,
        m: ConfigMap,
        f: BanCallback,
    ) -> Result<Self, ConfigurationError>
    where
        A: Authenticable,
    {
        let mut inner: HashMap<String, Client> = HashMap::new();

        for (audience, config) in m {
            match config {
                Config::None(config) => {
                    let client = config.into_client(me, cache.clone(), &audience, f.clone())?;
                    inner.insert(audience, client);
                }
                Config::Local(config) => {
                    let client = config.into_client(me, cache.clone(), &audience, f.clone())?;
                    inner.insert(audience, client);
                }
                Config::Http(config) => {
                    let client = config.into_client(me, cache.clone(), &audience, f.clone())?;
                    inner.insert(audience, client);
                }
                Config::LocalWhitelist(config) => {
                    let client = config.into_client(me, cache.clone(), &audience, f.clone())?;
                    inner.insert(audience, client);
                }
            }
        }

        Ok(Self { inner })
    }

    pub async fn authorize<A>(
        &self,
        audience: String,
        subject: A,
        object: Box<dyn IntentObject>,
        action: String,
    ) -> Result<Duration, Error>
    where
        A: Authenticable,
    {
        let start_time = Utc::now();

        let client = self.inner.get(&audience).ok_or_else(|| {
            ErrorKind::Forbidden(IntentError::new(
                Intent::new(subject.as_account_id().clone(), object.clone(), &action),
                &format!(
                    "no authorization configuration for the audience = {}",
                    audience
                ),
            ))
        })?;

        client
            .authorize(subject.as_account_id().to_owned(), object, action)
            .await
            .map(|()| Utc::now() - start_time)
    }

    pub async fn ban<A>(
        &self,
        audience: String,
        subject: A,
        object: Box<dyn IntentObject>,
        value: bool,
        seconds: usize,
    ) -> Result<(), Error>
    where
        A: Authenticable,
    {
        if let Some(client) = self.inner.get(&audience) {
            client
                .ban(subject.as_account_id().to_owned(), object, value, seconds)
                .await
        } else {
            Ok(())
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Deserialize)]
pub struct NoneConfig {}

impl IntoClient for NoneConfig {
    fn into_client<A>(
        self,
        _me: &A,
        _cache: Option<Box<dyn AuthzCache>>,
        _audience: &str,
        _ban_f: BanCallback,
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
        _subject: AccountId,
        _object: Box<dyn IntentObject>,
        _action: String,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn ban(
        &self,
        _subject: AccountId,
        _object: Box<dyn IntentObject>,
        _value: bool,
        _seconds: usize,
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
        _cache: Option<Box<dyn AuthzCache>>,
        _audience: &str,
        _ban_f: BanCallback,
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
        subject: AccountId,
        object: Box<dyn IntentObject>,
        action: String,
    ) -> Result<(), Error> {
        // Allow access if the subject in the trusted list
        if self.trusted.contains(&subject) {
            Ok(())
        } else {
            let intent_err = IntentError::new(
                Intent::new(subject, object, &action),
                "the subject isn't in a trusted list",
            );

            Err(ErrorKind::Forbidden(intent_err).into())
        }
    }

    async fn ban(
        &self,
        _subject: AccountId,
        _object: Box<dyn IntentObject>,
        _value: bool,
        _seconds: usize,
    ) -> Result<(), Error> {
        Ok(())
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
    user_agent: Option<String>,
    #[serde(default = "HttpConfig::default_max_retries")]
    max_retries: usize,
}

impl HttpConfig {
    fn default_max_retries() -> usize {
        1
    }

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
        cache: Option<Box<dyn AuthzCache>>,
        audience: &str,
        ban_f: BanCallback,
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
            client: Arc::new(surf::Client::new()),
            object_ns: me.as_account_id().to_string(),
            uri: self.uri,
            timeout: std::time::Duration::from_secs(self.timeout.unwrap_or(5)),
            trusted: self.trusted,
            token,
            authz_cache: cache,
            user_agent: self.user_agent,
            max_retries: self.max_retries,
            ban_f,
        }))
    }
}

#[derive(Clone)]
struct HttpClient {
    client: Arc<surf::Client<http_client::native::NativeClient>>,
    object_ns: String,
    uri: String,
    timeout: std::time::Duration,
    trusted: HashSet<AccountId>,
    token: String,
    authz_cache: Option<Box<dyn AuthzCache>>,
    user_agent: Option<String>,
    max_retries: usize,
    ban_f: BanCallback,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("client", &self.client)
            .field("object_ns", &self.object_ns)
            .field("uri", &self.uri)
            .field("timeout", &self.timeout)
            .field("trusted", &self.trusted)
            .field("token", &self.token)
            .field("authz_cache", &self.authz_cache)
            .field("user_agent", &self.user_agent)
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

#[async_trait]
impl Authorize for HttpClient {
    async fn authorize(
        &self,
        subject: AccountId,
        object: Box<dyn IntentObject>,
        action: String,
    ) -> Result<(), Error> {
        // Allow access if the subject in the trusted list
        if let true = self.trusted.contains(&subject) {
            return Ok(());
        }

        let intent = Intent::new(subject.clone(), object.clone(), &action);

        // Return a result from the cache if available
        if let Some(ref cache) = self.authz_cache {
            let cache = cache.clone();
            let intent_ = intent.to_string();

            if let Some(wildcard) = object.to_ban_key() {
                let cache_response = async_std::task::spawn_blocking(move || {
                    cache.mget(&[&intent_, &wildcard.join("/")])
                })
                .await;

                match cache_response[0..2] {
                    [_, CacheResponse::Hit(true)] => {
                        return Err(ErrorKind::Forbidden(IntentError::new(
                            intent,
                            "banned (cache hit)",
                        ))
                        .into());
                    }
                    [CacheResponse::Hit(result), CacheResponse::Hit(false)] => {
                        return if result {
                            Ok(())
                        } else {
                            Err(ErrorKind::Forbidden(IntentError::new(
                                intent,
                                "the action forbidden by tenant (cache hit)",
                            ))
                            .into())
                        };
                    }
                    [_, _] => {}
                    _ => {
                        log::warn!("Cache ban request returned improper number of responses, expected 2, got = {:?}", cache_response);
                    }
                }
            } else {
                let cache_response =
                    async_std::task::spawn_blocking(move || cache.get(&intent_)).await;

                if let CacheResponse::Hit(result) = cache_response {
                    return if result {
                        Ok(())
                    } else {
                        Err(ErrorKind::Forbidden(IntentError::new(
                            intent,
                            "the action forbidden by tenant (cache hit)",
                        ))
                        .into())
                    };
                }
            }
        }

        let subject_ = subject.clone();
        if let Some(ban_key) = object.to_ban_key() {
            let is_banned = (self.ban_f)(subject.to_owned(), object.clone()).await;

            if let Some(ref cache) = self.authz_cache {
                let cache = cache.clone();

                async_std::task::spawn_blocking(move || {
                    let ban_key = format!("ban::{}::{}", subject_, ban_key.join("/"));
                    cache.set(&ban_key, is_banned);
                })
                .await;
            }

            if is_banned {
                return Err(
                    ErrorKind::Forbidden(IntentError::new(intent, "banned (cache hit)")).into(),
                );
            }
        }

        let payload = HttpRequest::new(
            HttpSubject::new(subject.audience(), subject.label()),
            HttpObject::new(&self.object_ns, object.to_vec()),
            &action,
        );

        let intent_err = IntentError::new(
            intent.clone(),
            "Not attempted to send the authorization request. Check out that max_retries > 0",
        );

        let mut result = Err(ErrorKind::Internal(intent_err).into());

        let cache = self.authz_cache.clone();

        for _ in 0..self.max_retries {
            let intent_clone = intent.clone();

            let mut request_builder = self.client.post(&self.uri).set_header(
                http_types::headers::AUTHORIZATION,
                format!("Bearer {}", self.token),
            );

            if let Some(ref user_agent) = self.user_agent {
                request_builder = request_builder
                    .set_header(http_types::headers::USER_AGENT, user_agent.to_owned());
            }

            let request = request_builder.body_json(&payload);

            result = match request {
                Ok(req) => {
                    match future::select(req, Delay::new(self.timeout)).await {
                        Either::Left((Ok(mut resp), _)) => {
                            match resp.body_json::<Vec<String>>().await {
                                Ok(data) => {
                                    if !data.contains(&intent.action().to_owned()) {
                                        // Store the failure result into the cache
                                        if let Some(cache) = cache {
                                            let intent_ = intent.clone();
                                            async_std::task::spawn_blocking(move || {
                                                cache.set(&intent_.to_string(), false)
                                            })
                                            .await
                                        }

                                        let intent_err = IntentError::new(
                                            intent,
                                            "the action forbidden by tenant",
                                        );

                                        return Err(ErrorKind::Forbidden(intent_err).into());
                                    } else {
                                        // Store the success result into the cache
                                        if let Some(cache) = cache {
                                            async_std::task::spawn_blocking(move || {
                                                cache.set(&intent.to_string(), true)
                                            })
                                            .await
                                        }
                                        return Ok(());
                                    }
                                }
                                Err(_) => {
                                    let intent_err = IntentError::new(
                                        intent_clone,
                                        "invalid format of the authorization response",
                                    );

                                    Err(ErrorKind::Network(intent_err).into())
                                }
                            }
                        }
                        Either::Left((Err(err), _)) => {
                            let intent_err = IntentError::new(
                                intent_clone,
                                &format!("error sending the authorization request, {}", &err),
                            );

                            Err(ErrorKind::Network(intent_err).into())
                        }
                        Either::Right((_, _)) => {
                            let intent_err = IntentError::new(
                                intent_clone,
                                "timed out sending the authorization request",
                            );

                            Err(ErrorKind::Network(intent_err).into())
                        }
                    }
                }
                Err(err) => {
                    let intent_err = IntentError::new(
                        intent_clone,
                        &format!("failed to build authorization request, {}", &err),
                    );

                    return Err(ErrorKind::Internal(intent_err).into());
                }
            }
        }

        result
    }

    async fn ban(
        &self,
        subject: AccountId,
        object: Box<dyn IntentObject>,
        value: bool,
        seconds: usize,
    ) -> Result<(), Error> {
        self.authz_cache.as_ref().map(|cache| {
            let cache = cache.clone();
            let ban_key = format!("ban::{}::{}", subject, object.to_vec().join("/"));

            async {
                async_std::task::spawn_blocking(move || {
                    cache.set_ex(&ban_key, value, seconds);
                })
                .await
            }
        });

        Ok(())
    }

    fn box_clone(&self) -> Box<dyn Authorize> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Serialize)]
struct HttpRequest<'a> {
    subject: HttpSubject<'a>,
    object: HttpObject<'a>,
    action: &'a str,
}

impl<'a> HttpRequest<'a> {
    fn new(subject: HttpSubject<'a>, object: HttpObject<'a>, action: &'a str) -> Self {
        Self {
            subject,
            object,
            action,
        }
    }
}

#[derive(Debug, Serialize)]
struct HttpSubject<'a> {
    namespace: &'a str,
    value: &'a str,
}

impl<'a> HttpSubject<'a> {
    fn new(namespace: &'a str, value: &'a str) -> Self {
        Self { namespace, value }
    }
}

#[derive(Debug, Serialize)]
struct HttpObject<'a> {
    namespace: &'a str,
    value: Vec<String>,
}

impl<'a> HttpObject<'a> {
    fn new(namespace: &'a str, value: Vec<String>) -> Self {
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
    pub fn new<A: Authenticable>(subject: &A, object: Box<dyn IntentObject>, action: &str) -> Self {
        Self {
            subject_account_id: subject.as_account_id().to_owned(),
            object: object.to_vec(),
            action: action.to_string(),
        }
    }

    fn subject_account_id(&self) -> &AccountId {
        &self.subject_account_id
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
        _cache: Option<Box<dyn AuthzCache>>,
        _audience: &str,
        ban_f: BanCallback,
    ) -> Result<Client, ConfigurationError>
    where
        A: Authenticable,
    {
        Ok(Box::new(LocalWhitelistClient {
            records: self.records,
            ban_f,
        }))
    }
}

#[derive(Clone)]
pub struct LocalWhitelistClient {
    records: Vec<LocalWhitelistRecord>,
    ban_f: BanCallback,
}

impl fmt::Debug for LocalWhitelistClient {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("LocalWhitelistClient")
            .field("records", &self.records)
            .finish()
    }
}

#[async_trait]
impl Authorize for LocalWhitelistClient {
    async fn authorize(
        &self,
        subject: AccountId,
        object: Box<dyn IntentObject>,
        action: String,
    ) -> Result<(), Error> {
        let record = LocalWhitelistRecord::new(&subject, object.clone(), &action);

        match self.records.iter().find(|&r| r == &record) {
            Some(_) => {
                if (self.ban_f)(subject, object.clone()).await {
                    let intent =
                        Intent::new(record.subject_account_id().clone(), object, record.action());

                    let err = ErrorKind::Forbidden(IntentError::new(intent, "Banned"));
                    Err(err.into())
                } else {
                    Ok(())
                }
            }
            None => {
                let intent =
                    Intent::new(record.subject_account_id().clone(), object, record.action());

                let err = ErrorKind::Forbidden(IntentError::new(intent, "Not allowed"));
                Err(err.into())
            }
        }
    }

    async fn ban(
        &self,
        _subject: AccountId,
        _object: Box<dyn IntentObject>,
        _value: bool,
        _seconds: usize,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn box_clone(&self) -> Box<dyn Authorize> {
        Box::new(self.clone())
    }
}

////////////////////////////////////////////////////////////////////////////////

pub use intent::Object as IntentObject;
pub use svc_authn::Authenticable;

pub use self::error::{Error, Kind as ErrorKind};
pub mod cache;
pub mod error;
pub mod intent;

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
};

use crate::cache::{AuthzCache, Response as CacheResponse};
use crate::error::{ConfigurationError, IntentError};
use crate::intent::Intent;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{Duration, Utc};
use jsonwebtoken::Algorithm;
use reqwest::{
    header::{self, HeaderMap},
    Body,
};
use serde_derive::{Deserialize, Serialize};
use svc_authn::{token::jws_compact, AccountId};

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

    fn http_proxy(&self) -> Option<HttpProxy>;

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
        ban_f: Option<BanCallback>,
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
        f: Option<BanCallback>,
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
                format!(
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

    pub fn http_proxy(&self, audience: &str) -> Option<HttpProxy> {
        if let Some(client) = self.inner.get(audience) {
            client.http_proxy()
        } else {
            None
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
        _ban_f: Option<BanCallback>,
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

    fn http_proxy(&self) -> Option<HttpProxy> {
        None
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
        _ban_f: Option<BanCallback>,
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

    fn http_proxy(&self) -> Option<HttpProxy> {
        None
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
        ban_f: Option<BanCallback>,
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

        let timeout = std::time::Duration::from_secs(self.timeout.unwrap_or(5));

        let mut default_haders = HeaderMap::new();
        default_haders.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token)
                .try_into()
                .map_err(|e| ConfigurationError::new(&format!("Bad header value: {}", e)))?,
        );
        default_haders.insert(
            header::CONTENT_TYPE,
            "application/json"
                .try_into()
                .map_err(|e| ConfigurationError::new(&format!("Bad header value: {}", e)))?,
        );
        let builder = reqwest::Client::builder().timeout(timeout);
        if let Some(ref user_agent) = self.user_agent {
            default_haders.insert(
                header::USER_AGENT,
                user_agent
                    .try_into()
                    .map_err(|e| ConfigurationError::new(&format!("Bad header value: {}", e)))?,
            );
        };

        let client = builder
            .default_headers(default_haders)
            .build()
            .map_err(|err| {
                ConfigurationError::new(&format!(
                    "error converting an authorization config for audience = '{}' into client, {}",
                    audience, &err,
                ))
            })?;

        Ok(Box::new(HttpClient {
            client,
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
    client: reqwest::Client,
    object_ns: String,
    uri: String,
    timeout: std::time::Duration,
    trusted: HashSet<AccountId>,
    token: String,
    authz_cache: Option<Box<dyn AuthzCache>>,
    user_agent: Option<String>,
    max_retries: usize,
    ban_f: Option<BanCallback>,
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

impl HttpClient {
    async fn check_cache(
        &self,
        intent: &Intent,
        object: &Box<dyn IntentObject>,
    ) -> Option<Result<(), Error>> {
        if let Some(ref cache) = self.authz_cache {
            let cache = cache.clone();
            let intent_ = intent.to_string();

            if let Some(wildcard) = object.to_ban_key() {
                let cache_response = tokio::task::spawn_blocking(move || {
                    cache.mget(&[&intent_, &wildcard.join("/")])
                })
                .await
                .expect("Mget panicked");

                match cache_response.get(0..2) {
                    Some([_, CacheResponse::Hit(true)]) => {
                        return Some(Err(ErrorKind::Forbidden(IntentError::new(
                            intent.to_owned(),
                            "banned (cache hit)",
                        ))
                        .into()));
                    }
                    Some([CacheResponse::Hit(result), CacheResponse::Hit(false)]) => {
                        return if *result {
                            Some(Ok(()))
                        } else {
                            Some(Err(ErrorKind::Forbidden(IntentError::new(
                                intent.to_owned(),
                                "the action forbidden by tenant (cache hit)",
                            ))
                            .into()))
                        };
                    }
                    Some([_, _]) => {}
                    _ => {
                        log::warn!("Cache ban request returned improper number of responses, expected 2, got = {:?}", cache_response);
                    }
                }
            } else {
                let cache_response = tokio::task::spawn_blocking(move || cache.get(&intent_))
                    .await
                    .expect("Get panicked");

                if let CacheResponse::Hit(result) = cache_response {
                    return if result {
                        Some(Ok(()))
                    } else {
                        Some(Err(ErrorKind::Forbidden(IntentError::new(
                            intent.to_owned(),
                            "the action forbidden by tenant (cache hit)",
                        ))
                        .into()))
                    };
                }
            }
        }

        None
    }

    async fn check_ban(
        &self,
        intent: &Intent,
        object: &Box<dyn IntentObject>,
        subject: &AccountId,
    ) -> Option<Result<(), Error>> {
        if let Some(ban_key) = object.to_ban_key() {
            let is_banned = match &self.ban_f {
                Some(ban_f) => (ban_f)(subject.to_owned(), object.clone()).await,
                None => false,
            };

            if let Some(ref cache) = self.authz_cache {
                let cache = cache.clone();

                let subject_ = subject.clone();
                tokio::task::spawn_blocking(move || {
                    let ban_key = format!("ban::{}::{}", subject_, ban_key.join("/"));
                    cache.set(&ban_key, is_banned);
                })
                .await
                .expect("Set panicked");
            }

            if is_banned {
                return Some(Err(ErrorKind::Forbidden(IntentError::new(
                    intent.to_owned(),
                    "banned (cache hit)",
                ))
                .into()));
            }
        }

        None
    }

    async fn write_cache(&self, intent: &Intent, value: bool) {
        if let Some(cache) = self.authz_cache.clone() {
            let intent = intent.to_owned();
            tokio::task::spawn_blocking(move || cache.set(&intent.to_string(), value))
                .await
                .expect("Set panicked")
        }
    }

    async fn make_requests(&self, intent: &Intent, payload: &str) -> Result<(), Error> {
        let intent_err = IntentError::new(
            intent.clone(),
            "Not attempted to send the authorization request. Check out that max_retries > 0",
        );

        let mut result = Err(ErrorKind::Internal(intent_err).into());

        for _ in 0..self.max_retries {
            let intent_clone = intent.clone();

            let request = self
                .client
                .post(self.uri.clone())
                .body(payload.to_owned())
                .send();

            result = match request.await {
                Ok(response) => match response.text().await {
                    Ok(body) => {
                        match serde_json::from_str::<Vec<String>>(&body) {
                            Ok(data) => {
                                if data.iter().all(|s| s != intent.action()) {
                                    // Store the failure result into the cache
                                    self.write_cache(&intent, false).await;

                                    let intent_err = IntentError::new(
                                        intent.to_owned(),
                                        "the action forbidden by tenant",
                                    );

                                    return Err(ErrorKind::Forbidden(intent_err).into());
                                } else {
                                    // Store the success result into the cache
                                    self.write_cache(&intent, true).await;

                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                let intent_err = IntentError::new(
                                    intent_clone,
                                    format!("invalid format of the authorization response, err = {:?}, body = {}", e, body),
                                );

                                Err(ErrorKind::Network(intent_err).into())
                            }
                        }
                    }
                    Err(e) => {
                        let intent_err = IntentError::new(
                            intent_clone,
                            format!("Failed to read response body, err = {:?}", e),
                        );

                        result = Err(ErrorKind::Network(intent_err).into());
                        continue;
                    }
                },
                Err(err) => {
                    let intent_err = if err.is_timeout() {
                        IntentError::new(
                            intent_clone,
                            "timed out sending the authorization request",
                        )
                    } else {
                        IntentError::new(
                            intent_clone,
                            format!("error sending the authorization request, {:?}", err),
                        )
                    };

                    Err(ErrorKind::Network(intent_err).into())
                }
            }
        }

        result
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
        if let Some(res) = self.check_cache(&intent, &object).await {
            return res;
        }

        if let Some(res) = self.check_ban(&intent, &object, &subject).await {
            return res;
        }

        let payload = HttpRequest::new(
            HttpSubject::new(subject.audience(), subject.label()),
            HttpObject::new(&self.object_ns, object.to_vec()),
            &action,
        );

        let payload = serde_json::to_string(&payload).map_err(|err| {
            let intent_err = IntentError::new(
                intent.to_owned(),
                format!("Failed to serialize authorization request body, {}", &err),
            );

            let e: Error = ErrorKind::Internal(intent_err).into();
            e
        })?;

        self.make_requests(&intent, &payload).await
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
                tokio::task::spawn_blocking(move || {
                    cache.set_ex(&ban_key, value, seconds);
                })
                .await
            }
        });

        Ok(())
    }

    fn http_proxy(&self) -> Option<HttpProxy> {
        Some(HttpProxy {
            client: self.client.clone(),
            url: self.uri.clone(),
        })
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
        ban_f: Option<BanCallback>,
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
    ban_f: Option<BanCallback>,
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
                let is_banned = match &self.ban_f {
                    Some(ban_f) => (ban_f)(subject, object.clone()).await,
                    None => false,
                };

                if is_banned {
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

    fn http_proxy(&self) -> Option<HttpProxy> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone)]
pub struct HttpProxy {
    client: reqwest::Client,
    url: String,
}

impl HttpProxy {
    pub async fn send_async<T: Into<Body>>(&self, payload: T) -> Result<Bytes, reqwest::Error> {
        self.client
            .post(self.url.clone())
            .body(payload)
            .send()
            .await?
            .bytes()
            .await
    }
}

////////////////////////////////////////////////////////////////////////////////

pub use intent::Object as IntentObject;
pub use svc_authn::Authenticable;

pub use self::error::{Error, Kind as ErrorKind};
pub mod cache;
pub mod error;
pub mod intent;

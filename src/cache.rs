use log::error;
use r2d2_redis::RedisConnectionManager;
use std::sync::Arc;
use std::time::Duration;

pub type ConnectionPool = Arc<Pool<RedisConnectionManager>>;

pub use r2d2_redis::r2d2::Pool;
pub use r2d2_redis::redis::Commands;

pub fn create_pool(url: &str, size: u32, idle_size: Option<u32>, timeout: u64) -> ConnectionPool {
    let manager =
        RedisConnectionManager::new(url).expect("Error creating cache connection manager");
    let pool = Pool::builder()
        .max_size(size)
        .min_idle(idle_size)
        .connection_timeout(Duration::from_secs(timeout))
        .build(manager)
        .expect("Error creating a cache pool");

    Arc::new(pool)
}

pub trait AuthzCache: Send + Sync + std::fmt::Debug {
    fn get(&self, key: &str) -> Response;
    fn mget(&self, keys: &[&str]) -> Vec<Response>;

    fn set(&self, key: &str, value: bool);
    fn set_ex(&self, key: &str, value: bool, expiration_seconds: usize);
    fn box_clone(&self) -> Box<dyn AuthzCache>;
}

impl Clone for Box<dyn AuthzCache> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

#[derive(Debug, Clone)]
pub struct RedisCache {
    pool: ConnectionPool,
    expiration_time: usize,
}

#[derive(Debug)]
pub enum Response {
    Hit(bool),
    Miss,
}

impl RedisCache {
    pub fn new(pool: ConnectionPool, expiration_time: usize) -> Self {
        Self {
            pool,
            expiration_time,
        }
    }

    fn set(&self, key: &str, value: bool, expiration_seconds: usize) {
        if let Ok(mut conn) = self.pool.get() {
            let result: Result<bool, _> = conn.set_ex(key, value as u8, expiration_seconds);
            if Ok(true) == result {
                return;
            }
        }

        error!("Cache is unavailable");
    }

    fn mget(&self, keys: &[&str]) -> Vec<Response> {
        if let Ok(mut conn) = self.pool.get() {
            if let Ok(values) = conn.get::<_, Vec<Option<u32>>>(keys) {
                return values
                    .into_iter()
                    .map(|v| match v {
                        Some(1) => Response::Hit(true),
                        Some(_) => Response::Hit(false),
                        None => Response::Miss,
                    })
                    .collect::<Vec<_>>();
            }
        }

        error!("Cache is unavailable");
        let v: Vec<Response> = vec![];
        v
    }

    fn get(&self, key: &str) -> Response {
        if let Ok(mut conn) = self.pool.get() {
            if let Ok(resp) = conn.get(key) {
                return match resp {
                    Some(1) => Response::Hit(true),
                    Some(_) => Response::Hit(false),
                    None => Response::Miss,
                };
            }
        }

        error!("Cache is unavailable");
        Response::Miss
    }
}

impl AuthzCache for RedisCache {
    fn get(&self, intent: &str) -> Response {
        self.get(intent)
    }

    fn mget(&self, keys: &[&str]) -> Vec<Response> {
        self.mget(keys)
    }

    fn set(&self, key: &str, value: bool) {
        self.set(key, value, self.expiration_time);
    }

    fn set_ex(&self, key: &str, value: bool, expiration_seconds: usize) {
        self.set(key, value, expiration_seconds);
    }

    fn box_clone(&self) -> Box<dyn AuthzCache> {
        Box::new(self.clone())
    }
}

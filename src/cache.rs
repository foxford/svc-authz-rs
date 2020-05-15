use log::error;
use r2d2_redis::{r2d2::Pool, RedisConnectionManager};
use std::sync::Arc;
use std::time::Duration;

type ConnectionPool = Arc<Pool<RedisConnectionManager>>;

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

#[derive(Debug, Clone)]
pub struct Cache {
    pool: ConnectionPool,
    expiration_time: u64,
}

pub(crate) enum Response {
    Hit(bool),
    Miss,
}

impl Cache {
    pub fn new(pool: ConnectionPool, expiration_time: u64) -> Self {
        Self {
            pool,
            expiration_time,
        }
    }

    pub(crate) fn get(&self, key: &str) -> Response {
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

    pub(crate) fn set(&self, key: &str, value: bool) {
        if let Ok(mut conn) = self.pool.get() {
            let result: Result<bool, _> =
                conn.set_ex(key, value as u8, self.expiration_time as usize);
            if Ok(true) == result {
                return;
            }
        }

        error!("Cache is unavailable");
    }
}

//! How a route presents the provider credential upstream.

pub enum Authentication {
    Bearer,
    ApiKey,
}

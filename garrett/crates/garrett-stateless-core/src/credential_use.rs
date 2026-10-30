//! How a route presents the provider credential upstream.

#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub enum Authentication {
    Bearer,
    ApiKey,
}

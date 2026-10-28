//! Configuration files (spec sections 11 and 12). Unknown members are
//! errors; relative paths resolve against the configuration file's directory.
use crate::encoding::{is_kid, is_provider, is_scope, is_text};
use crate::error::{config, Result};
use crate::files::read_public;
use crate::json::{self, Value};
use aivm_secrets_garrett_core::stateless::IssuePolicy;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const PROVIDER_SCHEMA: &str = "garrett-stateless-v1/provider";
pub const BROKER_SCHEMA: &str = "garrett-stateless-v1/broker";
pub const PROXY_SCHEMA: &str = "garrett-stateless-v1/proxy";

struct Fields<'a> {
    map: &'a BTreeMap<String, Value>,
    what: &'static str,
    base: &'a Path,
}

impl<'a> Fields<'a> {
    fn new(
        value: &'a Value,
        what: &'static str,
        base: &'a Path,
        required: &[&str],
        optional: &[&str],
    ) -> Result<Self> {
        let map = value
            .as_object()
            .ok_or_else(|| config(format!("{what} is not an object")))?;
        for name in required {
            if !map.contains_key(*name) {
                return Err(config(format!("{what}: {name} missing")));
            }
        }
        for name in map.keys() {
            if !required.contains(&name.as_str()) && !optional.contains(&name.as_str()) {
                return Err(config(format!("{what}: unknown member {name}")));
            }
        }
        Ok(Self { map, what, base })
    }
    fn present(&self, name: &str) -> Option<&'a Value> {
        self.map.get(name).filter(|v| !matches!(v, Value::Null))
    }
    fn string(&self, name: &str) -> Result<String> {
        self.present(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| config(format!("{}: {name} must be a string", self.what)))
    }
    fn optional_string(&self, name: &str) -> Result<Option<String>> {
        match self.present(name) {
            None => Ok(None),
            Some(_) => self.string(name).map(Some),
        }
    }
    fn checked(&self, name: &str, valid: fn(&str) -> bool) -> Result<String> {
        let value = self.string(name)?;
        if !valid(&value) {
            return Err(config(format!("{}: invalid {name}", self.what)));
        }
        Ok(value)
    }
    fn int(&self, name: &str, default: i64, low: i64, high: i64) -> Result<i64> {
        let value = match self.present(name) {
            None => default,
            Some(v) => v
                .as_int()
                .ok_or_else(|| config(format!("{}: {name} must be an integer", self.what)))?,
        };
        if value < low || value > high {
            return Err(config(format!(
                "{}: {name} must be in {low}..={high}",
                self.what
            )));
        }
        Ok(value)
    }
    fn path(&self, name: &str) -> Result<PathBuf> {
        Ok(self.base.join(self.string(name)?))
    }
    fn optional_path(&self, name: &str) -> Result<Option<PathBuf>> {
        Ok(self.optional_string(name)?.map(|p| self.base.join(p)))
    }
    fn strings(&self, name: &str) -> Result<Vec<String>> {
        let Some(Value::Array(items)) = self.present(name) else {
            return Err(config(format!("{}: {name} must be an array", self.what)));
        };
        items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| config(format!("{}: {name} items must be strings", self.what)))
            })
            .collect()
    }
}

fn load(path: &Path, schema: &str) -> Result<(Value, PathBuf)> {
    let bytes = read_public(path, 1 << 20)?;
    let value = json::parse(&bytes, 1 << 20, 16)
        .map_err(|_| config(format!("{}: not strict JSON", path.display())))?;
    if value.get("schema").and_then(Value::as_str) != Some(schema) {
        return Err(config(format!(
            "{}: schema must be {schema}",
            path.display()
        )));
    }
    let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    Ok((value, base))
}

/// An `https://host[:port]/path` URL without query or fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl HttpsUrl {
    pub fn parse(text: &str) -> Result<Self> {
        let rest = text
            .strip_prefix("https://")
            .ok_or_else(|| config("endpoint must be https"))?;
        if rest.contains(['?', '#', '@', ' ']) {
            return Err(config("endpoint must not have a query, fragment or user"));
        }
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().map_err(|_| config("bad port"))?),
            None => (authority, 443),
        };
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        {
            return Err(config("bad host"));
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
            path: path.to_owned(),
        })
    }
    /// `host` or `host:port` when the port is not 443.
    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
    pub fn to_url(&self) -> String {
        format!("https://{}{}", self.authority(), self.path)
    }
}

/// The OAuth 2.0 client registration of an `oauth` provider (spec section 8).
#[derive(Clone, Debug)]
pub struct OAuthClient {
    pub authorization_url: HttpsUrl,
    pub token_url: HttpsUrl,
    /// `host:port` to connect to instead of resolving `token_url`'s host.
    pub token_address: Option<String>,
    pub token_ca_file: Option<PathBuf>,
    pub client_id: String,
    pub client_secret_file: Option<PathBuf>,
    /// RFC 9207 issuer: required in callbacks when set, refused when absent.
    pub issuer: Option<String>,
    pub scopes: Vec<String>,
    pub default_scope: String,
}

impl OAuthClient {
    /// The scope for a login: the requested one, which must name only
    /// configured scopes, or the default.
    pub fn requested_scope(&self, requested: Option<&str>) -> Result<String> {
        let scope = requested.unwrap_or(&self.default_scope);
        if !is_scope(scope)
            || !scope
                .split(' ')
                .filter(|s| !s.is_empty())
                .all(|s| self.scopes.iter().any(|c| c == s))
        {
            return Err(crate::error::Error::Protocol("invalid_scope"));
        }
        Ok(scope.to_owned())
    }
}

/// How a provider's credentials reach the broker (spec section 7.1). Issuance,
/// renewal and the proxy do not depend on it.
#[derive(Clone, Debug)]
pub enum Acquisition {
    /// The operator supplies each credential with `mint`: no OAuth client,
    /// callback listener, token endpoint or browser.
    Provisioned,
    /// Agent-initiated OAuth authorization code with PKCE.
    OAuth(Box<OAuthClient>),
}

/// A provider as the broker sees it.
#[derive(Clone, Debug)]
pub struct ProviderConfig {
    pub name: String,
    /// Which provider JWT claims surrogates copy under `upstream`.
    pub copy_claims: crate::token::ClaimCopy,
    pub acquisition: Acquisition,
}

const OAUTH_REQUIRED: [&str; 5] = [
    "authorization_url",
    "client_id",
    "default_scope",
    "scopes",
    "token_url",
];
const OAUTH_OPTIONAL: [&str; 4] = [
    "client_secret_file",
    "issuer",
    "token_address",
    "token_ca_file",
];

impl ProviderConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let (value, base) = load(path, PROVIDER_SCHEMA)?;
        let provisioned = match value.get("acquisition") {
            None | Some(Value::Null) => false,
            Some(Value::Str(kind)) if kind == "oauth" => false,
            Some(Value::Str(kind)) if kind == "provisioned" => true,
            Some(_) => return Err(config("provider: acquisition must be oauth or provisioned")),
        };
        let mut required = vec!["name", "schema"];
        let mut optional = vec!["acquisition", "copy_claims"];
        if !provisioned {
            required.extend(OAUTH_REQUIRED);
            optional.extend(OAUTH_OPTIONAL);
        }
        let f = Fields::new(&value, "provider", &base, &required, &optional)?;
        let copy_claims = match f.present("copy_claims") {
            None => crate::token::ClaimCopy::Access,
            Some(Value::Str(all)) if all == "all" => crate::token::ClaimCopy::All,
            Some(Value::Array(_)) => crate::token::ClaimCopy::Only(f.strings("copy_claims")?),
            Some(_) => {
                return Err(config(
                    "provider: copy_claims must be null, \"all\" or a list of names",
                ))
            }
        };
        let name = f.checked("name", is_provider)?;
        if provisioned {
            return Ok(Self {
                name,
                copy_claims,
                acquisition: Acquisition::Provisioned,
            });
        }
        let scopes = f.strings("scopes")?;
        if scopes.len() > 64
            || !scopes
                .iter()
                .all(|s| !s.is_empty() && !s.contains(' ') && is_scope(s))
        {
            return Err(config("provider: invalid scopes"));
        }
        let client = OAuthClient {
            authorization_url: HttpsUrl::parse(&f.string("authorization_url")?)?,
            token_url: HttpsUrl::parse(&f.string("token_url")?)?,
            token_address: f.optional_string("token_address")?,
            token_ca_file: f.optional_path("token_ca_file")?,
            client_id: f.checked("client_id", is_text)?,
            client_secret_file: f.optional_path("client_secret_file")?,
            issuer: match f.optional_string("issuer")? {
                Some(issuer) if is_text(&issuer) => Some(issuer),
                Some(_) => return Err(config("provider: invalid issuer")),
                None => None,
            },
            scopes,
            default_scope: f.string("default_scope")?,
        };
        client.requested_scope(None)?;
        Ok(Self {
            name,
            copy_claims,
            acquisition: Acquisition::OAuth(Box::new(client)),
        })
    }

    /// The OAuth client of an `oauth` provider.
    pub fn oauth(&self) -> Option<&OAuthClient> {
        match &self.acquisition {
            Acquisition::OAuth(client) => Some(client.as_ref()),
            Acquisition::Provisioned => None,
        }
    }
}

/// Whether a deployment keeps mutable state beyond keys and configuration
/// (spec section 9). `Strict` refuses everything that would.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Statelessness {
    /// The default: a broker may run OAuth logins (the transient mailbox)
    /// and a proxy may append to a local audit file.
    Standard,
    /// Keys and static configuration only: no OAuth login mailbox, no
    /// audit file.
    Strict,
}

impl Statelessness {
    fn of(f: &Fields) -> Result<Self> {
        match f.optional_string("stateless")?.as_deref() {
            None | Some("standard") => Ok(Self::Standard),
            Some("strict") => Ok(Self::Strict),
            Some(_) => Err(config(format!(
                "{}: stateless must be standard or strict",
                f.what
            ))),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Strict => "strict",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BrokerConfig {
    pub issuer: String,
    pub audience: String,
    pub replica: String,
    pub agent_listen: String,
    /// The browser endpoint, present exactly when an OAuth provider is.
    pub browser: Option<BrowserEndpoint>,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub agent_ca: PathBuf,
    pub keys: PathBuf,
    pub providers: Vec<ProviderConfig>,
    pub max_lifetime: i64,
    pub max_renew: i64,
    pub login_ttl: i64,
    pub stateless: Statelessness,
}

/// The broker's browser listener and its public URL, the registered OAuth
/// redirect base.
#[derive(Clone, Debug)]
pub struct BrowserEndpoint {
    pub listen: String,
    pub public_url: HttpsUrl,
}

impl BrokerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let (value, base) = load(path, BROKER_SCHEMA)?;
        let f = Fields::new(
            &value,
            "broker",
            &base,
            &[
                "agent_ca",
                "agent_listen",
                "audience",
                "certificate",
                "issuer",
                "keys",
                "private_key",
                "providers",
                "replica",
                "schema",
            ],
            &[
                "browser_listen",
                "login_ttl",
                "max_lifetime",
                "max_renew",
                "public_url",
                "stateless",
            ],
        )?;
        let mut providers = Vec::new();
        for item in f.strings("providers")? {
            providers.push(ProviderConfig::load(&base.join(item))?);
        }
        if providers.is_empty() || providers.len() > 16 {
            return Err(config("broker: between 1 and 16 providers"));
        }
        let mut names: Vec<&str> = providers.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        names.dedup();
        if names.len() != providers.len() {
            return Err(config("broker: duplicate provider names"));
        }
        let stateless = Statelessness::of(&f)?;
        let oauth = providers.iter().any(|p| p.oauth().is_some());
        if oauth && stateless == Statelessness::Strict {
            return Err(config(
                "broker: a strict broker has no OAuth providers (their logins need the mailbox)",
            ));
        }
        let browser =
            match (f.present("browser_listen"), f.present("public_url")) {
                (None, None) if !oauth => None,
                (Some(_), Some(_)) if oauth => {
                    let public_url = HttpsUrl::parse(&f.string("public_url")?)?;
                    if !public_url.path.ends_with('/') {
                        return Err(config("broker: public_url must end with /"));
                    }
                    Some(BrowserEndpoint {
                        listen: f.string("browser_listen")?,
                        public_url,
                    })
                }
                _ => return Err(config(
                    "broker: browser_listen and public_url are required with an OAuth provider, \
                     and refused without one",
                )),
            };
        Ok(Self {
            issuer: f.checked("issuer", is_text)?,
            audience: f.checked("audience", is_text)?,
            replica: f.checked("replica", is_kid)?,
            agent_listen: f.string("agent_listen")?,
            browser,
            certificate: f.path("certificate")?,
            private_key: f.path("private_key")?,
            agent_ca: f.path("agent_ca")?,
            keys: f.path("keys")?,
            providers,
            max_lifetime: f.int("max_lifetime", 3600, 1, 86400)?,
            max_renew: f.int("max_renew", 604800, 0, 2592000)?,
            login_ttl: f.int("login_ttl", 600, 1, 600)?,
            stateless,
        })
    }
}

impl BrokerConfig {
    pub fn provider_names(&self) -> Vec<Vec<u8>> {
        self.providers
            .iter()
            .map(|p| p.name.as_bytes().to_vec())
            .collect()
    }

    /// What this broker issues for: every configured provider, however its
    /// credentials are acquired.
    pub fn issue_policy(&self) -> IssuePolicy {
        IssuePolicy {
            issuer: self.issuer.as_bytes().to_vec(),
            audience: self.audience.as_bytes().to_vec(),
            providers: self.provider_names(),
            max_lifetime: self.max_lifetime,
            max_renew: self.max_renew,
        }
    }

    pub fn provider(&self, name: &str) -> Result<&ProviderConfig> {
        self.providers
            .iter()
            .find(|p| p.name == name)
            .ok_or(crate::error::Error::Protocol("unknown_provider"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authentication {
    Bearer,
    ApiKey,
}

#[derive(Clone, Debug)]
pub struct DenyRule {
    pub method: String,
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct RouteConfig {
    pub provider: String,
    pub host: String,
    pub address: String,
    pub port: u16,
    pub ca_file: Option<PathBuf>,
    pub authentication: Authentication,
    pub deny: Vec<DenyRule>,
}

/// One `read_only` resource: a route's provider, an optional read method
/// and a path (spec section 11.1).
#[derive(Clone, Debug)]
pub struct ResourceConfig {
    pub provider: String,
    pub method: String,
    pub path: String,
}

/// The proxy's operation policy: Garrett's (any operation the deny rules
/// leave) or read-only on the listed resources.
#[derive(Clone, Debug)]
pub enum Operations {
    Unrestricted,
    ReadOnly(Vec<ResourceConfig>),
}

impl Operations {
    pub fn name(&self) -> &'static str {
        match self {
            Operations::Unrestricted => "unrestricted",
            Operations::ReadOnly(_) => "read-only",
        }
    }
}

fn read_only_of(f: &Fields, base: &Path, routes: &[RouteConfig]) -> Result<Operations> {
    let Some(value) = f.present("read_only") else {
        return Ok(Operations::Unrestricted);
    };
    let Value::Array(items) = value else {
        return Err(config("proxy: read_only must be an array"));
    };
    if items.is_empty() || items.len() > 64 {
        return Err(config("proxy: between 1 and 64 read_only resources"));
    }
    let mut resources = Vec::new();
    for item in items {
        let r = Fields::new(
            item,
            "read_only resource",
            base,
            &["path", "provider"],
            &["method"],
        )?;
        let provider = r.string("provider")?;
        if !routes.iter().any(|route| route.provider == provider) {
            return Err(config("read_only resource: provider has no route"));
        }
        let method = r.optional_string("method")?.unwrap_or_default();
        if !matches!(method.as_str(), "" | "GET" | "HEAD") {
            return Err(config("read_only resource: method must be GET or HEAD"));
        }
        let path = r.string("path")?;
        if !path.starts_with('/') {
            return Err(config("read_only resource: path must start with /"));
        }
        resources.push(ResourceConfig {
            provider,
            method,
            path,
        });
    }
    Ok(Operations::ReadOnly(resources))
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen: String,
    pub authority: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub client_ca: PathBuf,
    pub keys: PathBuf,
    pub audiences: Vec<String>,
    pub max_lifetime: i64,
    pub skew: i64,
    pub request_limit: usize,
    pub routes: Vec<RouteConfig>,
    pub audit: Option<PathBuf>,
    pub stateless: Statelessness,
    pub operations: Operations,
}

fn route_of(value: &Value, base: &Path) -> Result<RouteConfig> {
    let f = Fields::new(
        value,
        "route",
        base,
        &["authentication", "host", "provider"],
        &["address", "ca_file", "deny", "port"],
    )?;
    let host = f.string("host")?.to_ascii_lowercase();
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err(config("route: invalid host"));
    }
    let authentication = match f.string("authentication")?.as_str() {
        "bearer" => Authentication::Bearer,
        "api-key" => Authentication::ApiKey,
        _ => return Err(config("route: authentication must be bearer or api-key")),
    };
    let mut deny = Vec::new();
    if let Some(Value::Array(rules)) = f.present("deny") {
        for rule in rules {
            let r = Fields::new(rule, "deny rule", base, &["path"], &["method"])?;
            let path = r.string("path")?;
            if !path.starts_with('/') {
                return Err(config("deny rule: path must start with /"));
            }
            deny.push(DenyRule {
                method: r.optional_string("method")?.unwrap_or_default(),
                path,
            });
        }
    }
    Ok(RouteConfig {
        provider: f.checked("provider", is_provider)?,
        address: f
            .optional_string("address")?
            .unwrap_or_else(|| host.clone()),
        port: f.int("port", 443, 1, 65535)? as u16,
        host,
        ca_file: f.optional_path("ca_file")?,
        authentication,
        deny,
    })
}

impl ProxyConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let (value, base) = load(path, PROXY_SCHEMA)?;
        let f = Fields::new(
            &value,
            "proxy",
            &base,
            &[
                "audiences",
                "authority",
                "certificate",
                "client_ca",
                "keys",
                "listen",
                "private_key",
                "routes",
                "schema",
            ],
            &[
                "audit",
                "max_lifetime",
                "read_only",
                "request_limit",
                "skew",
                "stateless",
            ],
        )?;
        let audiences = f.strings("audiences")?;
        if audiences.is_empty() || audiences.len() > 16 || !audiences.iter().all(|a| is_text(a)) {
            return Err(config("proxy: invalid audiences"));
        }
        let Some(Value::Array(items)) = f.present("routes") else {
            return Err(config("proxy: routes must be an array"));
        };
        let routes = items
            .iter()
            .map(|item| route_of(item, &base))
            .collect::<Result<Vec<_>>>()?;
        if routes.is_empty() || routes.len() > 16 {
            return Err(config("proxy: between 1 and 16 routes"));
        }
        let mut names: Vec<&str> = routes.iter().map(|r| r.provider.as_str()).collect();
        names.sort();
        names.dedup();
        if names.len() != routes.len() {
            return Err(config("proxy: duplicate route providers"));
        }
        let authority = f.string("authority")?.to_ascii_lowercase();
        if authority.is_empty()
            || !authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
        {
            return Err(config("proxy: invalid authority"));
        }
        let stateless = Statelessness::of(&f)?;
        let audit = f.optional_path("audit")?;
        if audit.is_some() && stateless == Statelessness::Strict {
            return Err(config("proxy: a strict proxy writes no audit file"));
        }
        let operations = read_only_of(&f, &base, &routes)?;
        Ok(Self {
            listen: f.string("listen")?,
            authority,
            certificate: f.path("certificate")?,
            private_key: f.path("private_key")?,
            client_ca: f.path("client_ca")?,
            keys: f.path("keys")?,
            audiences,
            max_lifetime: f.int("max_lifetime", 3600, 1, 86400)?,
            skew: f.int("skew", 60, 0, 300)?,
            request_limit: f.int("request_limit", 1 << 20, 1, 16 << 20)? as usize,
            routes,
            audit,
            stateless,
            operations,
        })
    }
}

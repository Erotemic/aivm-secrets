//! Canonical host-selected provider identity. Transport pins do not change
//! the authenticated origin or enter the Python-compatible profile digest.
use super::*;

pub struct Provider {
    canonical: Value,
    pub(crate) name: String,
    pub(crate) client_id: String,
    pub(crate) token_host: String,
    pub(crate) token_path: String,
    pub(crate) resource_host: String,
    pub(crate) digest: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) secret_file: String,
    pub(crate) rotation: bool,
    pub(crate) fallback_ttl: i64,
}
pub(crate) fn hostname(host: &str) -> Outcome<()> {
    if !(4..=253).contains(&host.len()) {
        return Err(Error::InvalidRequest);
    }
    let labels: Vec<_> = host.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.starts_with('-')
                || s.ends_with('-')
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || labels.last().is_some_and(|s| {
            matches!(*s, "local" | "localhost") || s.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}
fn endpoint(uri: &str) -> Outcome<(String, String)> {
    if uri.len() > 2048
        || !uri.bytes().all(|b| (33..=126).contains(&b))
        || uri.contains(['\\', '?', '#'])
    {
        return Err(Error::InvalidRequest);
    }
    let (authority, path) = uri
        .strip_prefix("https://")
        .and_then(|s| s.split_once('/'))
        .ok_or(Error::InvalidRequest)?;
    let host = authority
        .strip_suffix(":443")
        .unwrap_or(authority)
        .to_ascii_lowercase();
    hostname(&host)?;
    Ok((host, format!("/{path}")))
}
impl Provider {
    pub fn from_value(value: &Value) -> Outcome<Self> {
        let m = json::keys(
            value,
            &[
                "schema",
                "name",
                "client_id",
                "authorization_url",
                "token_url",
                "resource_host",
                "callback_port",
                "scopes",
            ],
            &[
                "issuer_response",
                "client_secret_file",
                "refresh_rotation",
                "fallback_ttl",
            ],
        )?;
        json::integer(&m["schema"], 1, 1)?;
        let name = text(value, "name")?;
        if name.is_empty()
            || name.len() > 48
            || !name.as_bytes()[0].is_ascii_lowercase()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
        {
            return Err(Error::InvalidRequest);
        }
        let client_id = text(value, "client_id")?;
        if client_id.is_empty()
            || client_id.len() > 160
            || !client_id.as_bytes()[0].is_ascii_alphanumeric()
            || !client_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(Error::InvalidRequest);
        }
        endpoint(text(value, "authorization_url")?)?;
        let (token_host, token_path) = endpoint(text(value, "token_url")?)?;
        let resource_host = text(value, "resource_host")?;
        hostname(resource_host)?;
        json::integer(&m["callback_port"], 1024, 65535)?;
        let scopes = scope_list(&m["scopes"])?;
        if scopes.is_empty() {
            return Err(Error::InvalidRequest);
        }
        let issuer = m
            .get("issuer_response")
            .map(|v| v.as_str().ok_or(Error::InvalidRequest))
            .transpose()?
            .unwrap_or("");
        if !issuer.is_empty() {
            endpoint(issuer)?;
        }
        let secret_file = m
            .get("client_secret_file")
            .map(|v| v.as_str().ok_or(Error::InvalidRequest))
            .transpose()?
            .unwrap_or("");
        if !secret_file.is_empty()
            && (!Path::new(secret_file).is_absolute() || secret_file.len() > 2048)
        {
            return Err(Error::InvalidRequest);
        }
        let rotation = m
            .get("refresh_rotation")
            .map(|v| v.as_bool().ok_or(Error::InvalidRequest))
            .transpose()?
            .unwrap_or(true);
        if !rotation && secret_file.is_empty() {
            return Err(Error::InvalidRequest);
        }
        let fallback = m
            .get("fallback_ttl")
            .map(|v| json::integer(v, 1, 86400))
            .transpose()?
            .unwrap_or(3600);
        let canonical = json!({"schema":1,"name":name,"client_id":client_id,"authorization_url":m["authorization_url"],"token_url":m["token_url"],"resource_host":resource_host,"callback_port":m["callback_port"],"scopes":scopes,"issuer_response":issuer,"client_secret_file":secret_file,"refresh_rotation":rotation,"fallback_ttl":fallback});
        Ok(Self {
            digest: sha(&json::canonical(&canonical)),
            canonical,
            name: name.into(),
            client_id: client_id.into(),
            token_host,
            token_path,
            resource_host: resource_host.into(),
            scopes,
            secret_file: secret_file.into(),
            rotation,
            fallback_ttl: fallback,
        })
    }
    pub fn from_file(path: &Path) -> Outcome<Self> {
        Self::from_value(&json::parse(
            &files::read_trusted_public(path, 16384)?,
            16384,
        )?)
    }
    pub fn public_profile(&self) -> Value {
        self.canonical.clone()
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn client_secret(&self) -> Outcome<Option<Zeroizing<String>>> {
        if self.secret_file.is_empty() {
            return Ok(None);
        }
        let bytes = Zeroizing::new(files::read_private(Path::new(&self.secret_file), 4096)?);
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::CredentialSource)?
            .trim();
        if text.is_empty() || !text.is_ascii() || text.contains(['\r', '\n']) {
            return Err(Error::CredentialSource);
        }
        Ok(Some(Zeroizing::new(text.to_owned())))
    }
}

//! Narrow, untrusted-side GitHub command translation for the W1 PR-read workflow.
//!
//! This is not a second policy engine. The native manifest broker independently
//! parses and authorizes every operation and argument. There is deliberately no
//! arbitrary `gh api`, command fallback, repository discovery, or write alias.
use aivm_secrets_garrett::{json, Error, Outcome};
use serde_json::{json as value, Map, Value};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandKind {
    View,
    Diff,
    Checks,
}

pub(crate) struct GitHubCommand {
    kind: CommandKind,
    number: i64,
    repository: String,
    fields: Vec<String>,
}

fn repository(value: &str) -> Outcome<String> {
    if value.len() > 200 {
        return Err(Error::InvalidRequest);
    }
    let parts: Vec<&str> = value.split('/').collect();
    if parts.len() != 2 || parts.iter().any(|part| {
        part.is_empty()
            || part.len() > 100
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    }) {
        return Err(Error::InvalidRequest);
    }
    Ok(value.to_ascii_lowercase())
}

impl GitHubCommand {
    pub(crate) fn parse(args: &[String]) -> Outcome<Self> {
        if args.len() < 4 || args[0] != "gh" || args[1] != "pr" {
            return Err(Error::InvalidRequest);
        }
        let kind = match args[2].as_str() {
            "view" => CommandKind::View,
            "diff" => CommandKind::Diff,
            "checks" => CommandKind::Checks,
            _ => return Err(Error::Denied),
        };
        if args[3].is_empty()
            || args[3].len() > 10
            || args[3].starts_with('0')
            || !args[3].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::InvalidRequest);
        }
        let number = args[3].parse::<i64>().map_err(|_| Error::InvalidRequest)?;
        if number <= 0 || number > 2147483647 {
            return Err(Error::InvalidRequest);
        }
        let mut repo = None;
        let mut fields = None;
        let mut i = 4;
        while i < args.len() {
            let option = args[i].as_str();
            let next = args.get(i + 1).ok_or(Error::InvalidRequest)?;
            match option {
                "--repo" | "-R" if repo.is_none() => repo = Some(repository(next)?),
                "--json" if fields.is_none() && kind != CommandKind::Diff => {
                    let allowed: &[&str] = match kind {
                        CommandKind::View => &["number", "title", "headRefOid"],
                        CommandKind::Checks => &["name", "status", "conclusion"],
                        CommandKind::Diff => return Err(Error::InvalidRequest),
                    };
                    let mut selected = Vec::new();
                    let mut seen = BTreeSet::new();
                    for name in next.split(',') {
                        if !allowed.contains(&name) || !seen.insert(name) {
                            return Err(Error::InvalidRequest);
                        }
                        selected.push(name.to_owned());
                    }
                    if selected.is_empty() || selected.len() > allowed.len() {
                        return Err(Error::InvalidRequest);
                    }
                    fields = Some(selected);
                }
                _ => return Err(Error::InvalidRequest),
            }
            i += 2;
        }
        Ok(Self {
            kind,
            number,
            // Deliberately require an explicit repository. No untrusted cwd,
            // remote, environment, or ambient gh configuration is consulted.
            repository: repo.ok_or(Error::InvalidRequest)?,
            fields: fields.unwrap_or_default(),
        })
    }

    pub(crate) fn frame(&self, capability: &str) -> Value {
        let operation = match self.kind {
            CommandKind::View => "pr.view",
            CommandKind::Diff => "pr.diff",
            CommandKind::Checks => "pr.checks",
        };
        value!({"version":1,"capability":capability,"request":{
            "operation":operation,
            "arguments":{"repository":self.repository,"pr":self.number}
        }})
    }

    // Only render broker-selected fields. A producer that returns a different
    // schema fails closed; this never reads a provider response directly.
    pub(crate) fn render(&self, reply: &Value) -> Outcome<Vec<u8>> {
        if reply.get("ok") != Some(&Value::Bool(true)) {
            return Err(Error::Denied);
        }
        let result = reply.get("result").ok_or(Error::InvalidRequest)?;
        if self.kind == CommandKind::Diff {
            return Ok(result
                .get("diff")
                .and_then(Value::as_str)
                .ok_or(Error::InvalidRequest)?
                .as_bytes()
                .to_vec());
        }
        let selected = if self.kind == CommandKind::Checks && !self.fields.is_empty() {
            let rows = result
                .get("checks")
                .and_then(Value::as_array)
                .ok_or(Error::InvalidRequest)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(Value::Object(self.select(row)?));
            }
            Value::Array(out)
        } else if !self.fields.is_empty() {
            Value::Object(self.select(result)?)
        } else {
            result.clone()
        };
        let mut output = json::canonical(&selected);
        output.push(b'\n');
        Ok(output)
    }

    fn select(&self, value: &Value) -> Outcome<Map<String, Value>> {
        let m = value.as_object().ok_or(Error::InvalidRequest)?;
        let mut result = Map::new();
        for name in &self.fields {
            let selected = m.get(name).ok_or(Error::InvalidRequest)?;
            result.insert(name.clone(), selected.clone());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::GitHubCommand;
    use serde_json::json;

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn explicit_read_commands_only() {
        let view = GitHubCommand::parse(&words(&[
            "gh", "pr", "view", "13861", "--repo", "TauCetiProject/TauCeti",
            "--json", "number,title,headRefOid",
        ]))
        .unwrap();
        assert_eq!(view.frame("cap")["request"], json!({
            "operation":"pr.view",
            "arguments":{"repository":"taucetiproject/tauceti","pr":13861}
        }));
        assert_eq!(String::from_utf8(view.render(&json!({"ok":true,"result":{
            "number":13861,"title":"Repair","headRefOid":"a", "private":"unreleased"
        }})).unwrap()).unwrap(), "{\"headRefOid\":\"a\",\"number\":13861,\"title\":\"Repair\"}\n");
        assert!(GitHubCommand::parse(&words(&["gh", "api", "/user"])).is_err());
        assert!(GitHubCommand::parse(&words(&[
            "gh", "pr", "comment", "13861", "--repo", "TauCetiProject/TauCeti"
        ])).is_err());
        assert!(GitHubCommand::parse(&words(&[
            "gh", "pr", "view", "13862", "--repo", "TauCetiProject/TauCeti",
            "--json", "token"
        ])).is_err());
        assert!(GitHubCommand::parse(&words(&[
            "gh", "pr", "view", "13861", "--repo", "TauCetiProject/TauCeti",
            "--repo", "Other/Repo"
        ])).is_err());
    }

    #[test]
    fn cannot_render_raw_data_or_failed_reply() {
        let checks = GitHubCommand::parse(&words(&[
            "gh", "pr", "checks", "13861", "--repo", "TauCetiProject/TauCeti",
            "--json", "name,status",
        ])).unwrap();
        assert_eq!(String::from_utf8(checks.render(&json!({"ok":true,"result":{"checks":[
            {"name":"lean","status":"completed","internal":"private"}
        ]}})).unwrap()).unwrap(), "[{\"name\":\"lean\",\"status\":\"completed\"}]\n");
        assert!(checks.render(&json!({"ok":false,"error":{"code":"denied"}})).is_err());
        assert!(checks.render(&json!({"ok":true,"result":{"raw":[{}]}})).is_err());
    }
}

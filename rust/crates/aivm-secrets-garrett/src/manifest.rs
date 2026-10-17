//! Host-selected declarative HTTPS policy. The operator chooses every route and
//! response disclosure; requests contain only operation names and scalar values.
use crate::{files, json, Error, Outcome};
use aivm_secrets_garrett_core::manifest as core;
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
pub mod disclosure;

const MAX_INT: i64 = 2147483647;
const MAX_TEXT: usize = 16384;
fn bad<T>() -> Outcome<T> {
    Err(Error::InvalidPolicy)
}
fn text(value: &Value, maximum: usize) -> Outcome<&str> {
    let s = value.as_str().ok_or(Error::InvalidPolicy)?;
    if s.is_empty() || s.len() > maximum || s.contains('\0') {
        return bad();
    }
    Ok(s)
}
fn integer(value: &Value, low: i64, high: i64) -> Outcome<i64> {
    json::integer(value, low, high).map_err(|_| Error::InvalidPolicy)
}
fn keys<'a>(v: &'a Value, required: &[&str], optional: &[&str]) -> Outcome<&'a Map<String, Value>> {
    json::keys(v, required, optional).map_err(|_| Error::InvalidPolicy)
}
fn name(value: &str, operation: bool) -> Outcome<()> {
    if value.is_empty()
        || value.len() > if operation { 64 } else { 32 }
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || b == b'_'
                || operation && b".-".contains(&b)
        })
    {
        return bad();
    }
    Ok(())
}
fn segment(value: &str) -> Outcome<()> {
    if value.is_empty()
        || value.len() > 128
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    {
        return bad();
    }
    Ok(())
}
fn media(value: &Value) -> Outcome<String> {
    let s = text(value, 96)?;
    let (a, b) = s.split_once('/').ok_or(Error::InvalidPolicy)?;
    if [a, b].iter().any(|part| {
        part.is_empty()
            || part.len() > 64
            || !part.as_bytes()[0].is_ascii_lowercase()
            || !part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".+-".contains(&b))
    }) {
        return bad();
    }
    Ok(s.into())
}
fn pointer(value: &Value) -> Outcome<Vec<String>> {
    let list = value.as_array().ok_or(Error::InvalidPolicy)?;
    if list.len() > 8 {
        return bad();
    }
    list.iter()
        .map(|v| text(v, 64).map(str::to_owned))
        .collect()
}
fn lookup<'a>(value: &'a Value, at: &[String], code: Error) -> Outcome<&'a Value> {
    let mut value = value;
    for key in at {
        value = value.as_object().and_then(|m| m.get(key)).ok_or(code)?;
    }
    Ok(value)
}
fn object(v: &Value) -> Outcome<&Map<String, Value>> {
    let m = v.as_object().ok_or(Error::InvalidPolicy)?;
    if m.len() > 16 {
        return bad();
    }
    Ok(m)
}
fn boolean(v: Option<&Value>) -> Outcome<bool> {
    v.map(|v| v.as_bool().ok_or(Error::InvalidPolicy))
        .transpose()
        .map(|v| v.unwrap_or(false))
}

fn absolute_path(v: &Value) -> Outcome<()> {
    let path = text(v, 4096)?;
    if !path.starts_with('/')
        || path[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return bad();
    }
    Ok(())
}

// Validate the description without opening files or executing a resolver. The
// live adapter separately requires its actual source to agree with this policy.
fn source(v: &Value) -> Outcome<()> {
    match v.get("kind").and_then(Value::as_str) {
        Some("file") => {
            let m = keys(v, &["kind", "path"], &[])?;
            absolute_path(&m["path"])
        }
        Some("command") => {
            let m = keys(v, &["kind", "argv"], &["inherit_env"])?;
            let argv = m["argv"].as_array().ok_or(Error::InvalidPolicy)?;
            if argv.is_empty() || argv.len() > 32 {
                return bad();
            }
            let mut size = 0;
            for arg in argv {
                size += text(arg, 1024)?.len();
            }
            if size > 8192 {
                return bad();
            }
            let empty = json!([]);
            let env = m
                .get("inherit_env")
                .unwrap_or(&empty)
                .as_array()
                .ok_or(Error::InvalidPolicy)?;
            if env.len() > 32 {
                return bad();
            }
            let mut seen = BTreeSet::new();
            for key in env {
                let key = text(key, 64)?;
                if !key.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_uppercase() || b == b'_' || i > 0 && b.is_ascii_digit()
                }) || !seen.insert(key)
                    || [
                        "BASH_ENV",
                        "ENV",
                        "GH_DEBUG",
                        "LD_AUDIT",
                        "LD_LIBRARY_PATH",
                        "LD_PRELOAD",
                        "PYTHONHOME",
                        "PYTHONPATH",
                        "PYTHONSTARTUP",
                        "SSLKEYLOGFILE",
                    ]
                    .contains(&key)
                {
                    return bad();
                }
            }
            Ok(())
        }
        _ => bad(),
    }
}

#[derive(Clone)]
enum Part {
    Literal(String),
    Parameter(String),
}
impl Part {
    fn parse(v: &str) -> Outcome<Self> {
        if let Some(p) = v.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
            name(p, false)?;
            Ok(Self::Parameter(p.into()))
        } else {
            segment(v)?;
            Ok(Self::Literal(v.into()))
        }
    }
    fn reference(&self) -> Option<&str> {
        match self {
            Self::Parameter(n) => Some(n),
            _ => None,
        }
    }
    fn fill(&self, args: &BTreeMap<String, Value>) -> Outcome<String> {
        match self {
            Self::Literal(v) => Ok(v.clone()),
            Self::Parameter(n) => scalar_string(args.get(n).ok_or(Error::Denied)?),
        }
    }
}
fn template(value: &Value) -> Outcome<Vec<Part>> {
    let s = text(value, 1024)?
        .strip_prefix('/')
        .ok_or(Error::InvalidPolicy)?;
    s.split('/').map(Part::parse).collect()
}
fn references(parts: &[Part]) -> BTreeSet<String> {
    parts
        .iter()
        .filter_map(Part::reference)
        .map(str::to_owned)
        .collect()
}
fn scalar_string(value: &Value) -> Outcome<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) if n.as_i64().is_some() => Ok(n.to_string()),
        _ => Err(Error::InvalidRequest),
    }
}
struct Parameter {
    rule: core::Rule,
}
impl Parameter {
    fn parse(v: &Value, in_query: bool) -> Outcome<Self> {
        if v.is_object() {
            let m = keys(v, &["min", "max"], &[])?;
            let lo = integer(&m["min"], 0, MAX_INT)?;
            let hi = integer(&m["max"], lo, MAX_INT)?;
            return Ok(Self {
                rule: core::Rule::Range(lo, hi),
            });
        }
        let list = v.as_array().ok_or(Error::InvalidPolicy)?;
        if list.is_empty() || list.len() > 256 {
            return bad();
        }
        if list[0].as_i64().is_some() {
            let mut values = BTreeSet::new();
            for v in list {
                if !values.insert(integer(v, 0, MAX_INT)?) {
                    return bad();
                }
            }
            let values = values.into_iter().collect::<Vec<_>>();
            Ok(Self {
                rule: core::Rule::Integers(values),
            })
        } else {
            let mut values = BTreeSet::new();
            for v in list {
                let s = text(v, 128)?;
                if in_query {
                    segment(s)?;
                } else {
                    for part in s.split('/') {
                        segment(part)?;
                    }
                }
                if !values.insert(s.to_owned()) {
                    return bad();
                }
            }
            let values = values.into_iter().collect::<Vec<_>>();
            Ok(Self {
                rule: core::Rule::Texts(values.iter().map(|s| s.as_bytes().to_vec()).collect()),
            })
        }
    }
    fn accepts(&self, v: &Value) -> bool {
        let scalar = match v {
            Value::String(s) => core::Scalar::Text(s.as_bytes().to_vec()),
            Value::Number(n) => match n.as_i64() {
                Some(v) => core::Scalar::Integer(v),
                None => return false,
            },
            _ => return false,
        };
        let witness = match (&self.rule, &scalar) {
            (core::Rule::Integers(values), core::Scalar::Integer(v)) => {
                values.iter().position(|x| x == v).unwrap_or(0)
            }
            (core::Rule::Texts(values), core::Scalar::Text(v)) => {
                values.iter().position(|x| x == v).unwrap_or(0)
            }
            _ => 0,
        };
        core::parameter(&self.rule, &scalar, witness).is_ok()
    }
}
fn raw_arguments(value: &Value) -> Outcome<BTreeMap<String, Value>> {
    let m = json::keys(value, &["operation"], &["arguments"])?;
    let empty = json!({});
    let raw = m
        .get("arguments")
        .unwrap_or(&empty)
        .as_object()
        .ok_or(Error::InvalidRequest)?;
    if raw.len() > 16 {
        return Err(Error::InvalidRequest);
    }
    let mut args = BTreeMap::new();
    for (n, v) in raw {
        name(n, false).map_err(|_| Error::InvalidRequest)?;
        match v {
            Value::Number(_) => {
                json::integer(v, 0, MAX_INT).map_err(|_| Error::InvalidRequest)?;
            }
            Value::String(s) if !s.is_empty() && s.len() <= MAX_TEXT && !s.contains('\0') => (),
            _ => return Err(Error::InvalidRequest),
        };
        args.insert(n.clone(), v.clone());
    }
    Ok(args)
}

struct Field {
    maximum: usize,
    required: bool,
}
struct Requirement {
    at: Vec<String>,
    literal: Option<Value>,
    parameter: Option<String>,
    fold: bool,
}
struct Capture {
    at: Vec<String>,
    format: String,
}
struct Check {
    path: Vec<Part>,
    accept: String,
    requirements: Vec<Requirement>,
    captures: BTreeMap<String, Capture>,
}
impl Check {
    fn parse(v: &Value) -> Outcome<Self> {
        let m = keys(v, &["path", "require"], &["accept", "bind"])?;
        let list = m["require"].as_array().ok_or(Error::InvalidPolicy)?;
        if list.is_empty() || list.len() > 16 {
            return bad();
        }
        let mut requirements = Vec::new();
        for r in list {
            let r = keys(r, &["at"], &["equals", "equals_parameter", "fold"])?;
            if r.contains_key("equals") == r.contains_key("equals_parameter") {
                return bad();
            }
            let literal = r.get("equals").cloned();
            if let Some(v) = &literal {
                if v.as_i64().is_some() {
                    integer(v, 0, MAX_INT)?;
                } else {
                    text(v, 256)?;
                }
            }
            let parameter = r
                .get("equals_parameter")
                .map(|v| {
                    text(v, 32).and_then(|s| {
                        name(s, false)?;
                        Ok(s.to_owned())
                    })
                })
                .transpose()?;
            let fold = boolean(r.get("fold"))?;
            if fold && literal.as_ref().is_some_and(|v| v.as_i64().is_some()) {
                return bad();
            }
            requirements.push(Requirement {
                at: pointer(&r["at"])?,
                literal,
                parameter,
                fold,
            });
        }
        let empty = json!({});
        let mut captures = BTreeMap::new();
        for (n, v) in object(m.get("bind").unwrap_or(&empty))? {
            name(n, false)?;
            let v = keys(v, &["at", "format"], &[])?;
            let format = text(&v["format"], 32)?;
            if !matches!(format, "hex" | "integer" | "segment") {
                return bad();
            }
            captures.insert(
                n.clone(),
                Capture {
                    at: pointer(&v["at"])?,
                    format: format.into(),
                },
            );
        }
        Ok(Self {
            path: template(&m["path"])?,
            accept: media(m.get("accept").unwrap_or(&json!("application/json")))?,
            requirements,
            captures,
        })
    }
    fn parameters(&self) -> BTreeSet<String> {
        let mut p = references(&self.path);
        p.extend(self.requirements.iter().filter_map(|r| r.parameter.clone()));
        p
    }
    fn verify(
        &self,
        args: &BTreeMap<String, Value>,
        facts: &Value,
    ) -> Outcome<BTreeMap<String, Value>> {
        for r in &self.requirements {
            let found = lookup(facts, &r.at, Error::ResourceMismatch)?;
            let expected = r
                .parameter
                .as_ref()
                .and_then(|n| args.get(n))
                .or(r.literal.as_ref())
                .ok_or(Error::ResourceMismatch)?;
            let matches = if r.fold && found.is_string() && expected.is_string() {
                found.as_str().map(str::to_ascii_lowercase)
                    == expected.as_str().map(str::to_ascii_lowercase)
            } else {
                found == expected
            };
            if !matches {
                return Err(Error::ResourceMismatch);
            }
        }
        let mut out = BTreeMap::new();
        for (n, c) in &self.captures {
            let v = lookup(facts, &c.at, Error::ResourceMismatch)?;
            let chosen = (|| -> Outcome<String> {
                match c.format.as_str() {
                    "integer" => Ok(integer(v, 0, MAX_INT)?.to_string()),
                    "hex" => {
                        let s = text(v, 64)?.to_ascii_lowercase();
                        if !matches!(s.len(), 40 | 64) || !s.bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            return bad();
                        }
                        Ok(s)
                    }
                    _ => {
                        let s = text(v, 128)?;
                        segment(s)?;
                        Ok(s.into())
                    }
                }
            })()
            .map_err(|_| Error::ResourceMismatch)?;
            out.insert(n.clone(), json!(chosen));
        }
        Ok(out)
    }
}
struct Graphql {
    document: String,
    operation: String,
    variables: BTreeMap<String, String>,
}
fn graphql(document: &Value, operation: &Value) -> Outcome<(String, String)> {
    let d = text(document, 8192)?;
    let op = text(operation, 64)?;
    if !op.as_bytes()[0].is_ascii_alphabetic() && !op.starts_with('_')
        || !op.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return bad();
    }
    let s = d.trim_start();
    let tail = s.strip_prefix("query").ok_or(Error::InvalidPolicy)?;
    if !tail.chars().next().is_some_and(char::is_whitespace) {
        return bad();
    }
    let tail = tail.trim_start();
    let end = tail
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(tail.len());
    if &tail[..end] != op || !tail[end..].trim_start().starts_with(['(', '{']) {
        return bad();
    }
    let words = d
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|w| matches!(*w, "query" | "mutation" | "subscription"))
        .collect::<Vec<_>>();
    if words != ["query"] {
        return bad();
    }
    Ok((d.into(), op.into()))
}
struct Page {
    size: usize,
    at: Vec<String>,
    parameter: Option<String>,
}
pub struct Operation {
    pub(crate) name: String,
    pub(crate) write: bool,
    method: String,
    path: Vec<Part>,
    query: BTreeMap<String, Part>,
    parameters: BTreeMap<String, Parameter>,
    fields: BTreeMap<String, Field>,
    defaults: BTreeMap<String, Value>,
    fold: Vec<String>,
    requires: Option<String>,
    returns_check: bool,
    accept: String,
    response: String,
    graphql: Option<Graphql>,
    page: Option<Page>,
}
impl Operation {
    fn parse(v: &Value, checks: &BTreeMap<String, Check>) -> Outcome<Self> {
        let m = keys(
            v,
            &["name", "effect"],
            &[
                "method",
                "path",
                "parameters",
                "query",
                "body_fields",
                "response",
                "accept",
                "requires",
                "returns",
                "defaults",
                "fold",
                "page",
                "graphql",
            ],
        )?;
        let n = text(&m["name"], 64)?;
        name(n, true)?;
        let write = match m["effect"].as_str() {
            Some("read") => false,
            Some("write") => true,
            _ => return bad(),
        };
        let requires = m
            .get("requires")
            .map(|v| text(v, 32).map(str::to_owned))
            .transpose()?;
        let check = requires
            .as_ref()
            .map(|n| {
                name(n, false)?;
                checks.get(n).ok_or(Error::InvalidPolicy)
            })
            .transpose()?;
        let returns = m
            .get("returns")
            .map(|v| text(v, 32))
            .transpose()?
            .unwrap_or("response");
        if !matches!(returns, "check" | "response") {
            return bad();
        }
        let returns_check = returns == "check";
        let empty = json!({});
        let raw_query = object(m.get("query").unwrap_or(&empty))?;
        let mut query = BTreeMap::new();
        let mut in_query = BTreeSet::new();
        for (n, v) in raw_query {
            name(n, false)?;
            let p = Part::parse(text(v, 128)?)?;
            if let Some(r) = p.reference() {
                in_query.insert(r.to_owned());
            }
            query.insert(n.clone(), p);
        }
        let mut parameters = BTreeMap::new();
        for (n, v) in object(m.get("parameters").unwrap_or(&empty))? {
            name(n, false)?;
            parameters.insert(n.clone(), Parameter::parse(v, in_query.contains(n))?);
        }
        let mut fields = BTreeMap::new();
        for (n, v) in object(m.get("body_fields").unwrap_or(&empty))? {
            name(n, false)?;
            let (max, optional) = if v.as_i64().is_some() {
                (integer(v, 1, MAX_TEXT as i64)?, false)
            } else {
                let v = keys(v, &["max_bytes"], &["optional"])?;
                (
                    integer(&v["max_bytes"], 1, MAX_TEXT as i64)?,
                    boolean(v.get("optional"))?,
                )
            };
            fields.insert(
                n.clone(),
                Field {
                    maximum: max as usize,
                    required: !optional,
                },
            );
        }
        let method = m
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let response = m
            .get("response")
            .map(|v| text(v, 32))
            .transpose()?
            .unwrap_or("json")
            .to_owned();
        let path = if returns_check {
            if check.is_none()
                || write
                || [
                    "method",
                    "path",
                    "query",
                    "body_fields",
                    "response",
                    "accept",
                    "page",
                ]
                .iter()
                .any(|n| m.contains_key(*n))
            {
                return bad();
            }
            Vec::new()
        } else {
            if !matches!(method.as_str(), "GET" | "POST" | "PATCH")
                || !matches!(response.as_str(), "json" | "text")
            {
                return bad();
            }
            if method != "GET" && !write && !m.contains_key("graphql") {
                return bad();
            }
            template(m.get("path").ok_or(Error::InvalidPolicy)?)?
        };
        let accept = media(m.get("accept").unwrap_or(&json!(if response == "json" {
            "application/json"
        } else {
            "text/plain"
        })))?;
        let captured = check
            .map(|c| c.captures.keys().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        let declared = parameters.keys().cloned().collect::<BTreeSet<_>>();
        let named = fields.keys().cloned().collect::<BTreeSet<_>>();
        if !declared.is_disjoint(&named)
            || !declared.is_disjoint(&captured)
            || !named.is_disjoint(&captured)
        {
            return bad();
        }
        let graph = if let Some(v) = m.get("graphql") {
            let g = keys(v, &["document", "operation", "variables"], &[])?;
            if returns_check
                || write
                || method != "POST"
                || !references(&path).is_empty()
                || !query.is_empty()
                || !fields.is_empty()
                || response != "json"
            {
                return bad();
            }
            let (document, operation) = graphql(&g["document"], &g["operation"])?;
            let vars = object(&g["variables"])?;
            if vars.is_empty() {
                return bad();
            }
            let mut variables = BTreeMap::new();
            for (n, v) in vars {
                name(n, false)?;
                let source = text(v, 32)?;
                name(source, false)?;
                if !declared.contains(source) && !captured.contains(source) {
                    return bad();
                }
                variables.insert(n.clone(), source.into());
            }
            Some(Graphql {
                document,
                operation,
                variables,
            })
        } else {
            None
        };
        let mut placed = references(&path);
        placed.extend(in_query);
        if let Some(g) = &graph {
            placed.extend(g.variables.values().cloned());
        }
        if placed
            .iter()
            .any(|n| !declared.contains(n) && !captured.contains(n))
        {
            return bad();
        }
        let mut used = placed
            .intersection(&declared)
            .cloned()
            .collect::<BTreeSet<_>>();
        if let Some(c) = check {
            let p = c.parameters();
            if !p.is_subset(&declared) {
                return bad();
            }
            used.extend(p);
        }
        if used != declared
            || method == "GET" && !fields.is_empty()
            || matches!(method.as_str(), "POST" | "PATCH") && fields.is_empty() && graph.is_none()
        {
            return bad();
        }
        let mut defaults = BTreeMap::new();
        for (n, v) in object(m.get("defaults").unwrap_or(&empty))? {
            if !parameters.get(n).is_some_and(|p| p.accepts(v)) {
                return bad();
            }
            defaults.insert(n.clone(), v.clone());
        }
        let mut fold = Vec::new();
        if let Some(raw) = m.get("fold") {
            let raw = raw.as_array().ok_or(Error::InvalidPolicy)?;
            if raw.len() > 16 {
                return bad();
            }
            for n in raw {
                let n = text(n, 32)?;
                if fold.iter().any(|x| x == n) {
                    return bad();
                }
                match parameters.get(n).map(|p| &p.rule) {
                    Some(core::Rule::Texts(v))
                        if v.iter().all(|v| !v.iter().any(u8::is_ascii_uppercase)) => {}
                    _ => return bad(),
                };
                fold.push(n.into());
            }
        }
        fold.sort();
        let page = if let Some(v) = m.get("page") {
            let v = keys(v, &["size"], &["at", "parameter"])?;
            if response != "json" {
                return bad();
            }
            let p = v
                .get("parameter")
                .map(|v| text(v, 32).map(str::to_owned))
                .transpose()?;
            if let Some(n) = &p {
                if !matches!(
                    parameters.get(n).map(|p| &p.rule),
                    Some(core::Rule::Range(..) | core::Rule::Integers(_))
                ) {
                    return bad();
                }
            }
            Some(Page {
                size: integer(&v["size"], 1, 1000)? as usize,
                at: pointer(v.get("at").unwrap_or(&json!([])))?,
                parameter: p,
            })
        } else {
            None
        };
        Ok(Self {
            name: n.into(),
            write,
            method,
            path,
            query,
            parameters,
            fields,
            defaults,
            fold,
            requires,
            returns_check,
            accept,
            response,
            graphql: graph,
            page,
        })
    }
    fn request(&self, value: &Value) -> Outcome<BTreeMap<String, Value>> {
        let mut args = raw_arguments(value)?;
        for n in &self.fold {
            if let Some(Value::String(s)) = args.get_mut(n) {
                *s = s.to_ascii_lowercase();
            }
        }
        for (n, v) in &self.defaults {
            args.entry(n.clone()).or_insert_with(|| v.clone());
        }
        if args
            .keys()
            .any(|n| !self.parameters.contains_key(n) && !self.fields.contains_key(n))
            || self.parameters.keys().any(|n| !args.contains_key(n))
            || self
                .fields
                .iter()
                .any(|(n, f)| f.required && !args.contains_key(n))
        {
            return Err(Error::InvalidRequest);
        }
        for (n, p) in &self.parameters {
            if !p.accepts(&args[n]) {
                return Err(Error::Denied);
            }
        }
        let mut present = 0;
        for (n, f) in &self.fields {
            if let Some(v) = args.get(n) {
                present += 1;
                let s = v.as_str().ok_or(Error::InvalidRequest)?;
                core::parameter(
                    &core::Rule::Body(f.maximum),
                    &core::Scalar::Text(s.as_bytes().to_vec()),
                    0,
                )
                .map_err(|_| Error::Denied)?;
            }
        }
        if !self.fields.is_empty() && present == 0 {
            return Err(Error::InvalidRequest);
        }
        Ok(args)
    }
    fn effect(&self, args: &BTreeMap<String, Value>) -> Outcome<Effect> {
        let body = if let Some(g) = &self.graphql {
            let mut variables = Map::new();
            for (n, source) in &g.variables {
                variables.insert(n.clone(), args.get(source).ok_or(Error::Denied)?.clone());
            }
            Some(json!({"query":g.document,"operationName":g.operation,"variables":variables}))
        } else if self.method != "GET" {
            Some(Value::Object(
                self.fields
                    .keys()
                    .filter_map(|n| args.get(n).map(|v| (n.clone(), v.clone())))
                    .collect(),
            ))
        } else {
            None
        };
        let path = fill_path(&self.path, args)?;
        let mut query = Vec::new();
        for (n, p) in &self.query {
            let v = p.fill(args)?;
            segment(&v).map_err(|_| Error::Denied)?;
            query.push(format!("{n}={v}"));
        }
        let target = if query.is_empty() {
            path
        } else {
            format!("{path}?{}", query.join("&"))
        };
        if target.len() > 8192 {
            return Err(Error::Denied);
        }
        Ok(Effect {
            method: self.method.clone(),
            target,
            accept: self.accept.clone(),
            response: self.response.clone(),
            body,
            write: self.write,
        })
    }
}
fn fill_path(parts: &[Part], args: &BTreeMap<String, Value>) -> Outcome<String> {
    let mut values = Vec::new();
    for p in parts {
        let v = p.fill(args)?;
        for piece in v.split('/') {
            segment(piece).map_err(|_| Error::Denied)?;
        }
        values.push(v);
    }
    let path = format!("/{}", values.join("/"));
    if !(2..=1024).contains(&path.len()) {
        return Err(Error::Denied);
    }
    Ok(path)
}
#[derive(Clone)]
pub struct Effect {
    pub method: String,
    pub target: String,
    pub accept: String,
    pub response: String,
    pub body: Option<Value>,
    pub write: bool,
}
impl Effect {
    pub fn wire(&self) -> Value {
        json!({"method":self.method,"target":self.target,"accept":self.accept,"response":self.response,"body":self.body,"write":self.write})
    }
}
pub struct Policy {
    pub(crate) host: String,
    pub(crate) authentication: String,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) lifetime: i64,
    pub(crate) maximum_body: usize,
    operations: BTreeMap<String, Operation>,
    checks: BTreeMap<String, Check>,
    document: Value,
}
impl Policy {
    pub fn from_file(path: &Path) -> Outcome<Self> {
        Self::parse(&json::parse(
            &files::read_trusted_public(path, 262144)?,
            262144,
        )?)
    }
    pub fn parse(value: &Value) -> Outcome<Self> {
        let m = keys(
            value,
            &[
                "schema",
                "adapter",
                "service",
                "host",
                "authentication",
                "credential_source",
                "operations",
            ],
            &[
                "egress",
                "headers",
                "checks",
                "cli",
                "lifetime_seconds",
                "max_requests",
                "max_body_bytes",
            ],
        )?;
        integer(&m["schema"], 2, 2)?;
        if m["adapter"] != "https" {
            return bad();
        }
        let service = text(&m["service"], 64)?;
        name(service, true)?;
        let host = text(&m["host"], 253)?;
        crate::oauth_vault::provider::hostname(host).map_err(|_| Error::InvalidPolicy)?;
        let authentication = text(&m["authentication"], 32)?;
        if !matches!(authentication, "bearer" | "x-api-key") {
            return bad();
        }
        // These source/pin declarations are preserved. A native session must
        // explicitly agree with the manifest instead of silently replacing it.
        source(&m["credential_source"])?;
        let empty = json!({});
        let pins = keys(
            m.get("egress").unwrap_or(&empty),
            &[],
            &["address", "port", "ca_file"],
        )?;
        if let Some(port) = pins.get("port") {
            integer(port, 1, 65535)?;
        }
        if let Some(address) = pins.get("address") {
            let address = text(address, 64)?;
            let parsed: std::net::IpAddr = address.parse().map_err(|_| Error::InvalidPolicy)?;
            if parsed.to_string() != address {
                return bad();
            }
        }
        if let Some(ca) = pins.get("ca_file") {
            absolute_path(ca)?;
        }
        let h = m
            .get("headers")
            .unwrap_or(&empty)
            .as_object()
            .ok_or(Error::InvalidPolicy)?;
        if h.len() > 8 {
            return bad();
        }
        let mut headers = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for (n, v) in h {
            let lower = n.to_ascii_lowercase();
            if n.is_empty()
                || n.len() > 64
                || !n
                    .bytes()
                    .enumerate()
                    .all(|(i, b)| b.is_ascii_alphanumeric() || i > 0 && b == b'-')
                || !seen.insert(lower.clone())
                || [
                    "accept",
                    "accept-encoding",
                    "authorization",
                    "connection",
                    "content-encoding",
                    "content-length",
                    "content-type",
                    "cookie",
                    "expect",
                    "forwarded",
                    "host",
                    "keep-alive",
                    "proxy-authorization",
                    "proxy-connection",
                    "te",
                    "trailer",
                    "transfer-encoding",
                    "upgrade",
                    "user-agent",
                    "via",
                    "x-api-key",
                ]
                .contains(&lower.as_str())
                || lower.starts_with("proxy-")
                || lower.starts_with("sec-")
                || lower.starts_with("x-forwarded-")
            {
                return bad();
            }
            let v = text(v, 256)?;
            if !v.bytes().all(|b| (32..=126).contains(&b)) || v.starts_with(' ') || v.ends_with(' ')
            {
                return bad();
            }
            headers.insert(n.clone(), v.into());
        }
        let mut checks = BTreeMap::new();
        for (n, v) in object(m.get("checks").unwrap_or(&empty))? {
            name(n, false)?;
            checks.insert(n.clone(), Check::parse(v)?);
        }
        let raw = m["operations"].as_array().ok_or(Error::InvalidPolicy)?;
        if raw.is_empty() || raw.len() > 64 {
            return bad();
        }
        let mut operations = BTreeMap::new();
        for v in raw {
            let op = Operation::parse(v, &checks)?;
            if operations.insert(op.name.clone(), op).is_some() {
                return bad();
            }
        }
        for n in checks.keys() {
            if !operations.values().any(|o| o.requires.as_ref() == Some(n)) {
                return bad();
            }
        }
        // CLI translation is an untrusted-side convenience, not host authority.
        // Native alias generation is not implemented; reject tables explicitly.
        if m.get("cli").is_some_and(|v| v != &empty) {
            return bad();
        }
        integer(m.get("max_requests").unwrap_or(&json!(200)), 1, 1000)?;
        let lifetime = integer(m.get("lifetime_seconds").unwrap_or(&json!(1800)), 1, 3600)?;
        let maximum_body = integer(
            m.get("max_body_bytes").unwrap_or(&json!(8192)),
            1,
            MAX_TEXT as i64,
        )? as usize;
        Ok(Self {
            host: host.into(),
            authentication: authentication.into(),
            headers,
            lifetime,
            maximum_body,
            operations,
            checks,
            document: value.clone(),
        })
    }
    pub fn document(&self) -> &Value {
        &self.document
    }
    pub fn operations(&self) -> Vec<String> {
        self.operations.keys().cloned().collect()
    }
    pub(crate) fn operation(
        &self,
        value: &Value,
    ) -> Outcome<(&Operation, BTreeMap<String, Value>)> {
        let m = json::keys(value, &["operation"], &["arguments"])?;
        let n = m["operation"].as_str().ok_or(Error::InvalidRequest)?;
        name(n, true).map_err(|_| Error::InvalidRequest)?;
        raw_arguments(value)?;
        let op = self.operations.get(n).ok_or(Error::Denied)?;
        let args = op.request(value)?;
        let size = args
            .iter()
            .filter(|(n, _)| op.fields.contains_key(*n))
            .map(|(_, v)| v.as_str().map(str::len).unwrap_or(0))
            .sum::<usize>();
        if size > self.maximum_body {
            return Err(Error::Denied);
        }
        Ok((op, args))
    }
    pub(crate) fn preflight(
        &self,
        op: &Operation,
        args: &BTreeMap<String, Value>,
    ) -> Outcome<Option<Effect>> {
        op.requires
            .as_ref()
            .map(|n| {
                let c = &self.checks[n];
                Ok(Effect {
                    method: "GET".into(),
                    target: fill_path(&c.path, args)?,
                    accept: c.accept.clone(),
                    response: "json".into(),
                    body: None,
                    write: false,
                })
            })
            .transpose()
    }
    pub(crate) fn final_effect(
        &self,
        op: &Operation,
        args: &BTreeMap<String, Value>,
        facts: &Value,
    ) -> Outcome<Option<Effect>> {
        let mut given = args.clone();
        if let Some(n) = &op.requires {
            given.extend(self.checks[n].verify(args, facts)?);
        }
        if op.returns_check {
            Ok(None)
        } else {
            op.effect(&given).map(Some)
        }
    }
    pub(crate) fn pagination(
        &self,
        op: &Operation,
        args: &BTreeMap<String, Value>,
        result: &Value,
    ) -> Outcome<Option<Value>> {
        op.page
            .as_ref()
            .map(|p| {
                let rows = lookup(result, &p.at, Error::UpstreamResponse)?
                    .as_array()
                    .ok_or(Error::UpstreamResponse)?;
                if rows.len() > p.size {
                    return Err(Error::UpstreamResponse);
                }
                let mut meta = json!({"per_page":p.size,"possibly_more":rows.len()==p.size});
                if let Some(n) = &p.parameter {
                    meta["page"] = args.get(n).cloned().ok_or(Error::InvalidRequest)?;
                }
                Ok(json!({"pagination":meta}))
            })
            .transpose()
    }
    /// Independent compiler runner; facts are test inputs here, never remotely
    /// supplied evidence to the live credentialed execution path.
    pub fn inspect(&self, value: &Value, facts: &Value) -> Outcome<Value> {
        let (op, args) = self.operation(value)?;
        let preflight = self.preflight(op, &args)?;
        let final_effect = self.final_effect(op, &args, facts)?;
        Ok(
            json!({"request":{"operation":op.name,"arguments":args},"preflight":preflight.as_ref().map(Effect::wire),"effect":final_effect.as_ref().map(Effect::wire)}),
        )
    }
}

pub fn evaluate(v: &Value) -> Outcome<Value> {
    let m = json::keys(v, &["version", "policy", "request"], &["facts"])?;
    json::integer(&m["version"], 1, 1)?;
    let policy = Policy::parse(&m["policy"])?;
    let result = policy.inspect(&m["request"], m.get("facts").unwrap_or(&Value::Null))?;
    Ok(json!({"ok":true,"result":result}))
}

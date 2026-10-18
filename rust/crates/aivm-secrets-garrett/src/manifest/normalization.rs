//! Canonical policy identity follows parsed meaning, not optional input spelling.
//! This is a concrete adapter, independently compared with Python's HTTPSpec.
use super::*;

impl Part {
    fn spelling(&self) -> String {
        match self {
            Self::Literal(value) => value.clone(),
            Self::Parameter(name) => format!("{{{name}}}"),
        }
    }
}
fn path(parts: &[Part]) -> String {
    format!(
        "/{}",
        parts
            .iter()
            .map(Part::spelling)
            .collect::<Vec<_>>()
            .join("/")
    )
}
impl Parameter {
    fn wire(&self) -> Outcome<Value> {
        Ok(match &self.rule {
            core::Rule::Range(low, high) => json!({"min":low,"max":high}),
            core::Rule::Integers(values) => json!(values),
            core::Rule::Texts(values) => Value::Array(
                values
                    .iter()
                    .map(|value| {
                        std::str::from_utf8(value)
                            .map(|s| json!(s))
                            .map_err(|_| Error::InvalidPolicy)
                    })
                    .collect::<Outcome<_>>()?,
            ),
            core::Rule::Body(_) => return bad(),
        })
    }
}
impl Check {
    fn wire(&self) -> Outcome<Value> {
        let requirements = self
            .requirements
            .iter()
            .map(|r| {
                let mut value = json!({"at":r.at,"fold":r.fold});
                if let Some(parameter) = &r.parameter {
                    value["equals_parameter"] = json!(parameter);
                } else {
                    value["equals"] = r.literal.clone().ok_or(Error::InvalidPolicy)?;
                }
                Ok(value)
            })
            .collect::<Outcome<Vec<_>>>()?;
        let mut value =
            json!({"path":path(&self.path),"accept":self.accept,"require":requirements});
        if !self.captures.is_empty() {
            value["bind"] = json!(self
                .captures
                .iter()
                .map(|(name, c)| (name.clone(), json!({"at":c.at,"format":c.format})))
                .collect::<Map<_, _>>());
        }
        Ok(value)
    }
}
impl Operation {
    fn wire(&self) -> Outcome<Value> {
        let mut value = json!({"name":self.name,"effect":if self.write {"write"} else {"read"}});
        if self.idempotency_header {
            value["idempotency_header"] = json!("Idempotency-Key");
        }
        if let Some(requires) = &self.requires {
            value["requires"] = json!(requires);
        }
        if self.returns_check {
            value["returns"] = json!("check");
        } else {
            value["method"] = json!(self.method);
            value["path"] = json!(path(&self.path));
            value["response"] = json!(self.response);
            value["accept"] = json!(self.accept);
        }
        if !self.parameters.is_empty() {
            value["parameters"] = Value::Object(
                self.parameters
                    .iter()
                    .map(|(name, p)| Ok((name.clone(), p.wire()?)))
                    .collect::<Outcome<_>>()?,
            );
        }
        if !self.query.is_empty() {
            value["query"] = json!(self
                .query
                .iter()
                .map(|(name, p)| (name.clone(), p.spelling()))
                .collect::<BTreeMap<_, _>>());
        }
        if !self.fields.is_empty() {
            value["body_fields"] = json!(self
                .fields
                .iter()
                .map(|(name, f)| (
                    name.clone(),
                    json!({"max_bytes":f.maximum,"optional":!f.required})
                ))
                .collect::<Map<_, _>>());
        }
        if !self.defaults.is_empty() {
            value["defaults"] = json!(self.defaults);
        }
        if !self.fold.is_empty() {
            value["fold"] = json!(self.fold);
        }
        if let Some(graph) = &self.graphql {
            value["graphql"] = json!({"document":graph.document,"operation":graph.operation,"variables":graph.variables});
        }
        if let Some(page) = &self.page {
            value["page"] = json!({"size":page.size,"at":page.at});
            if let Some(parameter) = &page.parameter {
                value["page"]["parameter"] = json!(parameter);
            }
        }
        Ok(value)
    }
}

pub(super) fn document(
    raw: &Map<String, Value>,
    operations: &BTreeMap<String, Operation>,
    checks: &BTreeMap<String, Check>,
    headers: &BTreeMap<String, String>,
    lifetime: i64,
    maximum_body: usize,
) -> Outcome<Value> {
    let mut source = raw["credential_source"].clone();
    if source["kind"] == "command" {
        let mut env = source.get("inherit_env").cloned().unwrap_or(json!([]));
        env.as_array_mut()
            .ok_or(Error::InvalidPolicy)?
            .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        source["inherit_env"] = env;
    }
    let mut pins = raw.get("egress").cloned().unwrap_or(json!({}));
    pins["port"] = json!(integer(pins.get("port").unwrap_or(&json!(443)), 1, 65535)?);
    Ok(json!({
        "schema":2,"adapter":"https","service":raw["service"],"host":raw["host"],
        "authentication":raw["authentication"],"credential_source":source,
        "egress":pins,"headers":headers,"cli":{},
        "checks":checks.iter().map(|(name,c)|Ok((name.clone(),c.wire()?))).collect::<Outcome<Map<_,_>>>()?,
        "operations":operations.values().map(Operation::wire).collect::<Outcome<Vec<_>>>()?,
        "lifetime_seconds":lifetime,
        "max_requests":integer(raw.get("max_requests").unwrap_or(&json!(200)),1,1000)?,
        "max_body_bytes":maximum_body,
    }))
}

pub(super) fn digest(value: &Value) -> String {
    ring::digest::digest(&ring::digest::SHA256, &json::canonical(value))
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

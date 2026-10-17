//! Native lifecycle administration. Plans contain public state and names only;
//! private bytes stay in zeroizing buffers and immutable protected files.
use super::*;
use aivm_secrets_garrett_core::trust::{self, RecoveryPhase};

#[cfg(test)]
mod tests;

const PLAN_LIMIT: usize = 524288;

fn trust_error(error: trust::TrustDenial) -> Error {
    match error {
        trust::TrustDenial::Stale => Error::Revoked,
        trust::TrustDenial::Unpublished => Error::InternalError,
        trust::TrustDenial::OutcomeUnknown => Error::OutcomeUnknown,
    }
}
fn validate_snapshot(value: &Value) -> Outcome<()> {
    json::keys(value, &["authority", "registry", "keyring"], &[])?;
    let selected = &value["authority"];
    lifecycle::evaluate_authority(&json!({"version":1,"action":"validate","state":selected}))?;
    Registry::parse(
        &value["registry"],
        text(selected, "issuer")?,
        text(selected, "audience")?,
    )?;
    parse_keyring(value["keyring"].clone())?;
    Ok(())
}
fn snapshot(root: &PrivateDirectory) -> Outcome<Value> {
    let selected = selection(root)?;
    ca_public(root, &selected)?;
    Ok(
        json!({"registry":read_registry(root,&selected)?,"authority":selected,"keyring":keyring(root)?}),
    )
}
fn anchor(state: &Value) -> Vec<u8> {
    json::canonical(&json!({"authority":state["authority"],"keyring":state["keyring"]}))
}
fn phase(plan: &Value, current: &Value) -> Outcome<RecoveryPhase> {
    trust::recovery_phase(
        &anchor(current),
        &anchor(&plan["before"]),
        &anchor(&plan["after"]),
        &json::canonical(&current["registry"]),
        &json::canonical(&plan["before"]["registry"]),
        &json::canonical(&plan["after"]["registry"]),
    )
    .map_err(trust_error)
}
fn phase_name(phase: RecoveryPhase) -> &'static str {
    match phase {
        RecoveryPhase::Unchanged => "unchanged",
        RecoveryPhase::Retired => "retired",
        RecoveryPhase::Activated => "activated",
    }
}
fn next_generation(
    root: &PrivateDirectory,
    folder: &str,
    label: &str,
    previous: i64,
    maximum: i64,
) -> Outcome<i64> {
    let directory = root.child(folder)?;
    for next in previous + 1..=maximum {
        if !directory.exists(&format!("{label}-{next}.key"))?
            && !directory.exists(&format!("{label}-{next}.pem"))?
        {
            return Ok(next);
        }
    }
    Err(Error::Exhausted)
}
struct Material {
    directory: &'static str,
    name: String,
    bytes: Zeroizing<Vec<u8>>,
}
impl Material {
    fn new(directory: &'static str, name: String, bytes: &[u8]) -> Self {
        Self {
            directory,
            name,
            bytes: Zeroizing::new(bytes.to_vec()),
        }
    }
    fn metadata(&self) -> Value {
        let mut value = json!({"directory":self.directory,"name":self.name});
        // No hash of a private key/AES secret enters plans, audits or replies.
        if self.name.ends_with(".pem") || self.name.ends_with(".pub") {
            value["public_sha256"] = json!(sha(&self.bytes));
        }
        value
    }
}

/// Validate the entire closed plan again on recovery. It cannot carry an
/// arbitrary file write, different issuer/audience, or restored enrollment.
fn validate_plan(plan: &Value) -> Outcome<()> {
    json::keys(
        plan,
        &[
            "schema",
            "operation",
            "created_at",
            "before",
            "after",
            "materials",
        ],
        &[],
    )?;
    json::integer(&plan["schema"], 1, 1)?;
    json::integer(&plan["created_at"], 0, i64::MAX)?;
    validate_snapshot(&plan["before"])?;
    validate_snapshot(&plan["after"])?;
    let before = &plan["before"];
    let after = &plan["after"];
    let operation = text(plan, "operation")?;
    let mut expected = before.clone();
    let mut names = Vec::<(String, String)>::new();
    match operation {
        "rotate-ca" | "renew-server" => {
            let mut transition = json!({"version":1,"action":operation,"state":before["authority"],"server_generation":after["authority"]["server"]["generation"]});
            if operation == "rotate-ca" {
                transition["ca_generation"] = after["authority"]["ca"]["generation"].clone();
                transition["ca_sha256"] = after["authority"]["ca"]["sha256"].clone();
                expected["registry"] = registry::evaluate(&json!({"version":1,"action":"revoke-all","issuer":before["authority"]["issuer"],"audience":before["authority"]["audience"],"state":before["registry"]}))?["state"].clone();
                let generation = number(&after["authority"]["ca"], "generation")?;
                names.extend([
                    ("ca-generations".into(), format!("ca-{generation}.key")),
                    ("ca-generations".into(), format!("ca-{generation}.pem")),
                ]);
            }
            expected["authority"] = lifecycle::evaluate_authority(&transition)?["state"].clone();
            let generation = number(&after["authority"]["server"], "generation")?;
            names.extend([
                (
                    "server-generations".into(),
                    format!("server-{generation}.key"),
                ),
                (
                    "server-generations".into(),
                    format!("server-{generation}.pem"),
                ),
            ]);
        }
        "rotate-issuer" => {
            let ring = &before["keyring"];
            let kid = text(&after["keyring"], "active")?;
            let index = kid
                .strip_prefix("local-")
                .and_then(|n| n.parse::<i64>().ok())
                .ok_or(Error::InvalidCapability)?;
            let enabled = ring["enabled"].as_array().ok_or(Error::InvalidCapability)?;
            if enabled.len() >= 8
                || index < number(ring, "next_number")?
                || index >= 100000
                || format!("local-{index}") != kid
                || enabled.contains(&json!(kid))
            {
                return Err(Error::InvalidCapability);
            }
            expected["keyring"]["active"] = json!(kid);
            expected["keyring"]["next_number"] = json!(index + 1);
            expected["keyring"]["enabled"]
                .as_array_mut()
                .ok_or(Error::InvalidCapability)?
                .push(json!(kid));
            for suffix in ["key", "pub", "aes256"] {
                names.push(("issuer-keys".into(), format!("{kid}.{suffix}")));
            }
        }
        "retire-issuer" => {
            let old = before["keyring"]["enabled"]
                .as_array()
                .ok_or(Error::InvalidCapability)?;
            let new = after["keyring"]["enabled"]
                .as_array()
                .ok_or(Error::InvalidCapability)?;
            let removed: Vec<_> = old.iter().filter(|v| !new.contains(v)).collect();
            if removed.len() != 1 || *removed[0] == before["keyring"]["active"] {
                return Err(Error::Denied);
            }
            expected["keyring"]["enabled"] = json!(old
                .iter()
                .filter(|v| **v != *removed[0])
                .collect::<Vec<_>>());
        }
        _ => return Err(Error::InvalidRequest),
    }
    if expected != *after {
        return Err(Error::InvalidCapability);
    }
    let materials = plan["materials"]
        .as_array()
        .ok_or(Error::InvalidCapability)?;
    if materials.len() != names.len() {
        return Err(Error::InvalidCapability);
    }
    for (entry, (directory, name)) in materials.iter().zip(names) {
        let public = name.ends_with(".pem") || name.ends_with(".pub");
        if public {
            json::keys(entry, &["directory", "name", "public_sha256"], &[])?;
            json::hex(&entry["public_sha256"], 64)?;
        } else {
            json::keys(entry, &["directory", "name"], &[])?;
        }
        if entry["directory"] != directory || entry["name"] != name {
            return Err(Error::InvalidCapability);
        }
    }
    Ok(())
}
fn verify_materials(root: &PrivateDirectory, plan: &Value) -> Outcome<()> {
    validate_plan(plan)?;
    for entry in plan["materials"]
        .as_array()
        .ok_or(Error::InvalidCapability)?
    {
        let data = Zeroizing::new(
            root.child(text(entry, "directory")?)?
                .read(text(entry, "name")?, 65536)?,
        );
        if let Some(hash) = entry.get("public_sha256") {
            if hash != &json!(sha(&data)) {
                return Err(Error::InvalidCapability);
            }
        }
    }
    let selected = &plan["after"]["authority"];
    let operation = text(plan, "operation")?;
    if matches!(operation, "rotate-ca" | "renew-server") {
        let ca_pem = ca_public(root, selected)?;
        if operation == "rotate-ca" {
            let key = Zeroizing::new(root.child("ca-generations")?.read(
                &format!("ca-{}.key", number(&selected["ca"], "generation")?),
                8192,
            )?);
            CertificateAuthority::from_pem(&ca_pem, &key)?;
        }
        let directory = root.child("server-generations")?;
        let generation = number(&selected["server"], "generation")?;
        let certificate = directory.read(&format!("server-{generation}.pem"), 65536)?;
        let key = Zeroizing::new(directory.read(&format!("server-{generation}.key"), 8192)?);
        let leaf = certificates::inspect_server(&certificate, &ca_pem)?;
        if leaf.not_after
            != number(plan, "created_at")?
                .checked_add(2592000)
                .ok_or(Error::InvalidCapability)?
        {
            return Err(Error::InvalidCapability);
        }
        tls::server_config(&certificate, &key, &ca_pem)?;
    } else if operation == "rotate-issuer" {
        let kid = text(&plan["after"]["keyring"], "active")?;
        let directory = root.child("issuer-keys")?;
        let key = Zeroizing::new(directory.read(&format!("{kid}.key"), 4096)?);
        let public = directory.read(&format!("{kid}.pub"), 4096)?;
        let aes = Zeroizing::new(directory.read(&format!("{kid}.aes256"), 32)?);
        Issuer::from_pem(&key, &public, &aes, kid)?;
    }
    Ok(())
}

struct PlannedChange<'a> {
    root: &'a PrivateDirectory,
    plan: Value,
    material: Option<Vec<Material>>,
    audit: Mutex<File>,
    intent: Value,
}
impl PlannedChange<'_> {
    fn record(&self, value: &Value) -> Result<(), core::StorageFailure> {
        let mut file = self
            .audit
            .lock()
            .map_err(|_| core::StorageFailure::Failed)?;
        file.write_all(&json::canonical(value))
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|_| core::StorageFailure::Failed)
    }
    fn publish(&self, name: &str, key: &str) -> Outcome<()> {
        let current = json::parse(&self.root.read(name, 131072)?, 131072)?;
        let after = &self.plan["after"][key];
        if current == *after {
            return Ok(());
        }
        if current != self.plan["before"][key] {
            return Err(Error::Revoked);
        }
        self.root.replace(name, &json::canonical(after))
    }
}
impl trust::TrustStore for PlannedChange<'_> {
    fn intent(&self) -> Result<(), core::StorageFailure> {
        self.record(&self.intent)
    }
    fn stage(&self) -> Result<(), core::StorageFailure> {
        let stage = || -> Outcome<()> {
            if let Some(material) = &self.material {
                for entry in material {
                    self.root
                        .child(entry.directory)?
                        .write_new(&entry.name, &entry.bytes)?;
                }
            }
            // Recovery verifies existing complete materials; it never repairs,
            // overwrites or adopts a partially written private key.
            verify_materials(self.root, &self.plan)
        };
        stage().map_err(|_| core::StorageFailure::Failed)
    }
    fn retire(&self) -> Result<(), core::StorageFailure> {
        self.publish("enrollments.json", "registry")
            .map_err(|_| core::StorageFailure::Failed)
    }
    fn activate(&self) -> Result<(), core::StorageFailure> {
        let activate = || -> Outcome<()> {
            if read_registry(self.root, &self.plan["before"]["authority"])?
                != self.plan["after"]["registry"]
            {
                return Err(Error::Revoked);
            }
            if text(&self.plan, "operation")?.ends_with("issuer") {
                self.publish("issuer-keyring.json", "keyring")
            } else {
                self.publish("authority.json", "authority")
            }
        };
        activate().map_err(|_| core::StorageFailure::Failed)
    }
    fn complete(&self) -> Result<(), core::StorageFailure> {
        self.record(&json!({"schema":2,"seq":1,"prev":sha(&json::canonical(&self.intent)),"channel":self.intent["channel"],"event":"identity_recorded","request_id":"","timestamp":self.intent["timestamp"],"code":"","digest":self.intent["digest"]}))
    }
}

impl IdentityAuthority {
    fn transaction_directory(&self) -> Outcome<PrivateDirectory> {
        if self.root.exists("transactions")? {
            self.root.child("transactions")
        } else {
            self.root.create_directory("transactions")
        }
    }
    fn read_plan(&self, id: &str) -> Outcome<Value> {
        json::hex(&json!(id), 32)?;
        let directory = self.root.child("transactions")?.child(id)?;
        let plan = json::parse(&directory.read("plan.json", PLAN_LIMIT)?, PLAN_LIMIT)?;
        validate_plan(&plan)?;
        Ok(plan)
    }
    fn planned_change(
        &self,
        id: &str,
        plan: Value,
        material: Option<Vec<Material>>,
        now: i64,
        recovery: bool,
    ) -> Outcome<PlannedChange<'_>> {
        let operation = text(&plan, "operation")?;
        let event = match operation {
            "rotate-ca" => "identity_ca_rotate_intent",
            "renew-server" => "identity_server_renew_intent",
            "rotate-issuer" => "identity_key_rotate_intent",
            "retire-issuer" => "identity_key_retire_intent",
            _ => return Err(Error::InvalidRequest),
        };
        let channel = files::random_id()?;
        let directory = self.root.child("audit")?;
        let audit = directory.create_file(&format!("{channel}.jsonl"))?;
        directory.sync()?;
        let digest = sha(&json::canonical(&plan));
        let intent = json!({"schema":2,"seq":0,"prev":"0".repeat(64),"channel":channel,"event":event,"request_id":"","timestamp":now,"code":"","resource":{"subject":"issuer","transaction":id,"recovery":recovery},"digest":digest});
        Ok(PlannedChange {
            root: &self.root,
            plan,
            material,
            audit: Mutex::new(audit),
            intent,
        })
    }
    fn run_plan(
        &self,
        id: &str,
        plan: Value,
        material: Option<Vec<Material>>,
        now: i64,
        recovery: bool,
    ) -> Outcome<Value> {
        let current = snapshot(&self.root)?;
        phase(&plan, &current)?;
        let digest = sha(&json::canonical(&plan));
        let transaction = self.planned_change(id, plan, material, now, recovery)?;
        // The common exclusive lease covers this preflight and all effects.
        let expected = if recovery {
            anchor(&current)
        } else {
            anchor(&transaction.plan["before"])
        };
        trust::commit_trust(&transaction, &anchor(&current), &expected).map_err(trust_error)?;
        // Publication has completed. Even a subsequent metadata read/reply
        // preparation failure must not imply unchanged authority.
        let mut result = self
            .plan_result(&transaction.plan)
            .map_err(|_| Error::OutcomeUnknown)?;
        result["transaction"] = json!(id);
        result["plan_sha256"] = json!(digest);
        if recovery {
            result["recovered"] = json!(true);
        }
        Ok(result)
    }
    fn prepare_plan(
        &self,
        operation: &str,
        before: Value,
        after: Value,
        material: Vec<Material>,
        now: i64,
    ) -> Outcome<Value> {
        let plan = json!({"schema":1,"operation":operation,"created_at":now,"before":before,"after":after,"materials":material.iter().map(Material::metadata).collect::<Vec<_>>()});
        validate_plan(&plan)?;
        let bytes = json::canonical(&plan);
        if bytes.len() > PLAN_LIMIT {
            return Err(Error::InvalidCapability);
        }
        let id = files::random_id()?;
        let directory = self.transaction_directory()?.create_directory(&id)?;
        directory.write_new("plan.json", &bytes)?;
        self.run_plan(&id, plan, Some(material), now, false)
    }
    fn plan_result(&self, plan: &Value) -> Outcome<Value> {
        let selected = &plan["after"]["authority"];
        match text(plan, "operation")? {
            "rotate-issuer" | "retire-issuer" => Ok(
                json!({"active":plan["after"]["keyring"]["active"],"enabled":plan["after"]["keyring"]["enabled"]}),
            ),
            "renew-server" => {
                let generation = number(&selected["server"], "generation")?;
                let certificate = self
                    .root
                    .child("server-generations")?
                    .read(&format!("server-{generation}.pem"), 65536)?;
                let leaf =
                    certificates::inspect_server(&certificate, &ca_public(&self.root, selected)?)?;
                Ok(
                    json!({"generation":generation,"certificate_sha256":crypto::certificate_thumbprint(&leaf.der)?,"not_after":leaf.not_after,"restart_required":true}),
                )
            }
            "rotate-ca" => {
                let revoked:Vec<_> = plan["before"]["registry"]["subjects"].as_object().ok_or(Error::InvalidCapability)?.iter().filter(|(_,r)|r["active"]==true).map(|(s,r)|json!({"subject":s,"epoch":r["epoch"],"certificate_sha256":r["certificate_sha256"]})).collect();
                Ok(
                    json!({"ca_generation":selected["ca"]["generation"],"ca_sha256":selected["ca"]["sha256"],"server_generation":selected["server"]["generation"],"enrollments_revoked":true,"revoked":revoked,"restart_required":true}),
                )
            }
            _ => Err(Error::InvalidRequest),
        }
    }
    pub fn rotate_issuer(&self, now: i64) -> Outcome<Value> {
        json::integer(&json!(now), 0, i64::MAX)?;
        let _lease = self.root.lock(true)?;
        self.current()?;
        let before = snapshot(&self.root)?;
        if before["keyring"]["enabled"]
            .as_array()
            .ok_or(Error::InvalidCapability)?
            .len()
            >= 8
        {
            return Err(Error::Exhausted);
        }
        let directory = self.root.child("issuer-keys")?;
        let mut index = number(&before["keyring"], "next_number")?;
        // Failed immutable stages are preserved. Allocate a different name;
        // never overwrite or infer that a partial key was approved.
        while index < 100000
            && ["key", "pub", "aes256"]
                .iter()
                .map(|s| directory.exists(&format!("local-{index}.{s}")))
                .collect::<Outcome<Vec<_>>>()?
                .into_iter()
                .any(|v| v)
        {
            index += 1;
        }
        if index >= 100000 {
            return Err(Error::Exhausted);
        }
        let kid = format!("local-{index}");
        let (key, public, aes) = crypto::issuer_material()?;
        let mut after = before.clone();
        after["keyring"]["active"] = json!(kid);
        after["keyring"]["next_number"] = json!(index + 1);
        after["keyring"]["enabled"]
            .as_array_mut()
            .ok_or(Error::InvalidCapability)?
            .push(json!(kid));
        self.prepare_plan(
            "rotate-issuer",
            before,
            after,
            vec![
                Material::new("issuer-keys", format!("{kid}.key"), key.as_bytes()),
                Material::new("issuer-keys", format!("{kid}.pub"), public.as_bytes()),
                Material::new("issuer-keys", format!("{kid}.aes256"), &aes),
            ],
            now,
        )
    }
    pub fn retire_issuer(&self, kid: &str, now: i64) -> Outcome<Value> {
        json::integer(&json!(now), 0, i64::MAX)?;
        let _lease = self.root.lock(true)?;
        self.current()?;
        let before = snapshot(&self.root)?;
        let enabled = before["keyring"]["enabled"]
            .as_array()
            .ok_or(Error::InvalidCapability)?;
        if before["keyring"]["active"] == kid || !enabled.contains(&json!(kid)) {
            return Err(Error::Denied);
        }
        let mut after = before.clone();
        after["keyring"]["enabled"] =
            json!(enabled.iter().filter(|v| **v != kid).collect::<Vec<_>>());
        self.prepare_plan("retire-issuer", before, after, Vec::new(), now)
    }
    pub fn renew_server(&self, now: i64) -> Outcome<Value> {
        let _lease = self.root.lock(true)?;
        let selected = self.current()?;
        let before = snapshot(&self.root)?;
        let generation = next_generation(
            &self.root,
            "server-generations",
            "server",
            number(&selected["server"], "generation")?,
            2048,
        )?;
        let (certificate, key) = self.ca(&selected)?.server_material(now)?;
        let mut after = before.clone();
        after["authority"] = lifecycle::evaluate_authority(&json!({"version":1,"action":"renew-server","state":selected,"server_generation":generation}))?["state"].clone();
        self.prepare_plan(
            "renew-server",
            before,
            after,
            vec![
                Material::new(
                    "server-generations",
                    format!("server-{generation}.key"),
                    key.as_bytes(),
                ),
                Material::new(
                    "server-generations",
                    format!("server-{generation}.pem"),
                    certificate.as_bytes(),
                ),
            ],
            now,
        )
    }
    pub fn rotate_ca(&self, expected_ca_sha256: &str, now: i64) -> Outcome<Value> {
        let _lease = self.root.lock(true)?;
        let selected = self.current()?;
        json::hex(&json!(expected_ca_sha256), 64)?;
        trust::require_root(
            &text(&selected["ca"], "sha256")?.as_bytes().to_vec(),
            &expected_ca_sha256.as_bytes().to_vec(),
        )
        .map_err(trust_error)?;
        let before = snapshot(&self.root)?;
        let ca_generation = next_generation(
            &self.root,
            "ca-generations",
            "ca",
            number(&selected["ca"], "generation")?,
            64,
        )?;
        let server_generation = next_generation(
            &self.root,
            "server-generations",
            "server",
            number(&selected["server"], "generation")?,
            2048,
        )?;
        let ca = CertificateAuthority::generate(now)?;
        let (server, server_key) = ca.server_material(now)?;
        let ca_pem = ca.certificate_pem();
        let ca_hash = sha(&certificates::checked_ca_der(ca_pem.as_bytes())?);
        let mut after = before.clone();
        after["authority"] = lifecycle::evaluate_authority(&json!({"version":1,"action":"rotate-ca","state":selected,"ca_generation":ca_generation,"ca_sha256":ca_hash,"server_generation":server_generation}))?["state"].clone();
        after["registry"] =
            self.evaluate_registry(&before["registry"], "revoke-all", json!({}))?["state"].clone();
        self.prepare_plan(
            "rotate-ca",
            before,
            after,
            vec![
                Material::new(
                    "ca-generations",
                    format!("ca-{ca_generation}.key"),
                    ca.secret_pem().as_bytes(),
                ),
                Material::new(
                    "ca-generations",
                    format!("ca-{ca_generation}.pem"),
                    ca_pem.as_bytes(),
                ),
                Material::new(
                    "server-generations",
                    format!("server-{server_generation}.key"),
                    server_key.as_bytes(),
                ),
                Material::new(
                    "server-generations",
                    format!("server-{server_generation}.pem"),
                    server.as_bytes(),
                ),
            ],
            now,
        )
    }
    pub fn transaction_status(&self, id: &str) -> Outcome<Value> {
        let _lease = self.root.lock(false)?;
        self.current()?;
        let plan = self.read_plan(id)?;
        let current = snapshot(&self.root)?;
        let status = phase(&plan, &current).map(phase_name).unwrap_or("conflict");
        Ok(
            json!({"transaction":id,"plan_sha256":sha(&json::canonical(&plan)),"phase":status,"materials_ready":verify_materials(&self.root,&plan).is_ok(),"plan":plan}),
        )
    }
    pub fn transactions(&self) -> Outcome<Value> {
        let _lease = self.root.lock(false)?;
        self.current()?;
        if !self.root.exists("transactions")? {
            return Ok(json!({"transactions":[]}));
        }
        let current = snapshot(&self.root)?;
        let mut entries = Vec::new();
        for id in self.root.child("transactions")?.names()? {
            match self.read_plan(&id) {
                Ok(plan) => entries.push(json!({"transaction":id,"operation":plan["operation"],"created_at":plan["created_at"],"plan_sha256":sha(&json::canonical(&plan)),"phase":phase(&plan,&current).map(phase_name).unwrap_or("conflict")})),
                Err(error) => entries.push(json!({"transaction":id,"phase":"invalid-plan","error":{"code":error.code()}})),
            }
        }
        Ok(json!({"transactions":entries}))
    }
    pub fn recover_transaction(
        &self,
        id: &str,
        expected_plan_sha256: &str,
        now: i64,
    ) -> Outcome<Value> {
        json::integer(&json!(now), 0, i64::MAX)?;
        json::hex(&json!(expected_plan_sha256), 64)?;
        let _lease = self.root.lock(true)?;
        self.current()?;
        let plan = self.read_plan(id)?;
        trust::require_root(
            &sha(&json::canonical(&plan)).into_bytes(),
            &expected_plan_sha256.as_bytes().to_vec(),
        )
        .map_err(trust_error)?;
        phase(&plan, &snapshot(&self.root)?)?;
        verify_materials(&self.root, &plan)?;
        if matches!(text(&plan, "operation")?, "rotate-ca" | "renew-server") {
            let created = number(&plan, "created_at")? as i128;
            if (now as i128) < created - 60 || (now as i128) >= created + 2592000 {
                return Err(Error::Expired);
            }
        }
        self.run_plan(id, plan, None, now, true)
    }
}

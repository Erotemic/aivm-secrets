//! Source-owned native selected-value release pipeline.
//!
//! `select` calls the five steps in one fixed order and returns no reply if a
//! current-control check, pagination, projection or reflection check fails.
//! `Manifest` is the production instance: every step except the native
//! current-control callback is extracted Rust over the provider document,
//! so the released wire value is a function of the document, the host schema,
//! the page specification, the guest's page argument and the credential.

use crate::disclosure::{Field, Json};
use crate::json_wire;

pub trait Work {
    type Metadata;
    type Selected;
    type Reply;
    type Released;
    type Error;

    fn current(&mut self) -> Result<(), Self::Error>;
    fn pagination(&mut self) -> Result<Option<Self::Metadata>, Self::Error>;
    fn project(&mut self) -> Result<Self::Selected, Self::Error>;
    fn assemble(&mut self, selected: Self::Selected, metadata: Option<Self::Metadata>) -> Self::Reply;
    fn check_safe(&mut self, reply: Self::Reply) -> Result<Self::Released, Self::Error>;
}

/// Actual production selection controller, called from the extracted
/// `completion::Work::select` callback. Only the value accepted by the final
/// reflection check is released; nothing escapes before it.
pub fn select<W: Work>(work: &mut W) -> Result<W::Released, W::Error> {
    work.current()?;
    let metadata = work.pagination()?;
    let selected = work.project()?;
    let reply = work.assemble(selected, metadata);
    work.check_safe(reply)
}

/// Why the extracted release refused. The native adapter maps these to its
/// public errors (`Denied`, `UpstreamResponse`, `InvalidRequest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    Denied,
    UpstreamResponse,
    InvalidRequest,
}

/// The guest's page argument, already validated as an integer by the policy.
pub enum PageArgument {
    Unused,
    Missing,
    Value(i64),
}

/// Host pagination policy: the row array location and page size.
pub struct Page {
    pub at: Vec<Vec<u8>>,
    pub size: i64,
    pub argument: PageArgument,
}

/// The only native callbacks: the current-control check and error mapping.
pub trait Current {
    type Error;
    fn current(&mut self) -> Result<(), Self::Error>;
    fn refuse(&mut self, denial: Denial) -> Self::Error;
}

/// Number of rows at `at[depth..]` below `value`, following object field
/// names only. A missing field, a non-object step or a non-array target is
/// an upstream response error.
pub fn rows_at(value: &Json, at: &Vec<Vec<u8>>, depth: usize) -> Result<usize, Denial> {
    if depth >= at.len() {
        return match value {
            Json::Array(rows) => Ok(rows.len()),
            _ => Err(Denial::UpstreamResponse),
        };
    }
    match value {
        Json::Object(fields) => {
            let mut i = 0;
            while i < fields.len() {
                if fields[i].0 == at[depth] {
                    return rows_at(&fields[i].1, at, depth + 1);
                }
                i += 1;
            }
            Err(Denial::UpstreamResponse)
        }
        _ => Err(Denial::UpstreamResponse),
    }
}

/// `{"pagination":{"page":p,"per_page":n,"possibly_more":rows==n}}`. The
/// provider document contributes exactly one bit (`possibly_more`) and the
/// refusal when the row array is missing or larger than the page size.
pub fn metadata(document: &Json, page: &Page) -> Result<Json, Denial> {
    let rows = rows_at(document, &page.at, 0)?;
    if rows as i64 > page.size {
        return Err(Denial::UpstreamResponse);
    }
    let mut fields = Vec::new();
    match page.argument {
        PageArgument::Unused => {}
        PageArgument::Missing => return Err(Denial::InvalidRequest),
        PageArgument::Value(value) => fields.push((b"page".to_vec(), Json::Integer(value))),
    }
    fields.push((b"per_page".to_vec(), Json::Integer(page.size)));
    fields.push((b"possibly_more".to_vec(), Json::Boolean(rows as i64 == page.size)));
    Ok(Json::Object(vec![(b"pagination".to_vec(), Json::Object(fields))]))
}

/// `{"meta":..,"ok":true,"result":..,"version":1}` in sorted key order.
pub fn assemble(selected: Json, metadata: Option<Json>) -> Json {
    let mut fields = Vec::new();
    if let Some(metadata) = metadata {
        fields.push((b"meta".to_vec(), metadata));
    }
    fields.push((b"ok".to_vec(), Json::Boolean(true)));
    fields.push((b"result".to_vec(), selected));
    fields.push((b"version".to_vec(), Json::Integer(1)));
    Json::Object(fields)
}

/// Both reflection checks on the complete reply, then the exact wire value:
/// no decoded key or string, and no byte of the encoding, contains the
/// credential.
pub fn checked(reply: Json, secret: &Vec<u8>) -> Result<json_wire::Value, Denial> {
    if !crate::json_reflection::safe(&reply, secret, 65) {
        return Err(Denial::UpstreamResponse);
    }
    let wire = match crate::selected_conversion::render_wire(&reply) {
        Ok(wire) => wire,
        Err(_) => return Err(Denial::UpstreamResponse),
    };
    let bytes = match json_wire::encode(&wire) {
        Ok(bytes) => bytes,
        Err(_) => return Err(Denial::UpstreamResponse),
    };
    if crate::reflection::contains(&bytes, secret) {
        return Err(Denial::UpstreamResponse);
    }
    Ok(wire)
}

/// Production manifest read release over the provider document.
pub struct Manifest<'a, C: Current> {
    pub current: C,
    pub document: &'a Json,
    pub fields: Option<&'a Vec<Field>>,
    pub page: &'a Option<Page>,
    pub secret: &'a Vec<u8>,
}

impl<'a, C: Current> Work for Manifest<'a, C> {
    type Metadata = Json;
    type Selected = Json;
    type Reply = Json;
    type Released = json_wire::Value;
    type Error = C::Error;

    fn current(&mut self) -> Result<(), C::Error> {
        self.current.current()
    }
    fn pagination(&mut self) -> Result<Option<Json>, C::Error> {
        match self.page {
            None => Ok(None),
            Some(page) => match metadata(self.document, page) {
                Ok(meta) => Ok(Some(meta)),
                Err(denial) => Err(self.current.refuse(denial)),
            },
        }
    }
    fn project(&mut self) -> Result<Json, C::Error> {
        let fields = match self.fields {
            Some(fields) => fields,
            None => return Err(self.current.refuse(Denial::Denied)),
        };
        match crate::disclosure::project_fields(self.document, fields, 9, 2 * 1024 * 1024 - 4096) {
            Ok(selected) => Ok(selected.value),
            Err(_) => Err(self.current.refuse(Denial::UpstreamResponse)),
        }
    }
    fn assemble(&mut self, selected: Json, metadata: Option<Json>) -> Json {
        assemble(selected, metadata)
    }
    fn check_safe(&mut self, reply: Json) -> Result<json_wire::Value, C::Error> {
        match checked(reply, self.secret) {
            Ok(wire) => Ok(wire),
            Err(denial) => Err(self.current.refuse(denial)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, PartialEq, Eq)]
    enum Failure { Refused(&'static str) }
    struct Probe {
        calls: Vec<&'static str>,
        fail_at: Option<&'static str>,
        metadata: Option<&'static str>,
    }
    impl Probe {
        fn step(&mut self, step: &'static str) -> Result<(), Failure> {
            self.calls.push(step);
            if self.fail_at == Some(step) { Err(Failure::Refused(step)) } else { Ok(()) }
        }
    }
    impl Work for Probe {
        type Metadata = &'static str;
        type Selected = &'static str;
        type Reply = String;
        type Released = String;
        type Error = Failure;
        fn current(&mut self) -> Result<(), Failure> { self.step("current") }
        fn pagination(&mut self) -> Result<Option<Self::Metadata>, Failure> {
            self.step("pagination")?;
            Ok(self.metadata)
        }
        fn project(&mut self) -> Result<Self::Selected, Failure> {
            self.step("project")?;
            Ok("selected")
        }
        fn assemble(&mut self, selected: Self::Selected, metadata: Option<Self::Metadata>) -> String {
            self.calls.push("assemble");
            format!("{selected}/{}", metadata.unwrap_or("none"))
        }
        fn check_safe(&mut self, reply: String) -> Result<String, Failure> {
            self.step("safe")?;
            Ok(reply)
        }
    }
    #[test]
    fn every_denial_stops_at_its_precise_prefix() {
        let expected = ["current", "pagination", "project", "assemble", "safe"];
        for (i, stage) in expected.iter().enumerate() {
            if *stage == "assemble" { continue; } // Pure assembly cannot fail.
            let mut p = Probe { calls: vec![], fail_at: Some(stage), metadata: Some("page") };
            assert_eq!(select(&mut p), Err(Failure::Refused(stage)));
            assert_eq!(p.calls, expected[..=i]);
        }
        let mut p = Probe { calls: vec![], fail_at: None, metadata: Some("page") };
        assert_eq!(select(&mut p), Ok("selected/page".into()));
        assert_eq!(p.calls, expected);
    }
}

//! Streaming projection of pinned Charon call sites for host-side review.
//! This is a development tool, not an I/O mediation or confidentiality proof.
#![forbid(unsafe_code)]

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, BufReader, Read};

#[derive(Deserialize, Serialize)]
pub struct Projection {
    #[serde(skip_deserializing, default = "schema")]
    pub projection_schema: u32,
    pub charon_version: String,
    pub translated: Translated,
    pub has_errors: bool,
}
#[derive(Deserialize, Serialize)]
pub struct Translated {
    pub crate_name: String,
    pub options: Options,
    pub files: Vec<SourceFile>,
    pub fun_decls: Vec<Option<Function>>,
}
fn schema() -> u32 {
    1
}

#[derive(Deserialize, Serialize)]
pub struct SourceFile {
    pub id: usize,
    pub name: BTreeMap<String, String>,
    pub crate_name: String,
}
#[derive(Deserialize, Serialize)]
pub struct Span {
    #[serde(rename = "Untagged")]
    pub untagged: LocatedSpan,
}
#[derive(Deserialize, Serialize)]
pub struct LocatedSpan {
    pub data: Location,
}
#[derive(Deserialize, Serialize)]
pub struct Location {
    pub file_id: usize,
    pub beg: Position,
    pub end: Position,
}
#[derive(Deserialize, Serialize)]
pub struct Position {
    pub line: usize,
    pub col: usize,
}
#[derive(Deserialize, Serialize)]
pub struct Generics {
    pub types: Count,
}
#[derive(Serialize)]
pub struct Count(pub usize);
impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Elements;
        impl<'de> Visitor<'de> for Elements {
            type Value = Count;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a parameter list")
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Count, S::Error> {
                let mut n = 0;
                while seq.next_element::<IgnoredAny>()?.is_some() {
                    n += 1;
                }
                Ok(Count(n))
            }
        }
        d.deserialize_seq(Elements)
    }
}
#[derive(Deserialize, Serialize)]
pub struct Options {
    pub monomorphize: bool,
    pub ullbc: bool,
}
#[derive(Deserialize, Serialize)]
pub struct Function {
    pub def_id: usize,
    pub item_meta: Meta,
    pub generics: Generics,
    pub body: Body,
}
#[derive(Deserialize, Serialize)]
pub struct Meta {
    pub name: Vec<NamePart>,
    pub has_errors: bool,
    pub span: Span,
}
#[derive(Serialize)]
pub struct NamePart(pub String);
impl<'de> Deserialize<'de> for NamePart {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Part;
        impl<'de> Visitor<'de> for Part {
            type Value = NamePart;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a name element")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("empty name element"))?;
                // Keep marker positions but skip large type arguments. The
                // numeric function ID already names a concrete instantiation.
                let label = if key == "Ident" {
                    let (s, _): (String, IgnoredAny) = map.next_value()?;
                    s
                } else {
                    let _: IgnoredAny = map.next_value()?;
                    format!("<{key}>")
                };
                if map.next_key::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("extra name element"));
                }
                Ok(NamePart(label))
            }
        }
        d.deserialize_map(Part)
    }
}

#[derive(Deserialize)]
struct Unstructured {
    body: Blocks,
}
#[derive(Default, Serialize)]
pub struct Blocks {
    pub count: usize,
    pub calls: usize,
    pub drops: usize,
    pub direct: BTreeSet<usize>,
    pub unresolved: BTreeMap<String, usize>,
    pub sites: Vec<CallSite>,
}
#[derive(Serialize)]
pub struct CallSite {
    pub block: usize,
    pub destination: Option<usize>,
    pub kind: String,
}
impl<'de> Deserialize<'de> for Blocks {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Elements;
        impl<'de> Visitor<'de> for Elements {
            type Value = Blocks;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("basic blocks")
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Blocks, S::Error> {
                // Cleanup IR can contain millions of blocks. Fold it instead
                // of retaining the original block/type trees in memory.
                let mut out = Blocks::default();
                while let Some(block) = seq.next_element::<Block>()? {
                    out.count += 1;
                    match block.terminator.kind {
                        Kind::Drop => out.drops += 1,
                        Kind::Call(Func::Regular(Regular {
                            kind: Target::Fun(fid),
                        })) => {
                            out.calls += 1;
                            out.direct.insert(fid);
                            out.sites.push(CallSite {
                                block: out.count - 1,
                                destination: Some(fid),
                                kind: "Fun".to_owned(),
                            });
                        }
                        Kind::Call(other) => {
                            out.calls += 1;
                            let label = match other {
                                Func::Regular(Regular {
                                    kind: Target::Trait(_),
                                }) => "Trait",
                                Func::Move(_) => "Move",
                                Func::Copy(_) => "Copy",
                                _ => unreachable!(),
                            };
                            *out.unresolved.entry(label.to_owned()).or_default() += 1;
                            out.sites.push(CallSite {
                                block: out.count - 1,
                                destination: None,
                                kind: label.to_owned(),
                            });
                        }
                        Kind::Other => {}
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_seq(Elements)
    }
}
#[derive(Deserialize)]
struct Block {
    terminator: Terminator,
}
#[derive(Deserialize)]
struct Terminator {
    kind: Kind,
}
enum Kind {
    Call(Func),
    Drop,
    Other,
}
#[derive(Deserialize)]
struct CallTerm {
    call: Call,
}
#[derive(Deserialize)]
struct Call {
    func: Func,
}
#[derive(Deserialize)]
enum Func {
    Regular(Regular),
    Move(IgnoredAny),
    Copy(IgnoredAny),
}
#[derive(Deserialize)]
struct Regular {
    kind: Target,
}
#[derive(Deserialize)]
enum Target {
    Fun(usize),
    Trait(IgnoredAny),
}
fn known(tag: &str) -> bool {
    matches!(
        tag,
        "Goto"
            | "Switch"
            | "Return"
            | "UnwindTerminate"
            | "UnwindResume"
            | "UndefinedBehavior"
            | "Assert"
    )
}
impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Term;
        impl<'de> Visitor<'de> for Term {
            type Value = Kind;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a terminator")
            }
            fn visit_str<E: de::Error>(self, tag: &str) -> Result<Kind, E> {
                if known(tag) {
                    Ok(Kind::Other)
                } else {
                    Err(E::custom("unknown unit terminator"))
                }
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Kind, M::Error> {
                let tag: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("empty terminator"))?;
                let out = if tag == "Call" {
                    Kind::Call(map.next_value::<CallTerm>()?.call.func)
                } else if tag == "Drop" {
                    let _: IgnoredAny = map.next_value()?;
                    Kind::Drop
                } else if known(&tag) {
                    let _: IgnoredAny = map.next_value()?;
                    Kind::Other
                } else {
                    return Err(de::Error::custom("unknown terminator"));
                };
                if map.next_key::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("extra terminator"));
                }
                Ok(out)
            }
        }
        d.deserialize_any(Term)
    }
}
#[derive(Serialize)]
pub struct Body {
    pub kind: String,
    pub blocks: Blocks,
}
impl<'de> Deserialize<'de> for Body {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Shape;
        impl<'de> Visitor<'de> for Shape {
            type Value = Body;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a function body")
            }
            fn visit_str<E: de::Error>(self, tag: &str) -> Result<Body, E> {
                if !matches!(tag, "Opaque" | "Intrinsic") {
                    return Err(E::custom("unknown body kind"));
                }
                Ok(Body {
                    kind: tag.to_owned(),
                    blocks: Blocks::default(),
                })
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Body, M::Error> {
                let tag: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("empty body"))?;
                let blocks = match tag.as_str() {
                    "Unstructured" => map.next_value::<Unstructured>()?.body,
                    "Intrinsic" => {
                        let _: IgnoredAny = map.next_value()?;
                        Blocks::default()
                    }
                    _ => return Err(de::Error::custom("unknown body kind")),
                };
                if map.next_key::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("extra body variant"));
                }
                Ok(Body { kind: tag, blocks })
            }
        }
        d.deserialize_any(Shape)
    }
}

/// Count input bytes before allocating projected records. Ignored type metadata
/// is scanned by Serde without constructing the original multi-GB object tree.
struct Bounded<R> {
    inner: R,
    consumed: u64,
    limit: u64,
}
impl<R: Read> Read for Bounded<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.consumed = self.consumed.saturating_add(n as u64);
        if self.consumed > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compiler input exceeds byte limit",
            ));
        }
        Ok(n)
    }
}

pub fn project(
    reader: impl Read,
    max_bytes: u64,
) -> Result<Projection, Box<dyn std::error::Error>> {
    let bounded = Bounded {
        inner: reader,
        consumed: 0,
        limit: max_bytes,
    };
    let source = BufReader::with_capacity(1024 * 1024, bounded);
    let mut decoder = serde_json::Deserializer::from_reader(source);
    let data = Projection::deserialize(&mut decoder)?;
    decoder.end()?;
    if data.charon_version != "0.1.291"
        || data.has_errors
        || data.translated.crate_name != "garrett_bridge"
        || !data.translated.options.monomorphize
        || !data.translated.options.ullbc
    {
        return Err("unreviewed/incomplete compiler artifact".into());
    }
    let mut ids = BTreeSet::new();
    for f in data.translated.fun_decls.iter().flatten() {
        if f.item_meta.has_errors || !ids.insert(f.def_id) {
            return Err("invalid or duplicated compiler function declaration".into());
        }
    }
    if !data.translated.fun_decls.iter().flatten().any(|f| {
        f.item_meta
            .name
            .iter()
            .map(|p| p.0.as_str())
            .eq(["garrett_bridge", "main"])
            && f.body.kind == "Unstructured"
            && f.generics.types.0 == 0
    }) {
        return Err("specialized bridge main body is missing".into());
    }
    let files: BTreeSet<_> = data.translated.files.iter().map(|f| f.id).collect();
    if files.len() != data.translated.files.len() {
        return Err("duplicated source file ID".into());
    }
    for f in data.translated.fun_decls.iter().flatten() {
        if !files.contains(&f.item_meta.span.untagged.data.file_id) {
            return Err("declaration lacks a source file record".into());
        }
        if !f.body.blocks.direct.iter().all(|id| ids.contains(id)) {
            return Err("direct call lacks a compiler function declaration".into());
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn function(id: usize, name: &str, body: Value) -> Value {
        json!({"def_id":id,"generics":{"types":[]},"item_meta":{
            "name":[{"Ident":["garrett_bridge",0]},{"Ident":[name,0]}],
            "has_errors":false,"span":{"Untagged":{"data":{
                "file_id":0,"beg":{"line":1,"col":0},"end":{"line":2,"col":1}
            }}}
        },"body":body})
    }

    fn block(kind: Value) -> Value {
        json!({"terminator":{"kind":kind}})
    }
    fn call(target: Value) -> Value {
        block(json!({"Call":{"call":{"func":{"Regular":{"kind":target}}},
                              "target":1,"on_unwind":2}}))
    }
    fn fixture() -> Value {
        let body = json!({"Unstructured":{"body":[
            call(json!({"Fun":1})), block(json!({"Drop":{"place":{}}})), block(json!("Return"))
        ]}});
        json!({"charon_version":"0.1.291","has_errors":false,"translated":{
            "crate_name":"garrett_bridge","options":{"monomorphize":true,"ullbc":true},
            "files":[{"id":0,"name":{"Local":"src/main.rs"},"crate_name":"garrett_bridge"}],
            "fun_decls":[function(0,"main",body),function(1,"leaf",json!("Opaque"))]
        }})
    }
    fn parse(value: &Value) -> Result<Projection, Box<dyn std::error::Error>> {
        let raw = serde_json::to_vec(value)?;
        project(raw.as_slice(), raw.len() as u64)
    }

    #[test]
    fn projects_calls_and_keeps_opaque_and_drop_obligations() {
        let result = parse(&fixture()).unwrap();
        let main = result.translated.fun_decls[0].as_ref().unwrap();
        assert_eq!(main.body.blocks.direct, BTreeSet::from([1]));
        assert_eq!(main.body.blocks.calls, 1);
        assert_eq!(main.body.blocks.drops, 1);
        assert_eq!(main.body.blocks.count, 3);
        assert_eq!(main.body.blocks.sites[0].block, 0);
        assert_eq!(
            result.translated.fun_decls[1].as_ref().unwrap().body.kind,
            "Opaque"
        );
    }

    #[test]
    fn dynamic_calls_are_retained_as_unresolved() {
        let mut input = fixture();
        input["translated"]["fun_decls"][0]["body"]["Unstructured"]["body"][0] =
            call(json!({"Trait":[{"Deduplicated":3},0]}));
        let result = parse(&input).unwrap();
        let body = &result.translated.fun_decls[0].as_ref().unwrap().body.blocks;
        assert!(body.direct.is_empty());
        assert_eq!(body.unresolved["Trait"], 1);
        assert_eq!(body.sites[0].destination, None);
    }

    #[test]
    fn incomplete_and_wrong_compiler_headers_are_rejected() {
        for (path, bad) in [
            (vec!["charon_version"], json!("future")),
            (vec!["has_errors"], json!(true)),
            (vec!["translated", "crate_name"], json!("another_crate")),
            (vec!["translated", "options", "monomorphize"], json!(false)),
            (vec!["translated", "options", "ullbc"], json!(false)),
        ] {
            let mut input = fixture();
            let mut target = &mut input;
            for key in path {
                target = &mut target[key];
            }
            *target = bad;
            assert!(parse(&input).is_err());
        }
    }

    #[test]
    fn missing_calls_duplicates_and_function_errors_are_rejected() {
        for mutation in ["missing", "duplicate", "error", "file"] {
            let mut input = fixture();
            match mutation {
                "missing" => {
                    input["translated"]["fun_decls"][0]["body"]["Unstructured"]["body"][0] =
                        call(json!({"Fun":99}))
                }
                "duplicate" => input["translated"]["fun_decls"][1]["def_id"] = json!(0),
                "error" => {
                    input["translated"]["fun_decls"][1]["item_meta"]["has_errors"] = json!(true)
                }
                "file" => input["translated"]["files"] = json!([]),
                _ => unreachable!(),
            }
            assert!(parse(&input).is_err());
        }
    }

    #[test]
    fn unknown_executable_forms_are_not_silently_ignored() {
        for kind in [
            json!("FutureTerminator"),
            json!({"FutureTerminator":{}}),
            json!({"Call":{"call":{"func":{"FutureOperand":0}}}}),
        ] {
            let mut input = fixture();
            input["translated"]["fun_decls"][0]["body"]["Unstructured"]["body"][0] = block(kind);
            assert!(parse(&input).is_err());
        }
    }

    #[test]
    fn byte_limit_and_document_end_are_enforced() {
        let raw = serde_json::to_vec(&fixture()).unwrap();
        assert!(project(raw.as_slice(), raw.len() as u64).is_ok());
        assert!(project(raw.as_slice(), (raw.len() - 1) as u64).is_err());
        let mut trailing = raw.clone();
        trailing.extend(b" {}");
        assert!(project(trailing.as_slice(), trailing.len() as u64).is_err());
        assert!(project(&raw[..raw.len() - 1], raw.len() as u64).is_err());
    }

    #[test]
    fn large_ignored_metadata_does_not_change_the_projection() {
        let before = serde_json::to_value(parse(&fixture()).unwrap()).unwrap();
        let mut input = fixture();
        input["translated"]["fun_decls"][0]["body"]["Unstructured"]["locals"] =
            json!({"unused_types": vec![0; 100_000]});
        assert_eq!(
            serde_json::to_value(parse(&input).unwrap()).unwrap(),
            before
        );
    }
}

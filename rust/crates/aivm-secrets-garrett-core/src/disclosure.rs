//! Typed provider-response projection. Only selected leaves and schema-owned
//! output names can enter the result; unknown input fields have no serializer.
#![allow(clippy::ptr_arg)]
use crate::credential_use::UseDenial;

pub enum Json {
    Null,
    Boolean(bool),
    Integer(i64),
    Text(Vec<u8>),
    Array(Vec<Json>),
    Object(Vec<(Vec<u8>, Json)>),
    Opaque,
}
pub struct Field {
    pub name: Vec<u8>,
    pub projection: Projection,
}
pub struct Projection {
    pub at: Vec<Vec<u8>>,
    pub kind: Kind,
}
pub enum Kind {
    Integer,
    Boolean,
    Text,
    Null,
    Object(Vec<Field>),
    Array(Box<Projection>, usize),
}

pub type Members = Vec<(Vec<u8>, Json)>;
pub fn field<'a>(fields: &'a Members, name: &Vec<u8>) -> Result<&'a Json, UseDenial> {
    let mut index = 0;
    while index < fields.len() {
        let entry = &fields[index];
        if entry.0 != *name {
            index += 1;
        } else {
            return Ok(&entry.1);
        }
    }
    Err(UseDenial::Denied)
}
pub fn lookup_from<'a>(
    value: &'a Json,
    at: &Vec<Vec<u8>>,
    index: usize,
) -> Result<&'a Json, UseDenial> {
    if index >= at.len() {
        return Ok(value);
    }
    match value {
        Json::Object(fields) => match field(fields, &at[index]) {
            Ok(child) => lookup_from(child, at, index + 1),
            Err(error) => Err(error),
        },
        _ => Err(UseDenial::Denied),
    }
}
pub fn lookup<'a>(value: &'a Json, at: &Vec<Vec<u8>>) -> Result<&'a Json, UseDenial> {
    if at.len() > 8 {
        return Err(UseDenial::Denied);
    }
    lookup_from(value, at, 0)
}

pub struct Selection {
    pub value: Json,
    pub remaining: usize,
}
pub fn charge(budget: usize, size: usize) -> Result<usize, UseDenial> {
    if size > budget {
        return Err(UseDenial::Denied);
    }
    Ok(budget - size)
}
pub fn text_safe(value: &Vec<u8>) -> bool {
    if value.len() > 16384 {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        if value[index] == 0 {
            return false;
        }
        index += 1;
    }
    true
}

pub fn project(
    value: &Json,
    schema: &Projection,
    fuel: usize,
    budget: usize,
) -> Result<Selection, UseDenial> {
    if fuel == 0 {
        return Err(UseDenial::Denied);
    }
    let selected = lookup(value, &schema.at)?;
    match (&schema.kind, selected) {
        (Kind::Integer, Json::Integer(v)) => Ok(Selection {
            value: Json::Integer(*v),
            remaining: charge(budget, 21)?,
        }),
        (Kind::Boolean, Json::Boolean(v)) => Ok(Selection {
            value: Json::Boolean(*v),
            remaining: charge(budget, 5)?,
        }),
        (Kind::Null, Json::Null) => Ok(Selection {
            value: Json::Null,
            remaining: charge(budget, 4)?,
        }),
        (Kind::Text, Json::Text(v)) => {
            if !text_safe(v) {
                return Err(UseDenial::Denied);
            }
            // UTF-8 source strings need at most six ASCII JSON bytes per
            // source byte, including escapes. No private serialization is used
            // to compute the selected-value construction budget.
            Ok(Selection {
                value: Json::Text(v.clone()),
                remaining: charge(budget, 6 * v.len() + 2)?,
            })
        }
        (Kind::Object(fields), Json::Object(_)) => {
            project_fields(selected, fields, fuel - 1, budget)
        }
        (Kind::Array(item, maximum), Json::Array(values)) => {
            if *maximum < 1 || *maximum > 1000 || values.len() > *maximum {
                return Err(UseDenial::Denied);
            }
            array_from(values, item, fuel - 1, charge(budget, 2)?, 0, Vec::new())
        }
        _ => Err(UseDenial::Denied),
    }
}
pub fn array_step(
    value: &Json,
    schema: &Projection,
    fuel: usize,
    budget: usize,
    mut out: Vec<Json>,
) -> Result<(Vec<Json>, usize), UseDenial> {
    let selected = project(value, schema, fuel, charge(budget, 1)?)?;
    out.push(selected.value);
    Ok((out, selected.remaining))
}
pub fn array_from(
    values: &Vec<Json>,
    schema: &Projection,
    fuel: usize,
    budget: usize,
    mut index: usize,
    out: Vec<Json>,
) -> Result<Selection, UseDenial> {
    let mut state = Ok((out, budget));
    while index < values.len() {
        state = match state {
            Ok((out, remaining)) => array_step(&values[index], schema, fuel, remaining, out),
            Err(error) => Err(error),
        };
        index += 1;
    }
    match state {
        Ok((out, remaining)) => Ok(Selection {
            value: Json::Array(out),
            remaining,
        }),
        Err(error) => Err(error),
    }
}
pub fn field_step(
    value: &Json,
    field: &Field,
    fuel: usize,
    budget: usize,
    mut out: Members,
) -> Result<(Members, usize), UseDenial> {
    if field.name.len() > 64 {
        return Err(UseDenial::Denied);
    }
    let selected = project(
        value,
        &field.projection,
        fuel,
        charge(budget, 6 * field.name.len() + 4)?,
    )?;
    out.push((field.name.clone(), selected.value));
    Ok((out, selected.remaining))
}
pub fn fields_from(
    value: &Json,
    fields: &Vec<Field>,
    fuel: usize,
    budget: usize,
    mut index: usize,
    out: Members,
) -> Result<Selection, UseDenial> {
    let mut state = Ok((out, budget));
    while index < fields.len() {
        state = match state {
            Ok((out, remaining)) => field_step(value, &fields[index], fuel, remaining, out),
            Err(error) => Err(error),
        };
        index += 1;
    }
    match state {
        Ok((out, remaining)) => Ok(Selection {
            value: Json::Object(out),
            remaining,
        }),
        Err(error) => Err(error),
    }
}
// The pinned Aeneas library models len, but not Vec::is_empty.
#[allow(clippy::len_zero)]
pub fn project_fields(
    value: &Json,
    fields: &Vec<Field>,
    fuel: usize,
    budget: usize,
) -> Result<Selection, UseDenial> {
    if fields.len() == 0 || fields.len() > 32 {
        return Err(UseDenial::Denied);
    }
    fields_from(value, fields, fuel, charge(budget, 2)?, 0, Vec::new())
}

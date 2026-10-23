//! Guest-side translation of an HTTP request target into the arguments of
//! a named operation (HP-6, constrained-http over the bridge).
//!
//! Candidate arguments are read off the target against the operation's
//! templates, then accepted only if [`route::fill_target`] (the function
//! the host uses to build the provider target) reproduces the target byte
//! for byte. The matcher's heuristics therefore affect only which requests
//! are translated, never what an accepted translation means.

use crate::route::{fill_target, lookup, Binding, Piece, QueryPiece};

/// The end of the path: the first `?`, or the end of the target.
pub fn path_end(target: &[u8]) -> usize {
    let mut index = 0;
    while index < target.len() {
        if target[index] == b'?' {
            return index;
        }
        index += 1;
    }
    target.len()
}

/// The end of the piece starting at `start`: the next `stop` byte or `end`.
pub fn piece_end(target: &[u8], start: usize, end: usize, stop: u8) -> usize {
    let mut index = start;
    while index < end && index < target.len() {
        if target[index] == stop {
            return index;
        }
        index += 1;
    }
    end
}

/// Bind `name` to `value` unless an earlier binding already names it.
pub fn bind(bindings: &mut Vec<Binding>, name: &[u8], value: &[u8]) {
    match lookup(bindings, name) {
        Some(_) => (),
        None => bindings.push(Binding {
            name: name.to_vec(),
            value: value.to_vec(),
        }),
    }
}

/// Read one path segment per template part (`/part/part...`).
pub fn bind_path(bindings: &mut Vec<Binding>, path: &[Piece], target: &[u8], end: usize) {
    let mut start = 1;
    let mut index = 0;
    while index < path.len() && start <= end {
        let stop = piece_end(target, start, end, b'/');
        match &path[index] {
            Piece::Literal(_) => (),
            Piece::Parameter(name) => bind(bindings, name, &target[start..stop]),
        }
        start = stop + 1;
        index += 1;
    }
}

/// Read `name=value` pairs after the `?` and bind each query parameter the
/// first pair with its name provides.
pub fn bind_query(bindings: &mut Vec<Binding>, query: &[QueryPiece], target: &[u8], end: usize) {
    let mut start = end + 1;
    while start < target.len() {
        let stop = piece_end(target, start, target.len(), b'&');
        let equals = piece_end(target, start, stop, b'=');
        if equals < stop {
            let name = &target[start..equals];
            let mut index = 0;
            while index < query.len() {
                let wanted: &[u8] = &query[index].name;
                if wanted == name {
                    match &query[index].piece {
                        Piece::Literal(_) => (),
                        Piece::Parameter(parameter) => {
                            bind(bindings, parameter, &target[equals + 1..stop])
                        }
                    }
                }
                index += 1;
            }
        }
        start = stop + 1;
    }
}

/// The arguments under which the host's own `fill_target` writes exactly
/// `target`, or `None`.
pub fn translate(path: &[Piece], query: &[QueryPiece], target: &[u8]) -> Option<Vec<Binding>> {
    let end = path_end(target);
    if end == 0 || target[0] != b'/' {
        return None;
    }
    let mut bindings = Vec::new();
    bind_path(&mut bindings, path, target, end);
    bind_query(&mut bindings, query, target, end);
    match fill_target(path, query, &bindings) {
        Ok(filled) => {
            let produced: &[u8] = &filled;
            if produced == target {
                Some(bindings)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(text: &str) -> Piece {
        Piece::Literal(text.as_bytes().to_vec())
    }
    fn param(text: &str) -> Piece {
        Piece::Parameter(text.as_bytes().to_vec())
    }
    fn value(bindings: &[Binding], name: &str) -> Vec<u8> {
        let index = lookup(bindings, name.as_bytes()).expect("bound");
        bindings[index].value.clone()
    }

    #[test]
    fn a_target_translates_only_when_the_host_fill_reproduces_it() {
        let path = [
            lit("repos"),
            param("owner"),
            param("repo"),
            lit("pulls"),
            param("pr"),
        ];
        let query = [QueryPiece {
            name: b"page".to_vec(),
            piece: param("page"),
        }];
        let found = translate(&path, &query, b"/repos/octo/demo/pulls/7?page=2").expect("match");
        assert_eq!(value(&found, "owner"), b"octo");
        assert_eq!(value(&found, "pr"), b"7");
        assert_eq!(value(&found, "page"), b"2");
        for refused in [
            b"/repos/octo/demo/pulls/7".as_slice(), // query missing
            b"/repos/octo/demo/pulls/7?page=2&x=1", // extra pair
            b"/repos/octo/demo/issues/7?page=2",    // literal differs
            b"/repos/octo/demo/pulls/7/x?page=2",   // extra segment
            b"/repos/octo/../pulls/7?page=2",       // dot segment
            b"/repos/oc%74o/demo/pulls/7?page=2",   // escape
            b"repos/octo/demo/pulls/7?page=2",      // no leading slash
            b"/repos/octo/demo/pulls/7?page=2#f",   // fragment
        ] {
            assert!(
                translate(&path, &query, refused).is_none(),
                "{:?}",
                String::from_utf8_lossy(refused)
            );
        }
    }

    #[test]
    fn repeated_parameters_must_agree() {
        let path = [param("x"), param("x")];
        assert!(translate(&path, &[], b"/a/a").is_some());
        assert!(translate(&path, &[], b"/a/b").is_none());
    }
}

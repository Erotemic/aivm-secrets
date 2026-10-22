//! Source-owned native selected-value release pipeline.
//!
//! The concrete `ManifestSelection` implements these five callbacks. This
//! controller calls them in a single fixed order and returns no reply if a
//! current-control check, pagination, projection or reflection check fails.
//! Correctness of the callbacks themselves (notably serde JSON projection,
//! metadata and the concrete reflection predicate) is a separate obligation.

pub trait Work {
    type Metadata;
    type Selected;
    type Reply;
    type Error;

    fn current(&mut self) -> Result<(), Self::Error>;
    fn pagination(&mut self) -> Result<Option<Self::Metadata>, Self::Error>;
    fn project(&mut self) -> Result<Self::Selected, Self::Error>;
    fn assemble(&mut self, selected: Self::Selected, metadata: Option<Self::Metadata>) -> Self::Reply;
    fn check_safe(&mut self, reply: &Self::Reply) -> Result<(), Self::Error>;
}

/// Actual production selection controller, called from the extracted
/// `completion::Work::select` callback. No selected reply escapes before the
/// final reflection predicate accepts the fully assembled public JSON.
pub fn select<W: Work>(work: &mut W) -> Result<W::Reply, W::Error> {
    work.current()?;
    let metadata = work.pagination()?;
    let selected = work.project()?;
    let reply = work.assemble(selected, metadata);
    work.check_safe(&reply)?;
    Ok(reply)
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
        fn check_safe(&mut self, _: &Self::Reply) -> Result<(), Failure> { self.step("safe") }
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

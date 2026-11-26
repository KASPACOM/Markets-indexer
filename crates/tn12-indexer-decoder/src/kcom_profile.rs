//! Pinned campaign artifact families. These select decoding bytes, never campaign terms.
use anyhow::{bail, Result};
use serde_json::{Map, Value};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    Production,
    FastTn10,
    ConfigurableV2,
}

impl Profile {
    pub(crate) const ALL: [Self; 3] = [Self::Production, Self::FastTn10, Self::ConfigurableV2];
    pub(crate) const CONFIGURABLE_NAME: &'static str = "kcom-configurable-v2";
    pub(crate) const FAST_NAME: &'static str = "kcom-fast-tn10-60s-v1";

    pub(crate) fn from_state(state: &Map<String, Value>) -> Result<Self> {
        match state.get("artifactProfile") {
            None => Ok(Self::Production),
            Some(Value::String(name)) if name == Self::FAST_NAME => Ok(Self::FastTn10),
            Some(Value::String(name)) if name == Self::CONFIGURABLE_NAME => Ok(Self::ConfigurableV2),
            Some(_) => bail!("unsupported KCOM artifact profile"),
        }
    }

    pub(crate) fn annotate(self, state: &mut Value) {
        if self == Self::ConfigurableV2 {
            state["artifactProfile"] = Value::String(Self::CONFIGURABLE_NAME.into());
            state["testOnly"] = Value::Bool(true);
        }
        if self == Self::FastTn10 {
            state["artifactProfile"] = Value::String(Self::FAST_NAME.into());
            state["testOnly"] = Value::Bool(true);
        }
    }
}

pub(crate) fn fast_abi(opening: bool) -> &'static Value {
    static OPEN: OnceLock<Value> = OnceLock::new();
    static GRAPH: OnceLock<Value> = OnceLock::new();
    let (cell, source) = if opening {
        (&OPEN, include_str!("../fixtures/kcom-fast-tn10/open.program-abi.json"))
    } else {
        (&GRAPH, include_str!("../fixtures/kcom-fast-tn10/graph.program-abi.json"))
    };
    cell.get_or_init(|| serde_json::from_str(source).expect("pinned TN10 campaign ABI"))
}

pub(crate) fn fast_vesting_abi() -> &'static Value {
    static ABI: OnceLock<Value> = OnceLock::new();
    ABI.get_or_init(|| serde_json::from_str(include_str!(
        "../fixtures/kcom-fast-tn10/vesting.program-abi.json"
    )).expect("pinned TN10 vesting ABI"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn pinned_fast_abi_files_are_unchanged() {
        for (source, expected) in [
            (include_str!("../fixtures/kcom-fast-tn10/open.program-abi.json"), "4900ac23285ed4419eb8d8ef5464b7fd25d214517ae9bb9cad9cc1d725f0fa9c"),
            (include_str!("../fixtures/kcom-fast-tn10/graph.program-abi.json"), "7bb9ee8bba182f648325dcb6eb489e45bccbb80d2196992eb46512ebbc68e810"),
            (include_str!("../fixtures/kcom-fast-tn10/vesting.program-abi.json"), "97f5c645981fae903b63607b1e6f5847ea318032fd906babc2f4de5c5280088d"),
        ] {
            assert_eq!(hex::encode(Sha256::digest(source.as_bytes())), expected);
        }
    }

    #[test]
    fn unknown_profile_fails_closed() {
        for value in [serde_json::json!("unknown"), Value::Null, serde_json::json!(true)] {
            let mut state = Map::new();
            state.insert("artifactProfile".into(), value);
            assert!(Profile::from_state(&state).is_err());
        }
    }
}

pub(crate) fn configurable_abi(opening: bool) -> &'static Value {
    static OPEN: OnceLock<Value> = OnceLock::new();
    static GRAPH: OnceLock<Value> = OnceLock::new();
    let (cell, source) = if opening {
        (&OPEN, include_str!("../../../wallet-lab/vendor/kcom-configurable-v2/initializer/program-abi.json"))
    } else {
        (&GRAPH, include_str!("../../../wallet-lab/vendor/kcom-configurable-v2/graph/program-abi.json"))
    };
    cell.get_or_init(|| serde_json::from_str(source).expect("pinned configurable campaign ABI"))
}
pub(crate) fn configurable_vesting_abi() -> &'static Value {
    static ABI: OnceLock<Value> = OnceLock::new();
    ABI.get_or_init(|| serde_json::from_str(include_str!(
        "../../../wallet-lab/vendor/kcom-configurable-v2/vesting/program-abi.json"
    )).expect("pinned configurable vesting ABI"))
}

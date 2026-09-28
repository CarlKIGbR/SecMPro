// SPDX-License-Identifier: AGPL-3.0-or-later
//! Workspace facts from `cargo metadata` (packages, targets, features, the resolved dependency graph).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;

use crate::util::{Cmd, Error, Result, bail};

/// One build target of a workspace package (lib, bin, test, bench, example, custom-build, ...).
#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub(crate) name: String,
    pub(crate) kinds: Vec<String>,
    pub(crate) src_path: PathBuf,
}

/// One workspace member.
#[derive(Clone, Debug)]
pub(crate) struct Package {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) manifest_path: PathBuf,
    pub(crate) targets: Vec<Target>,
    pub(crate) features: BTreeSet<String>,
}

/// The workspace as seen by Cargo.
#[derive(Clone, Debug)]
pub(crate) struct Workspace {
    pub(crate) root: PathBuf,
    pub(crate) members: Vec<Package>,
    /// Package id → (name, version, is workspace member).
    pub(crate) all: BTreeMap<String, (String, String, bool)>,
    /// Package id → ids of its direct dependencies (all dependency kinds, all targets).
    pub(crate) edges: BTreeMap<String, Vec<String>>,
}

fn s(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error(format!("cargo metadata: missing string field {key:?}")))
}

fn arr<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| Error(format!("cargo metadata: missing array field {key:?}")))
}

impl Workspace {
    /// Run `cargo metadata --locked` (full graph) and parse it.
    pub(crate) fn load() -> Result<Self> {
        let json = Cmd::cargo()
            .args(["metadata", "--format-version", "1", "--locked"])
            .read()?;
        Self::parse(&json)
    }

    pub(crate) fn parse(json: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(json)
            .map_err(|e| Error(format!("cargo metadata: bad JSON: {e}")))?;
        let root = PathBuf::from(s(&v, "workspace_root")?);
        let member_ids: BTreeSet<String> = arr(&v, "workspace_members")?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let mut members = Vec::new();
        let mut all = BTreeMap::new();
        for p in arr(&v, "packages")? {
            let id = s(p, "id")?;
            let name = s(p, "name")?;
            let is_member = member_ids.contains(&id);
            all.insert(id.clone(), (name.clone(), s(p, "version")?, is_member));
            if !is_member {
                continue;
            }
            let mut targets = Vec::new();
            for t in arr(p, "targets")? {
                targets.push(Target {
                    name: s(t, "name")?,
                    kinds: arr(t, "kind")?
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                    src_path: PathBuf::from(s(t, "src_path")?),
                });
            }
            let features = p
                .get("features")
                .and_then(Value::as_object)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            members.push(Package {
                id,
                name,
                manifest_path: PathBuf::from(s(p, "manifest_path")?),
                targets,
                features,
            });
        }
        members.sort_by(|a, b| a.name.cmp(&b.name));
        let mut edges = BTreeMap::new();
        if let Some(nodes) = v
            .get("resolve")
            .and_then(|r| r.get("nodes"))
            .and_then(Value::as_array)
        {
            for n in nodes {
                let id = s(n, "id")?;
                let deps = arr(n, "deps")?
                    .iter()
                    .map(|d| s(d, "pkg"))
                    .collect::<Result<Vec<_>>>()?;
                edges.insert(id, deps);
            }
        } else {
            bail!("cargo metadata: no resolve graph");
        }
        Ok(Self {
            root,
            members,
            all,
            edges,
        })
    }

    pub(crate) fn member(&self, name: &str) -> Option<&Package> {
        self.members.iter().find(|p| p.name == name)
    }

    /// (name, version) of every non-workspace package reachable from `root_name` (all dependency kinds).
    pub(crate) fn external_closure(&self, root_name: &str) -> Result<BTreeSet<(String, String)>> {
        let Some(root) = self.member(root_name) else {
            bail!("no workspace member named {root_name}")
        };
        let mut seen = BTreeSet::new();
        let mut stack = vec![root.id.clone()];
        let mut out = BTreeSet::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some((name, version, is_member)) = self.all.get(&id)
                && !is_member
            {
                out.insert((name.clone(), version.clone()));
            }
            if let Some(deps) = self.edges.get(&id) {
                stack.extend(deps.iter().cloned());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "workspace_root": "/w",
      "workspace_members": ["path+file:///w/a#0.0.0", "path+file:///w/b#0.0.0"],
      "packages": [
        {"id": "path+file:///w/a#0.0.0", "name": "a", "version": "0.0.0", "manifest_path": "/w/a/Cargo.toml",
         "features": {"kat": []},
         "targets": [{"name": "a", "kind": ["lib"], "src_path": "/w/a/src/lib.rs"}]},
        {"id": "path+file:///w/b#0.0.0", "name": "b", "version": "0.0.0", "manifest_path": "/w/b/Cargo.toml",
         "features": {},
         "targets": [{"name": "b", "kind": ["bin"], "src_path": "/w/b/src/main.rs"}]},
        {"id": "registry+x#c@1.0.0", "name": "c", "version": "1.0.0", "manifest_path": "/r/c/Cargo.toml",
         "features": {}, "targets": []},
        {"id": "registry+x#d@2.0.0", "name": "d", "version": "2.0.0", "manifest_path": "/r/d/Cargo.toml",
         "features": {}, "targets": []}
      ],
      "resolve": {"nodes": [
        {"id": "path+file:///w/a#0.0.0", "deps": [{"pkg": "registry+x#c@1.0.0"}]},
        {"id": "path+file:///w/b#0.0.0", "deps": [{"pkg": "path+file:///w/a#0.0.0"}, {"pkg": "registry+x#d@2.0.0"}]},
        {"id": "registry+x#c@1.0.0", "deps": []},
        {"id": "registry+x#d@2.0.0", "deps": [{"pkg": "registry+x#c@1.0.0"}]}
      ]}
    }"#;

    #[test]
    fn parses_members_targets_features() -> Result<()> {
        let w = Workspace::parse(SAMPLE)?;
        assert_eq!(w.members.len(), 2);
        let a = w.member("a").ok_or_else(|| Error("a missing".into()))?;
        assert!(a.features.contains("kat"));
        assert_eq!(
            a.targets.first().map(|t| t.kinds.clone()),
            Some(vec!["lib".to_owned()])
        );
        Ok(())
    }

    #[test]
    fn closure_is_transitive_and_external_only() -> Result<()> {
        let w = Workspace::parse(SAMPLE)?;
        let names =
            |set: BTreeSet<(String, String)>| set.into_iter().map(|(n, _)| n).collect::<Vec<_>>();
        assert_eq!(names(w.external_closure("a")?), vec!["c"]);
        assert_eq!(names(w.external_closure("b")?), vec!["c", "d"]);
        assert!(w.external_closure("zzz").is_err());
        Ok(())
    }

    #[test]
    fn rejects_garbage() {
        assert!(Workspace::parse("{}").is_err());
        assert!(Workspace::parse("not json").is_err());
    }
}

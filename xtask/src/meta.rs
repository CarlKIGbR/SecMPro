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
    /// Package id → (id, is a normal dependency) of its direct dependencies (all dependency kinds; all targets,
    /// or one target with [`Workspace::load_for_platform`]).
    pub(crate) edges: BTreeMap<String, Vec<(String, bool)>>,
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

    /// The resolved graph as compiled for one target triple (`cargo metadata --filter-platform`): edges that
    /// are inactive on that platform (other-OS or `cfg(...)`-gated dependencies) are absent.
    pub(crate) fn load_for_platform(triple: &str) -> Result<Self> {
        let json = Cmd::cargo()
            .args([
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--filter-platform",
                triple,
            ])
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
                    .map(|d| Ok((s(d, "pkg")?, is_normal_edge(d))))
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

    /// (name, version) of every non-workspace package reachable from `root_name`: over every dependency kind
    /// (`normal_only = false`), or only over normal edges (`normal_only = true`) — the shipped closure of
    /// ADR-036, `cargo tree -e normal`, where build- and dev-dependencies are not followed at any depth.
    pub(crate) fn external_closure(
        &self,
        root_name: &str,
        normal_only: bool,
    ) -> Result<BTreeSet<(String, String)>> {
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
                stack.extend(
                    deps.iter()
                        .filter(|(_, normal)| *normal || !normal_only)
                        .map(|(dep, _)| dep.clone()),
                );
            }
        }
        Ok(out)
    }
}

/// Whether a `resolve.nodes[].deps[]` entry is a normal dependency for the resolved platform(s): at least one
/// `dep_kinds` entry has `"kind": null`. Without `dep_kinds` (very old Cargo) the edge counts as normal, which
/// can only make the zero-exemption check stricter.
fn is_normal_edge(dep: &Value) -> bool {
    dep.get("dep_kinds")
        .and_then(Value::as_array)
        .is_none_or(|kinds| {
            kinds
                .iter()
                .any(|k| k.get("kind").is_none_or(Value::is_null))
        })
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
         "features": {}, "targets": []},
        {"id": "registry+x#e@1.0.0", "name": "e", "version": "1.0.0", "manifest_path": "/r/e/Cargo.toml",
         "features": {}, "targets": []},
        {"id": "registry+x#f@1.0.0", "name": "f", "version": "1.0.0", "manifest_path": "/r/f/Cargo.toml",
         "features": {}, "targets": []},
        {"id": "registry+x#g@1.0.0", "name": "g", "version": "1.0.0", "manifest_path": "/r/g/Cargo.toml",
         "features": {}, "targets": []}
      ],
      "resolve": {"nodes": [
        {"id": "path+file:///w/a#0.0.0", "deps": [
          {"pkg": "registry+x#c@1.0.0", "dep_kinds": [{"kind": null, "target": null}]},
          {"pkg": "registry+x#e@1.0.0", "dep_kinds": [{"kind": "dev", "target": null}]}]},
        {"id": "path+file:///w/b#0.0.0", "deps": [{"pkg": "path+file:///w/a#0.0.0"}, {"pkg": "registry+x#d@2.0.0"}]},
        {"id": "registry+x#c@1.0.0", "deps": [
          {"pkg": "registry+x#g@1.0.0", "dep_kinds": [{"kind": "build", "target": null}]}]},
        {"id": "registry+x#d@2.0.0", "deps": [{"pkg": "registry+x#c@1.0.0"}]},
        {"id": "registry+x#e@1.0.0", "deps": [
          {"pkg": "registry+x#f@1.0.0", "dep_kinds": [{"kind": "build", "target": null}, {"kind": null, "target": null}]}]},
        {"id": "registry+x#f@1.0.0", "deps": []},
        {"id": "registry+x#g@1.0.0", "deps": []}
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
        // every dependency kind: the dev-dependency e, its dependency f and c's build-dependency g count
        assert_eq!(
            names(w.external_closure("a", false)?),
            vec!["c", "e", "f", "g"]
        );
        assert_eq!(
            names(w.external_closure("b", false)?),
            vec!["c", "d", "e", "f", "g"]
        );
        // normal edges only (ADR-036): neither dev- nor build-dependencies are followed, at any depth; an edge
        // without `dep_kinds` counts as normal
        assert_eq!(names(w.external_closure("a", true)?), vec!["c"]);
        assert_eq!(names(w.external_closure("b", true)?), vec!["c", "d"]);
        assert!(w.external_closure("zzz", true).is_err());
        Ok(())
    }

    #[test]
    fn rejects_garbage() {
        assert!(Workspace::parse("{}").is_err());
        assert!(Workspace::parse("not json").is_err());
    }
}

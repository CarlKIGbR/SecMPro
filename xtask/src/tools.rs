// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pinned versions of every external tool a gate uses, checked before the gate runs (a gate never silently
//! runs with a missing or different tool). Versions were checked live on 2026-09-28 and are at least 7 days
//! old (docs/06 §3 cooldown applied to tools as well). Changing a pin is a reviewed change of this file.

use crate::util::{Cmd, Result, bail, say};

/// A cargo subcommand installed with `cargo install --locked --version <version> <krate>`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CargoTool {
    pub(crate) krate: &'static str,
    pub(crate) version: &'static str,
    /// The `cargo <sub>` name.
    pub(crate) sub: &'static str,
}

pub(crate) const NEXTEST: CargoTool = CargoTool {
    krate: "cargo-nextest",
    version: "0.9.145",
    sub: "nextest",
};
pub(crate) const DENY: CargoTool = CargoTool {
    krate: "cargo-deny",
    version: "0.20.2",
    sub: "deny",
};
pub(crate) const VET: CargoTool = CargoTool {
    krate: "cargo-vet",
    version: "0.10.2",
    sub: "vet",
};
pub(crate) const AUDIT: CargoTool = CargoTool {
    krate: "cargo-audit",
    version: "0.22.2",
    sub: "audit",
};
pub(crate) const AUDITABLE: CargoTool = CargoTool {
    krate: "cargo-auditable",
    version: "0.7.6",
    sub: "auditable",
};
pub(crate) const CYCLONEDX: CargoTool = CargoTool {
    krate: "cargo-cyclonedx",
    version: "0.5.9",
    sub: "cyclonedx",
};
pub(crate) const FUZZ: CargoTool = CargoTool {
    krate: "cargo-fuzz",
    version: "0.13.2",
    sub: "fuzz",
};
pub(crate) const MUTANTS: CargoTool = CargoTool {
    krate: "cargo-mutants",
    version: "27.1.0",
    sub: "mutants",
};
pub(crate) const LLVM_COV: CargoTool = CargoTool {
    krate: "cargo-llvm-cov",
    version: "0.9.1",
    sub: "llvm-cov",
};
pub(crate) const XWIN: CargoTool = CargoTool {
    krate: "cargo-xwin",
    version: "0.23.1",
    sub: "xwin",
};
pub(crate) const ZIGBUILD: CargoTool = CargoTool {
    krate: "cargo-zigbuild",
    version: "0.23.4",
    sub: "zigbuild",
};
pub(crate) const KANI: CargoTool = CargoTool {
    krate: "kani-verifier",
    version: "0.68.0",
    sub: "kani",
};

/// Pinned nightly for Miri and cargo-fuzz (rustc 1.100.0-nightly bba531001 2026-09-20; Miri available on all
/// three targets).
pub(crate) const NIGHTLY: &str = "nightly-2026-09-21";
/// ProVerif, built from `https://proverif.inria.fr/proverif2.05.tar.gz` (SHA-256
/// `4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4`, as recorded by opam; see README.md and
/// `.github/workflows/ci.yml`).
pub(crate) const PROVERIF_VERSION: &str = "2.05";
/// zig, required by cargo-zigbuild for Linux-target builds from macOS (Amendment A1 §3).
pub(crate) const ZIG_VERSION: &str = "0.16.0";

/// Tool sets installed by `cargo xtask install-tools --set <name>`.
pub(crate) fn set(name: &str) -> Result<Vec<CargoTool>> {
    Ok(match name {
        "fast" => vec![NEXTEST, DENY, VET, AUDIT, AUDITABLE, CYCLONEDX],
        "windows" => vec![NEXTEST],
        "xwin" => vec![XWIN],
        "full" => vec![
            NEXTEST, DENY, VET, AUDIT, AUDITABLE, CYCLONEDX, FUZZ, MUTANTS, LLVM_COV, XWIN, KANI,
        ],
        "all" => vec![
            NEXTEST, DENY, VET, AUDIT, AUDITABLE, CYCLONEDX, FUZZ, MUTANTS, LLVM_COV, XWIN,
            ZIGBUILD, KANI,
        ],
        other => bail!("unknown tool set {other:?} (fast | windows | xwin | full | all)"),
    })
}

/// Optional install root for the pinned tools (CI caches it); `cargo install --root` when set.
pub(crate) fn tools_root() -> Option<String> {
    std::env::var("SECMP_TOOLS_ROOT")
        .ok()
        .filter(|r| !r.is_empty())
}

/// Parse `cargo install --list` into (crate, version) pairs.
pub(crate) fn parse_install_list(list: &str) -> Vec<(String, String)> {
    list.lines()
        .filter(|l| !l.starts_with(char::is_whitespace))
        .filter_map(|l| {
            let (name, rest) = l.split_once(' ')?;
            let version = rest.trim().strip_prefix('v')?.strip_suffix(':')?;
            Some((name.to_owned(), version.to_owned()))
        })
        .collect()
}

/// Fail unless `tool` is installed at exactly the pinned version (per `cargo install --list`, because the
/// tools do not report their versions consistently) and `cargo <sub>` can be started.
pub(crate) fn require(tool: CargoTool) -> Result<()> {
    let mut list = Cmd::cargo().args(["install", "--list"]);
    if let Some(root) = tools_root() {
        list = list.args(["--root", &root]);
    }
    let installed = parse_install_list(&list.read()?);
    match installed.iter().find(|(n, _)| n == tool.krate) {
        Some((_, v)) if v == tool.version => {}
        Some((_, v)) => bail!(
            "{} {v} is installed, pinned {} (run `cargo xtask install-tools`)",
            tool.krate,
            tool.version
        ),
        None => bail!(
            "{} is not installed (run `cargo xtask install-tools`; pinned {})",
            tool.krate,
            tool.version
        ),
    }
    if !Cmd::cargo().args([tool.sub, "--help"]).exists() {
        bail!("`cargo {}` cannot be started", tool.sub);
    }
    Ok(())
}

/// Fail unless the pinned nightly exists with the given components.
pub(crate) fn require_nightly(components: &[&str]) -> Result<()> {
    let installed = Cmd::new("rustup")
        .args(["component", "list", "--installed", "--toolchain", NIGHTLY])
        .capture()?;
    if !installed.success {
        bail!("toolchain {NIGHTLY} is not installed (run `cargo xtask install-tools --nightly`)");
    }
    for c in components {
        if !installed
            .stdout
            .lines()
            .any(|l| l.starts_with(&format!("{c}-")) || l.trim() == *c)
        {
            bail!(
                "toolchain {NIGHTLY} lacks component {c} (run `cargo xtask install-tools --nightly`)"
            );
        }
    }
    Ok(())
}

/// `cargo xtask install-tools [--set NAME] [--nightly]`.
pub(crate) fn install(args: &[String]) -> Result<()> {
    let mut set_name = "all".to_owned();
    let mut nightly = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--set" => match it.next() {
                Some(v) => v.clone_into(&mut set_name),
                None => bail!("--set needs a value"),
            },
            "--nightly" => nightly = true,
            other => bail!("unknown argument {other:?}"),
        }
    }
    for tool in set(&set_name)? {
        if require(tool).is_ok() {
            say(&format!(
                "{} {} already installed",
                tool.krate, tool.version
            ));
            continue;
        }
        let mut install =
            Cmd::cargo().args(["install", "--locked", "--version", tool.version, tool.krate]);
        if let Some(root) = tools_root() {
            install = install.args(["--root", &root]);
        }
        install.run()?;
        if tool.krate == KANI.krate {
            Cmd::cargo().args(["kani", "setup"]).run()?;
        }
        require(tool)?;
    }
    if nightly {
        Cmd::new("rustup")
            .args([
                "toolchain",
                "install",
                NIGHTLY,
                "--profile",
                "minimal",
                "--component",
                "miri,rust-src,llvm-tools",
            ])
            .run()?;
        require_nightly(&["miri", "rust-src"])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_list_parsing() {
        let list =
            "cargo-deny v0.20.2:\n    cargo-deny\ncargo-nextest v0.9.145:\n    cargo-nextest\n";
        assert_eq!(
            parse_install_list(list),
            vec![
                ("cargo-deny".to_owned(), "0.20.2".to_owned()),
                ("cargo-nextest".to_owned(), "0.9.145".to_owned())
            ]
        );
        assert!(parse_install_list("garbage\n").is_empty());
    }

    #[test]
    fn unknown_set_is_rejected() {
        assert!(set("nope").is_err());
        assert!(set("fast").is_ok());
    }
}

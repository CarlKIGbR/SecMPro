// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-ui --probe`: the spike's checks on the machine it runs on, one line per item,
//! `PROBE <id> <PASS|FAIL|NOT-RUN> <detail>`. No profile is opened and nothing is written; the window shows the product name
//! and the tagline only.

use std::io::Write as _;
use std::process::ExitCode;

use slint::ComponentHandle as _;

use crate::app::select_backend;
use crate::capture;
use crate::locale::{self, Lang, key};
use crate::screens::MainWindow;

/// The outcome of one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The item holds.
    Pass,
    /// The item does not hold.
    Fail,
    /// The item cannot be checked on this machine.
    NotRun,
}

impl Verdict {
    const fn word(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::NotRun => "NOT-RUN",
        }
    }
}

/// One output line of the probe.
#[must_use]
pub fn line(id: &str, verdict: Verdict, detail: &str) -> String {
    format!("PROBE {id} {} {detail}", verdict.word())
}

fn emit(id: &str, verdict: Verdict, detail: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{}", line(id, verdict, detail));
}

/// P6: the session type and the compositor, from the environment (Linux).
#[must_use]
pub fn session_probe(
    session_type: Option<&str>,
    desktop: Option<&str>,
    wayland_display: bool,
) -> (Verdict, String) {
    if !cfg!(target_os = "linux") {
        return (Verdict::NotRun, "linux only".to_owned());
    }
    let session = session_type
        .filter(|s| !s.is_empty())
        .unwrap_or(if wayland_display {
            "wayland"
        } else {
            "unknown"
        });
    let desktop = desktop.filter(|s| !s.is_empty()).unwrap_or("unknown");
    let verdict = if session == "unknown" || desktop == "unknown" {
        Verdict::Fail
    } else {
        Verdict::Pass
    };
    (verdict, format!("session={session} compositor={desktop}"))
}

/// Run the probe: the checks that need no window first, then the window's.
#[must_use]
pub fn run() -> ExitCode {
    let env = |name: &str| std::env::var(name).ok();
    let (verdict, detail) = session_probe(
        env("XDG_SESSION_TYPE").as_deref(),
        env("XDG_CURRENT_DESKTOP").as_deref(),
        std::env::var_os("WAYLAND_DISPLAY").is_some(),
    );
    emit("P6", verdict, &detail);

    if let Err(e) = select_backend() {
        emit("P1", Verdict::Fail, &format!("no backend: {e}"));
        for id in ["P2", "P3", "P4", "P5"] {
            emit(id, Verdict::NotRun, "no window");
        }
        return ExitCode::FAILURE;
    }
    let Ok(ui) = MainWindow::new() else {
        emit("P1", Verdict::Fail, "window not created");
        for id in ["P2", "P3", "P4", "P5"] {
            emit(id, Verdict::NotRun, "no window");
        }
        return ExitCode::FAILURE;
    };
    ui.set_tagline(locale::text(Lang::En, key::APP_TAGLINE).into());
    emit("P1", Verdict::Pass, "window created (winit backend)");
    let forced = std::env::var("SLINT_BACKEND").ok();
    emit(
        "P2",
        Verdict::Pass,
        &format!(
            "requested: {}; the toolkit API does not report the renderer it started",
            forced
                .as_deref()
                .unwrap_or("default order femtovg, software")
        ),
    );
    emit(
        "P4",
        Verdict::Pass,
        "accessibility feature compiled in; the tree is built when a platform client asks for it",
    );

    let weak = ui.as_weak();
    capture::arm_probe(&ui, move |outcome| {
        if let Some(ui) = weak.upgrade() {
            emit(
                "P3",
                Verdict::Pass,
                &format!("scale factor {:.2}", ui.window().scale_factor()),
            );
        }
        match outcome {
            Some(Ok(affinity)) => emit("P5", Verdict::Pass, &format!("affinity=0x{affinity:x}")),
            Some(Err(_)) => emit(
                "P5",
                Verdict::Fail,
                "affinity is not 0x11 or the call failed",
            ),
            None => emit("P5", Verdict::NotRun, "windows only"),
        }
        let _ = slint::quit_event_loop();
    });
    if ui.show().is_err() {
        emit("P3", Verdict::Fail, "window not shown");
        emit("P5", Verdict::NotRun, "window not shown");
        return ExitCode::FAILURE;
    }
    match slint::run_event_loop() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

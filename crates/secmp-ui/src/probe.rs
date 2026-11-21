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
    /// A value that is reported, not checked against anything.
    Info,
}

impl Verdict {
    const fn word(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::NotRun => "NOT-RUN",
            Self::Info => "INFO",
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
        Verdict::Info
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
        for id in ["P2", "P3", "P4", "P5a", "P5b"] {
            emit(id, Verdict::NotRun, "no window");
        }
        return ExitCode::FAILURE;
    }
    let Ok(ui) = MainWindow::new() else {
        emit("P1", Verdict::Fail, "window not created");
        for id in ["P2", "P3", "P4", "P5a", "P5b"] {
            emit(id, Verdict::NotRun, "no window");
        }
        return ExitCode::FAILURE;
    };
    ui.set_tagline(locale::text(Lang::En, key::APP_TAGLINE).into());
    emit("P1", Verdict::Pass, "window created (winit backend)");
    let forced = std::env::var("SLINT_BACKEND").ok();
    emit(
        "P2",
        Verdict::Info,
        &format!(
            "requested: {}; the toolkit API does not report the renderer it started",
            forced
                .as_deref()
                .unwrap_or("default order femtovg, software")
        ),
    );
    emit(
        "P4",
        Verdict::Info,
        "accessibility feature compiled in; the tree is built when a platform client asks for it",
    );

    let weak = ui.as_weak();
    let armed = capture::arm_probe(&ui, move |outcome| {
        if let Some(ui) = weak.upgrade() {
            emit(
                "P3",
                Verdict::Info,
                &format!("scale factor {:.2}", ui.window().scale_factor()),
            );
        }
        match outcome {
            Some(Ok(report)) => {
                // P5a: the affinity before anything of ours set it: 0x11 only if the window attribute acted at creation
                match report.pre {
                    Ok(pre) if pre == capture::EXCLUDED => {
                        emit("P5a", Verdict::Pass, &format!("pre=0x{pre:x}"));
                    }
                    Ok(pre) => emit("P5a", Verdict::Fail, &format!("pre=0x{pre:x}")),
                    Err(_) => emit("P5a", Verdict::Fail, "pre: the read failed"),
                }
                // P5b: after the call
                match (report.set, report.post) {
                    (Ok(()), Ok(post)) if post == capture::EXCLUDED => {
                        emit("P5b", Verdict::Pass, &format!("post=0x{post:x}"));
                    }
                    (set, Ok(post)) => emit(
                        "P5b",
                        Verdict::Fail,
                        &format!("post=0x{post:x} set_ok={}", set.is_ok()),
                    ),
                    (_, Err(_)) => emit("P5b", Verdict::Fail, "post: the read failed"),
                }
            }
            Some(Err(_)) => {
                emit("P5a", Verdict::Fail, "no native window or handle");
                emit("P5b", Verdict::Fail, "no native window or handle");
            }
            None => {
                emit("P5a", Verdict::NotRun, "windows only");
                emit("P5b", Verdict::NotRun, "windows only");
            }
        }
        if slint::quit_event_loop().is_err() {
            emit("P1", Verdict::Fail, "event loop could not be stopped");
        }
    });
    if armed.is_err() {
        emit("P3", Verdict::Fail, "the check could not be started");
        return ExitCode::FAILURE;
    }
    if ui.show().is_err() {
        emit("P3", Verdict::Fail, "window not shown");
        emit("P5a", Verdict::NotRun, "window not shown");
        emit("P5b", Verdict::NotRun, "window not shown");
        return ExitCode::FAILURE;
    }
    match slint::run_event_loop() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

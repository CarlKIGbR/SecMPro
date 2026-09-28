// SPDX-License-Identifier: AGPL-3.0-or-later
//! M0 spike (c): a Slint window (winit backend) opens and closes. Prints `SPIKE-C OK` on success.
// M0 finding: `#![forbid(unsafe_code)]` makes the `slint!` expansion fail with E0453 (it contains
// `#[allow(unsafe_code)]`), see docs/reviews/M0-spikes.md. `deny` (the workspace level) compiles.
#![deny(unsafe_code)]

use std::error::Error;
use std::time::Duration;

slint::slint! {
    export component Hello inherits Window {
        title: "SecMPro M0 spike";
        width: 360px;
        height: 120px;
        Text { text: "SecMPro — Slint hello-world (M0 spike)"; }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let ui = Hello::new()?;
    let weak = ui.as_weak();
    slint::Timer::single_shot(Duration::from_secs(2), move || {
        if let Some(ui) = weak.upgrade() {
            let w = ui.window();
            println!("window visible after 2 s: {} (size {:?}, scale {})", w.is_visible(), w.size(), w.scale_factor());
            let _ = ui.hide();
        }
        let _ = slint::quit_event_loop();
    });
    ui.show()?;
    slint::run_event_loop()?;
    println!("SPIKE-C OK ({} {})", std::env::consts::OS, std::env::consts::ARCH);
    Ok(())
}

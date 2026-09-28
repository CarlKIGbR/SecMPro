# deploy/ — relay deployment

systemd unit (`secmp-relay.service`, docs/05 §4), torrc, nftables, sysctl/journald/sshd configuration, the
installer for Debian 13 / Ubuntu 26.04, `check-hardening.sh` and the operator runbook — all M10 deliverables.

CI step 14 (`cargo xtask step systemd`) runs `systemd-analyze security --offline=true` on every unit listed in
`xtask/src/expect.rs` (`SYSTEMD_UNITS`) and fails above an exposure level of 2.0. A deliberately unhardened
fixture (`xtask/fixtures/systemd/weak.service`) must be rejected on every run, proving the gate is not a no-op.

Status: empty in M0.

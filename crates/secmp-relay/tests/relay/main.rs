// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay tests (TEST-SPEC-M5 (a) V-06…V-16, V-20, V-22; (b4) Q-*; (b5) RL-*; F-11; (d) P-06…P-11).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod d2;
mod fixture;
mod generator;
mod props;
mod q_auth;
mod q_linkdata;
mod q_queue;
mod q_send_fetch;
mod q_seq;
mod q_shape;
mod rl_conn;
mod rl_process;
mod rl_store;
mod rl_util;
mod vectors;

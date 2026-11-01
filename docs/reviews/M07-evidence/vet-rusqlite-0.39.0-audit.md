# cargo-vet source audit: rusqlite 0.39.0 (criteria: safe-to-deploy)

- Audited: 2026-10-29, by the reviewer's verifier (read-only source review, no cargo run)
- Crate: `rusqlite 0.39.0`. `.crate` sha256 `a0d2b0146dd9661bf67bb107c0bb2a55064d556eeb3fc314151b957f313bcd4e` matches the SecMPro Cargo.lock entry. `.cargo_vcs_info.json` gives git `2a1790a69107cd03dae85d501dcbdb11c5b32ef3`. This sha was not compared against upstream.
- Source tree: `/home/claude/m07/vet/rusqlite/rusqlite-0.39.0/`
- **Verdict: safe-to-deploy, YES WITH NOTES.** I found no soundness issue or UB risk in the compiled code under normal use. The crate has no network access, no process spawning, no file access outside the SQLite C API, and no build-time code. The notes below concern secret hygiene: key material ends up in plain heap copies and can appear in error and Debug strings. SecMPro has to mitigate these in its own code.

## 1. Effective feature set (Cargo feature unification)

| Source | Declaration | rusqlite features contributed |
|---|---|---|
| SecMPro `Cargo.toml:72` | `rusqlite = "=0.39.0", default-features = false, features = ["bundled-sqlcipher-vendored-openssl"]` | `bundled-sqlcipher-vendored-openssl` → `bundled-sqlcipher` → `bundled` → `modern_sqlite` |
| `tor-dirmgr 0.46.0` Cargo.toml (crate downloaded to `/home/claude/m07/vet/tor-dirmgr/`, sha256 `805da4e9…a463e` = Cargo.lock) | `[dependencies.rusqlite] version=">=0.36.0, <0.40.0", features=["time"]`, with default features **left on** | `default` = `cache` (→ `hashlink`), `time` |
| `arti-client 0.46.0` (SecMPro `Cargo.toml:64` enables `static-sqlite`; crate sha256 `aafcbc50…3097` = Cargo.lock) | `static-sqlite = ["tor-dirmgr/static"]`, and `tor-dirmgr/static = ["rusqlite/bundled"]` | `bundled` (already present) |

**Union:** `default, cache, time, bundled, bundled-sqlcipher, bundled-sqlcipher-vendored-openssl, modern_sqlite` (libsqlite3-sys side: `bundled-sqlcipher-vendored-openssl`, `bundled_bindings`).
The lock file agrees: rusqlite's dependency list there is bitflags, fallible-iterator, fallible-streaming-iterator, hashlink, libsqlite3-sys, smallvec, time, plus sqlite-wasm-rs, which is target-gated to wasm32-unknown-unknown and not built on native. The only crates in the lock that depend on rusqlite are `secmp-store` and `tor-dirmgr`.

**Not compiled:** `sqlcipher` (the rusqlite-level feature is off; rusqlite has no sqlcipher-specific Rust code), `functions`, `hooks`, `preupdate_hook`, `session`, `vtab`, `blob`, `backup`, `collation`, `column_decltype`, `column_metadata`, `load_extension`, `loadable_extension`, `unlock_notify`, `trace`, `limits`, `serialize`, `extra_check`, `pointer`, `i128_blob`, `chrono`, `jiff`, `serde_json`, `url`, `uuid`, `fallible_uint`, `rusqlite-macros`.
Because `load_extension` is off, rusqlite exposes no dlopen path (`load_extension*` and `LoadExtensionGuard` are absent). `auto_extension` **is** compiled, since it is gated on `not(loadable_extension)`.

## 2. Modules read in full (production code; `#[cfg(test)]` parts skimmed for unsafe and feature use only)

| Module | Lines (total / production) | Compiled `unsafe` sites | Classification |
|---|---|---|---|
| lib.rs | 2330 / 1289 | 10 | 2× `unsafe impl` Send for Connection and Send+Sync for InterruptHandle (counted as 3 impls, see total); 3 `pub unsafe fn` (handle/from_handle/from_handle_owned, documented); 1 `unsafe fn` errmsg_to_string (CStr from SQLite ptr); 3 blocks: FFI `db_filename`, `sqlite3_db_name` plus CStr, `sqlite3_interrupt` under mutex |
| inner_connection.rs | 446 / 446 | 22 | 1 `unsafe impl Send`; 3 unsafe fns (`new`, `get_autocommit`, `db_filename`); 18 FFI blocks (open_v2/close/prepare_v3/changes64/next_stmt/mutex_alloc probe …). unlock_notify and load_extension variants not compiled |
| raw_statement.rs | 282 / 282 | 19 | 4 unsafe fns (`new`, `ptr`, `expanded_sql`, `stmt_status`); 15 FFI blocks, 3 of them build `CStr::from_ptr` on SQLite-owned NUL-terminated strings (column_name, bind_parameter_name, sql) |
| statement.rs | 1396 / 899 | 15 | 8 bind FFI calls (null/int64/double/text64/blob64/zeroblob(0)); 2 `slice::from_raw_parts` on column_text/column_blob; 3 column FFI; `into_raw` (cache), `ptr` |
| error.rs | 514 / 514 | 5 | unsafe fns: error_from_handle, error_msg, decode_result_raw, error_with_offset (modern), to_sqlite_error (raw `*err_msg` write) |
| auto_extension.rs | 62 / 62 | 4 | 2 unsafe fns (register/init, documented); 2 FFI blocks |
| busy.rs | 138 / 80 | 3 | `extern "C"` callback with `mem::transmute(*mut c_void → fn(i32)->bool)` (pointer came from a `fn`, sound) wrapped in `catch_unwind`; 2 FFI |
| cache.rs | 351 / 176 | 2 | `unsafe impl Send for StatementCache`; `into_raw` on CachedStatement drop |
| column.rs | 576 / 395 | 4 | `sqlite3_table_column_metadata` ×2, CStr ×2 |
| config.rs | 169 / 135 | 2 | variadic `sqlite3_db_config(int, int*)`, correctly typed |
| bind.rs | 71 / 51 | 1 | `sqlite3_bind_parameter_index` |
| version.rs | 27 / 27 | 2 | libversion FFI and CStr |
| util/small_cstr.rs | 159 / 116 | 2 | `from_utf8_unchecked` (constructor only takes `&str`), `CStr::from_bytes_with_nul_unchecked` (NUL appended and internal NULs rejected in `new`) |
| util/sqlite_string.rs | 230 / 166 | 5 | sqlite3_malloc64 + copy_nonoverlapping + NUL write, sqlite3_free in Drop, CStr |
| util/mod.rs, util/param_cache.rs | 55, 63 / 55, 29 | 0 | (`free_boxed_value` is not compiled) |
| params.rs, pragma.rs, transaction.rs, row.rs | 453, 426, 826, 680 | 0 | (`Row::get_pointer` is not compiled) |
| types/mod.rs, from_sql.rs, to_sql.rs, value.rs, value_ref.rs, time.rs | 457, 507, 601, 171, 350, 429 | 0 | (the to_sql pointer feature and `ValueRef::from_value` are not compiled) |

**Total: 96 compiled unsafe sites.** Breakdown: 5 Send/Sync impls (Connection, InnerConnection, StatementCache: Send; InterruptHandle: Send+Sync), 1 transmute, about 17 raw-pointer or slice/CStr constructions, and the rest direct FFI calls.
Modules not compiled under the union and so not reviewed: functions, hooks/*, vtab/*, blob/*, backup, collation, session, trace, limits, serialize, unlock_notify, load_extension_guard, context, types/{chrono,jiff,serde_json,url}.

## 3. Soundness review (specific checks requested)

- **Send/Sync.** `Connection: Send`, and it is `!Sync` automatically because it holds a `RefCell<InnerConnection>`. `Statement<'conn>` holds `&Connection`, so it is `!Send`. Connections open with `SQLITE_OPEN_NOMUTEX` (multi-thread mode), and `ensure_safe_sqlite_threading_mode` (inner_connection.rs:420-446) refuses SQLite builds that are single-threaded or were configured that way at runtime. `InterruptHandle: Send+Sync` is sound: the pointer sits in `Arc<Mutex<_>>`, `close()` takes the same mutex and nulls it before returning (inner_connection.rs:147-165), and `sqlite3_interrupt` is documented as thread-safe. **OK.**
- **Drop order, Statement before Connection.** Every Statement, CachedStatement, Rows and Row borrows `&Connection`, so the borrow checker forces them to drop first. `Connection::drop` flushes the statement cache (lib.rs:357-363) before the `InnerConnection` field drops and calls `sqlite3_close`. If a statement was `mem::forget`-ed, `sqlite3_close` (not `close_v2`) returns SQLITE_BUSY and the handle leaks; that is not a use-after-free. **OK.**
- **Bind lifetimes.** Every non-empty text and blob is bound with `SQLITE_TRANSIENT`, so SQLite copies it (lib.rs:313-328, statement.rs:644-668). `SQLITE_STATIC` is used only for the static `""` literal, and empty blobs go through `bind_zeroblob(0)`. No dangling binds. **OK.**
- **CStr from buffers.** Every `CStr::from_ptr` is applied to a string SQLite returned, and those are NUL-terminated. SQL is passed to `sqlite3_prepare_v3` with an explicit byte length (`c_int::try_from(len)`, which fails as SQLITE_TOOBIG), so the input SQL is never treated as a C string. **OK.**
- **`prepare_v3` tail handling.** The tail offset is computed by pointer difference and clamped to `0 < n < len` (inner_connection.rs:260-269). `execute_batch` and `Batch` advance correctly and stop on a NULL statement (empty input or comment-only). `prepare_with_flags` rejects multi-statement input with `MultipleStatement`. **OK.**
- **Column reads.** `value_ref` (statement.rs:795-849) switches on `sqlite3_column_type`, calls `column_text`/`column_blob` before `column_bytes` as the SQLite docs require, and never converts to UTF-16, so returned pointers are not invalidated. `ValueRef<'_>` is tied to a `&Row` borrow, and the next `step` needs `&mut Rows`. Indices are bounds-checked in `RowIndex::idx`. **OK.**
- **`unlock_notify`.** Not compiled.
- **Error-code mapping.** `decode_result` maps every non-OK code to `Err`, keeping extended codes via `ffi::Error::new`. `step` maps ROW/DONE and passes everything else (BUSY, IOERR_*, CORRUPT, NOTADB…) through as an error. `execute_with_bound_parameters` reports the step error, or the reset error after DONE. `Rows::advance` returns the error and resets the statement. SQLITE_BUSY and SQLITE_IOERR are **not** swallowed on any statement path. The one exception is under N-3.
- **RefCell re-entrancy.** With hooks/functions/trace off, the only callback is the busy handler. It is a plain `fn(i32)` with no Connection access, so a `borrow_mut` can never be taken twice and nothing panics on that path.
- **Panics across FFI.** The busy handler uses `catch_unwind`. `init_auto_extension` uses `catch_unwind` around the user closure. Neither path is used by SecMPro or Arti.

## 4. Environment access and build-time code

- No `build.rs`: Cargo.toml has `build = false` and none exists. No proc-macro dependency is compiled (`rusqlite-macros` is optional and off).
- The production modules contain no `std::net`, `std::process`, `std::fs` or `std::env` (grep). `std::fs::File` appears only in a `#[cfg(test)]` test, lib.rs:1439.
- Files are reached only through `sqlite3_open_v2(path, flags, vfs)`. Note that `SQLITE_OPEN_URI` is in the default flags (lib.rs:1241-1251), so the path string is parsed as a URI (`file:…?mode=…&vfs=…`). SecMPro must not build that path from untrusted input.
- Default `sqlite3_busy_timeout(db, 5000)` is set at open (inner_connection.rs:118).
- Out of scope: `libsqlite3-sys 0.37.0`. It has a build.rs, compiles bundled SQLCipher C, and builds vendored OpenSSL through `openssl-src`. It needs its own audit entry.

## 5. Secret-handling findings (NOTES)

**N-1. `PRAGMA key` text is copied into an un-zeroized `String`. Confirmed.**
`pragma.rs:9-11` `pub struct Sql { buf: String }` has no `Drop` and no zeroize.
`Connection::pragma_update` (pragma.rs:222-239) builds `PRAGMA key=` and calls `Sql::push_value` (49-75) → `push_string_literal` (77-79) → `wrap_and_escape` (113-124). That function pushes the value one `char` at a time into `buf` starting from capacity 0, so the String reallocates about log2(n) times and each old buffer is freed without zeroing. The final `buf` is freed un-zeroized when `sql` goes out of scope at the end of `pragma_update` (line 239). A `"x'<hex>'"` text value becomes `PRAGMA key='x''<hex>'''`.
`pragma_update_and_check` (244-263) and `pragma` (190-216) behave the same way.

**N-2. Blob key values leak into the error string.**
`Sql::push_value` rejects `ValueRef::Blob` with `err!(SQLITE_MISUSE, "Unsupported value \"{value:?}\"")` (pragma.rs:70-72). `ValueRef` derives `Debug` (types/value_ref.rs:8), so `pragma_update(None, "key", &key_bytes[..])` returns an `Error::SqliteFailure` whose message holds the **raw key bytes**.

**N-3. SQL text is copied into `Error::SqlInputError`.**
`error_with_offset` (error.rs:466-487, called from inner_connection.rs:256 on any prepare failure) runs `sql.to_owned()` when the code is plain SQLITE_ERROR (`ErrorCode::Unknown`) and `sqlite3_error_offset >= 0`. `Display` then prints `"{msg} in {sql} at offset {offset}"` (error.rs:325-330). So if a key-bearing statement fails to prepare with a token offset, the key appears in the error text and in any log line.

**N-4. `Statement` Debug and `expanded_sql`.**
`impl Debug for Statement` (statement.rs:766-778) prints `sqlite3_sql()`, the full SQL text. `Statement::expanded_sql` (statement.rs:712-716) returns the SQL with bound values filled in. Neither should be used on key-bearing statements.

**N-5. Where SQL text is retained after use.**
- `Connection::execute_batch` (lib.rs:539-558, used by `pragma_update`) prepares through `InnerConnection::prepare`. It **never** touches the statement cache, and each `Statement` is finalized at the end of its loop iteration.
- `sqlite3_prepare_v3` does keep its own copy of the SQL inside the Vdbe (that is what `sqlite3_sql` returns) until finalize. It is freed through the SQLite/SQLCipher allocator and zeroed only if SQLCipher `cipher_memory_security` is ON. That is SQLCipher behaviour, outside rusqlite.
- On the Rust side, **only `prepare_cached`** keeps SQL text: the trimmed `Arc<str>` key in `StatementCache` (cache.rs:141-149) and `RawStatement::statement_cache_key` (raw_statement.rs:27), until LRU eviction, `flush_prepared_statement_cache` or Connection drop.
- `ParamIndexCache` keeps parameter *names* only.
- Bound values (TRANSIENT copies) stay in SQLite memory until rebind, `clear_bindings` or finalize. Cached statements get `clear_bindings` on return to the cache (cache.rs:159).

**N-6. Transaction drop behaviour.**
`Transaction::finish_` with `DropBehavior::Commit` runs `commit_().or_else(|_| rollback_())` (transaction.rs:224). If COMMIT fails (for example SQLITE_BUSY) and ROLLBACK succeeds, `finish()` returns `Ok(())`. Savepoint behaves the same way (349). The default `DropBehavior::Rollback` and an explicit `commit()` are **not** affected: `commit()` returns the COMMIT error. Separately, `DropBehavior::Panic` panics inside `Drop`.

**N-7. SQL injection in savepoint names.**
`Savepoint::with_name_` interpolates the name unescaped: `format!("SAVEPOINT {name}")` at transaction.rs:253, and the same for RELEASE (314) and ROLLBACK TO (328). Names must never come from untrusted input.

**N-8. Panic on malformed date text (robustness, not UB).**
`impl FromSql for OffsetDateTime` evaluates `s[8..]` at types/time.rs:79. That panics for TEXT values shorter than 8 bytes or with a non-char boundary at byte 8. It is reachable from database content through the `time` feature that tor-dirmgr enables, so a corrupted dir-cache row panics instead of returning an error.
Other `expect` calls that can panic: non-UTF-8 column or parameter names (column.rs:151, statement.rs:469), `busy_timeout` with a duration above i32 ms (busy.rs:32), and OOM asserts.

**Mitigations for SecMPro (outside rusqlite):**
- Pass the key only as a `Zeroizing<String>` in `"x'…'"` form. Never pass it as a blob.
- Never Debug- or Display-format a rusqlite `Error` or `Statement` from the key path. Map the error to a key-free error code.
- Don't use `prepare_cached` for the key.
- Set `PRAGMA cipher_memory_security = ON` if wiping SQLite heap memory on free is required.
- Accept or document that the transient `Sql` heap copies are not zeroized, or bypass `pragma_update` by calling `sqlite3_key_v2` through `Connection::handle()`. That function is available with bundled SQLCipher; using it needs an ADR decision.

## 6. supply-chain/audits.toml entry (proposed)

```toml
[[audits.rusqlite]]
who = "<reviewer>"
criteria = "safe-to-deploy"
version = "0.39.0"
notes = "Read in full every module compiled under the unified features (default/cache, time, bundled, bundled-sqlcipher[-vendored-openssl], modern_sqlite): lib, inner_connection, raw_statement, statement, row, params, bind, column, error, transaction, pragma, config, busy, cache, version, auto_extension, types/{mod,from_sql,to_sql,value,value_ref,time}, util/*. 96 unsafe sites (FFI, SQLite-owned CStr/slices, 1 fn-ptr transmute, Send/Sync impls) judged sound; TRANSIENT binds, drop order and error mapping OK. No build.rs, net, process or fs beyond sqlite3_open_v2. Notes: pragma_update copies values (PRAGMA key) into un-zeroized pragma::Sql String; blob values and SqlInputError put key/SQL text into error strings; time.rs:79 can panic on short TEXT. libsqlite3-sys/SQLCipher C not covered."
```

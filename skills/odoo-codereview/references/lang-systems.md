# Language Patterns — Systems

Go and Rust.

## Go

### HTTP / Server

- `http.ListenAndServe` with handler that uses `r.URL.Path` directly to read files = traversal. Use `filepath.Clean` + prefix check.
- `http.FileServer` rooted at user-controlled dir = obvious traversal.
- `r.RemoteAddr` trusted for rate-limit when behind proxy = bypass via `X-Forwarded-For`.
- `r.ParseMultipartForm(maxMemory)` — verify max bound. Default `maxMemory` doesn't cap total disk usage.
- `r.Body` not closed = leak. Defer `r.Body.Close()`.
- Routers: gin/echo/chi — middleware order matters. Verify auth middleware mounted before route group.
- `gorilla/csrf` or framework equivalent — verify on cookie-auth state-changing endpoints.

### SQL

- `db.Query("SELECT ... WHERE id = " + id)` = injection.
- `db.Query("SELECT ... WHERE id = ?", id)` = safe.
- `sqlx.NamedExec` with map from user = verify the SQL template uses bind params, not Go-templated values.
- `gorm` — `Where("id = ?", id)` safe. `Where(fmt.Sprintf("id = %s", id))` unsafe.
- Identifier quoting: gorm `Table("users")` with concat → table name injection.

### Crypto

- `math/rand` for security-sensitive values = predictable. Use `crypto/rand`.
- `subtle.ConstantTimeCompare` for token compare; `bytes.Equal` is timing-side-channel.
- `crypto/aes` + `cipher.NewCBC` without HMAC = padding oracle. Use GCM.
- `crypto/tls` config — `InsecureSkipVerify: true` = MITM. Hunt for it.
- `golang.org/x/crypto/bcrypt` — cost < 10 = weak.
- JWT (`golang-jwt/jwt`): `Parse` requires keyfunc that returns expected type. Algorithm confusion attacks if not validated.

### Deserialization

- `encoding/gob` on untrusted input — Go gob can construct types but RCE primitives are limited compared to Java. Still risky.
- `encoding/xml` — XXE not directly supported in stdlib (good), but third-party XML libs may. `etree` etc.
- `gopkg.in/yaml.v2` < 2.4 — type assertion panics on malformed input (DoS).
- `encoding/json` — generally safe but `json.RawMessage` deferred to later parser.

### Process / FS

- `exec.Command(cmd, args...)` safer than `exec.Command("sh", "-c", cmd)` if `cmd` ever has user input.
- `os.OpenFile(user, ...)` with traversal → file disclosure.
- `filepath.Join(base, user)` does NOT prevent traversal (`..` is honored). Use `filepath.Clean` + `strings.HasPrefix(realPath, baseAbs)`.

### Concurrency

- Goroutine leaks via channel deadlock — DoS vector if attacker can spawn many.
- `sync.Map` vs map+mutex — wrong choice causes races but not usually security. Skip unless TOCTOU on a security check.
- Context cancellation not propagated — runaway request = DoS.

### SSRF

- `http.Get(url)` with user URL → SSRF.
- `net/http` doesn't restrict IP space by default. Custom `net.Dialer` with `Control` callback to reject 169.254/127/10/etc.
- DNS rebinding: resolve once for validation, then connect = TOCTOU. Pin IP after first resolve.

### Versions to Flag (April 2026)

- Go < 1.22 — runtime CVEs.
- gin < 1.9.x — multiple CVEs.
- gorilla/\* archived (since Dec 2022) — replacement libs vary.

## Rust

### Memory Safety

- `unsafe` blocks — read each one. Common bugs: out-of-bounds writes, use-after-free, data races.
- `transmute` — type confusion.
- Raw pointer arithmetic in safe-looking wrappers.

### HTTP / Async

- `actix-web`, `axum`, `rocket`: routing + middleware. Verify auth extractor runs.
- `tower` middleware order — same as Express: auth before route.
- TLS: `reqwest::Client::builder().danger_accept_invalid_certs(true)` = MITM.
- `tokio::process::Command` — same `Command(cmd).args(args)` vs shell pattern as Go.

### SQL

- `sqlx::query!` macro — compile-time checked, parameterized, safe.
- `sqlx::query(format!(...))` = injection.
- `diesel` query DSL — safe by construction. `diesel::sql_query(format!(...))` = injection.

### Deserialization

- `serde_json::from_str` — generally safe for typed structs. Untagged enums + attacker JSON can cause panics → DoS.
- `serde_yaml` — older versions had YAML 1.1 quirks.
- `bincode` on untrusted input — type confusion possible if version mismatch.
- `rmp-serde` (MessagePack) — similar.

### Crypto

- `ring` — modern, hard to misuse.
- `RustCrypto/aes` + manual CBC — padding oracle if no MAC.
- `rand::thread_rng()` is ChaCha20 (CSPRNG since 0.8). `rand::random()` same. Verify version pin.
- `sha2`, `blake3` for hashing — fine. Don't use for passwords. Use `argon2`.
- `subtle::ConstantTimeEq` for compares.

### Panic / DoS

- `unwrap` / `expect` on attacker-influenced data = panic = thread / task crash. Async runtime usually keeps server up but specific tasks die.
- `unreachable!()` reachable via specific input = same.
- Integer overflow: `u32::MAX + 1` panics in debug, wraps in release (default). Use `checked_add` etc.
- `String::with_capacity(n)` where `n` from user = unbounded allocation.

### Cargo / Supply Chain

- `cargo-audit` for known CVEs in deps.
- Build scripts (`build.rs`) execute at compile. Untrusted dependency = code execution.
- Procedural macros (`proc-macro2` deps) execute at compile. Same.
- `[patch.crates-io]` / git deps — ensure pinned to commit SHA, not branch.

### Versions to Flag (April 2026)

- Rust toolchain < 1.78 — various stdlib fixes.
- tokio < 1.37 — cancellation safety bugs.
- hyper < 1.x — old API.
- reqwest < 0.12 — TLS lib transition.
- `time` < 0.3.36 — formatter bugs.

## Cross-Language Notes

- **Logging:** never log secrets, tokens, or PII. Hunt for `log.info(req)` and `log.debug(token)`.
- **Error messages:** never include stack traces or query SQL in user-facing errors.
- **Telemetry / metrics tags:** high-cardinality from user input = memory blow-up.
- **Config files:** check for committed `.env`, `config/secrets.yml`, `terraform.tfvars` with secrets.

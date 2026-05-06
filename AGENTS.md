# Repository Guidelines

## Project Structure & Module Organization
- `src/lib.rs` exposes the reusable modules: `guan_yuan_sso` (RSA helpers) and `http_api` (Axum router/state). Keep new core logic here so both binaries and tests can reuse it.
- `src/main.rs` only hosts the HTTP server bootstrap (env parsing, socket binding). Keep it thin and delegate to library modules.
- API handlers live in `src/http_api.rs`; each route should be coded here with request/response structs defined via Serde for clean JSON translations.
- RSA primitives stay in `src/guan_yuan_sso.rs` so any future CLI or jobs can consume them without depending on the HTTP layer.
- Runtime artifacts are written to `target/`; avoid committing anything under that directory.

## Build, Test, and Development Commands
- `cargo build` — compile the server and surface compiler warnings.
- `cargo run` — start the Axum API (listens on `$SSO_BIND_ADDR`, defaults to `0.0.0.0:8080`). Requires `GUANYUAN_PRIVATE_KEY` in Base64 PKCS#8 form; optional `GUANYUAN_PUBLIC_KEY` and `SSO_BASE_URL`, `SSO_PROVIDER` override URL settings.
- `cargo test` — run module/unit tests, including the HTTP handler smoke test that exercises `/api/token`.
- `cargo fmt` — format all Rust sources with the project style rules.
- `cargo clippy -- -D warnings` — run the lint suite and fail on warnings to keep CI green.

## Coding Style & Naming Conventions
- Follow standard Rustfmt defaults: 4-space indentation, trailing commas where possible, and minimal `use` wildcards.
- Modules and functions should use `snake_case`, types and traits `CamelCase`, and constants `SCREAMING_SNAKE_CASE`.
- Keep functions short; when logic grows, move it into helper modules (`http_api`, `guan_yuan_sso`) to preserve `main.rs` as an orchestration layer.
- Document non-obvious behavior with `///` doc comments so `cargo doc` output stays meaningful.

## Testing Guidelines
- Prefer Rust unit tests colocated with the module they exercise: add a `mod tests { ... }` block at the bottom of each file.
- API handlers can be validated with Axum’s router + `tower::ServiceExt::oneshot`, as shown in `http_api.rs`.
- Name tests after the behavior (`handles_wraparound_count`) rather than the method, and include assertions covering edge cases (e.g., early loop exits).
- Run `cargo test` before every push; add regression tests whenever you fix a bug.

## Commit & Pull Request Guidelines
- Use imperative, present-tense commit subjects under 65 characters (e.g., `add loop guard for counter overflow`) followed by concise bodies when context is needed.
- Reference related issues in the footer (`Refs #12`) and explain any user-facing effects.
- Pull requests should include: a short summary, testing evidence (`cargo test` output or screenshots), and any follow-up TODOs so reviewers can verify state quickly.

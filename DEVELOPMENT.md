# Development

This repository owns `verification-code` independently of the Inbox Grinder app. Existing plugin IDs and contract versions are preserved. Fixtures are synthetic; see PRIVACY.md.

Build automation is shared from [plugin-sdk](https://github.com/inbox-grinder/plugin-sdk), pinned to `51674b696c62ea7dd2498e0b52cb0aae4c7ffca8`. Run `python3 /path/to/plugin-sdk/scripts/plugin.py --root "$PWD"` with Python 3.10+, jsonschema 4.26.0, and the language tools installed. This runs tests, builds the runtime, and writes a runtime-only ZIP and SHA-256 file under `dist/`.

Install the Rust `wasm32-unknown-unknown` target. Use `cargo test --locked` for unit tests.

To release, update the manifest version, update Cargo.toml and Cargo.lock if present, commit, then push a matching `v<version>` tag. CI rejects version mismatches and publishes exactly one package ZIP plus a checksum file after tests pass. No repository secret is required. Catalogue submission and curation remain separate steps.

No open-source license has been declared. Public repository visibility does not grant a license.

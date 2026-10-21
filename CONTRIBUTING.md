# Contributing & Open-Source Hygiene Policy

Velenza Inarch (`inr`) is a strictly vendor-neutral, clean-room open-source project licensed under Apache-2.0.

## Strict Zero-Proprietary-IP & Config-Only Policy

To keep Velenza Inarch 100% portable and safe for public distribution, the repository enforces three non-negotiable rules through automated CI tests (`crates/inarch-cli/tests/open_source_hygiene_test.rs`) and `.githooks/pre-commit`:

1. **Zero Proprietary IP or Organization Identifiers**
   - No organization names, internal codenames, internal project identifiers, or proprietary domain names may appear anywhere in source code, comments, tests, commit messages, or documentation.
   - Use generic domains (`@example.com` or `@inarch.dev`) in unit and integration tests.

2. **Zero Hardcoded Environment Coordinates**
   - Never hardcode workstation paths (`/Users/<name>`, `/Volumes/<name>`, `/home/<name>`, `C:\Users\<name>`), internal hostnames, cloud project IDs, database instance IDs, or private/Tailscale IP addresses (`100.x.x.x`, `10.x.x.x`, `192.168.x.x`).

3. **Everything Goes Through Configuration (`InarchConfig`)**
   - All deployment-specific coordinates—storage paths, cache directories, server endpoints, default branch names, default author identities, ignore lists, and path ACL rules—must be supplied at runtime via `inarch.toml`, `.inarch/config.toml`, `--config <path>`, or `INARCH_*` environment variables.
   - See [`inarch.example.toml`](./inarch.example.toml) for the full configuration schema.
   - Local configuration files (`inarch.toml` and `.inarch/`) are listed in `.gitignore` and blocked from being committed by `.githooks/pre-commit`.

## Enabling the Pre-Commit Guard

Run the following command once after cloning, or let the repository bootstrap configure it automatically:

```sh
git config core.hooksPath .githooks
```

You can also place additional organization-specific forbidden substrings in `.git/info/forbidden-patterns.txt` (one pattern per line, untracked by Git). Both the pre-commit hook and `cargo test` will scan every file against those patterns as well as the built-in cryptographic token digest filter.

## License, Code of Conduct & Contact

- **License**: By contributing to Velenza Inarch, you agree that your contributions will be licensed under the [Apache License, Version 2.0](./LICENSE) and subject to the attribution requirements in [`NOTICE`](./NOTICE).
- **Code of Conduct**: Participation is governed by our [Code of Conduct](./CODE_OF_CONDUCT.md).
- **Security Vulnerabilities**: Please follow [`SECURITY.md`](./SECURITY.md) and report security issues privately via GitHub Private Vulnerability Reporting or email to **open-source@velenzaboc.com**.
- **General Open-Source Contact**: **open-source@velenzaboc.com**

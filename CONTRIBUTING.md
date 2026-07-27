# Contributing

Contributions should remain compatible with the official WiFi Pineapple
Mark VII module structure and should be suitable for a future pull request to
`hak5/pineapple-modules`.

## Development rules

- Keep the module name `PineAI` consistent in paths, metadata, frontend
  requests, and backend registration.
- Bump the module version for every release submitted upstream.
- Keep deterministic parsing and policy decisions outside the language model.
- Treat SSIDs, hostnames, probe data, API responses, and model output as
  untrusted input.
- Never execute model-generated shell commands.
- Require explicit operator approval before starting an active or disruptive
  operation.
- Do not commit API keys, device tokens, packet captures, Recon exports, or
  customer data.

## Validation

Before opening a pull request:

1. Use Node.js 16 and run `npm ci`.
2. Run `python3 -m unittest discover -s tests -v`.
3. Run `npm test -- --watch=false --browsers=ChromeHeadless`.
4. Run `npm run build -- --prod`.
5. Run `./build.sh package` in a Linux-compatible environment.
6. Confirm `dist/PineAI/assets/pineai_backend/` and
   `dist/PineAI/assets/pineai_cli.py` exist.
7. Inspect the archive and verify its SHA-256 checksum.
8. Install the package on a physical Mark VII.
9. Verify backend actions, secret-file permissions, network TLS, and
   uninstall/reinstall behavior.

Security issues should be reported according to [SECURITY.md](SECURITY.md).

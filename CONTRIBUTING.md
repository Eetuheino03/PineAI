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

1. Run `npm install`.
2. Run `npm run build`.
3. Run `./build.sh package` in a Linux-compatible environment.
4. Install the package on a physical Mark VII.
5. Verify frontend/backend communication and uninstall/reinstall behavior.

Security issues should be reported according to [SECURITY.md](SECURITY.md).

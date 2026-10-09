# @munhq/sealkeep

Give AI agents the use of your secrets without the values. This package runs the [sealkeep](https://github.com/munhq/sealkeep) binary: it downloads the release build for your platform, checks it against the `SHA256SUMS` of the release, and caches it.

MCP server (stdio):

```json
{ "mcpServers": { "sealkeep": { "command": "npx", "args": ["-y", "@munhq/sealkeep"] } } }
```

CLI:

```sh
npx @munhq/sealkeep list
npx @munhq/sealkeep run shared/openrouter/API_KEY -- sh -c 'curl -H "Authorization: Bearer $API_KEY" https://openrouter.ai/api/v1/key'
```

For the guard hook and the skill in Claude Code, Codex and Cursor, install the binary itself (`curl -fsSL https://raw.githubusercontent.com/munhq/sealkeep/main/install.sh | sh`), so the hooks point to a stable path.

`SEALKEEP_BIN` runs a local build instead of the download. Licence: MIT.

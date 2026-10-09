# sealkeep

sealkeep lets an AI agent use your secrets without seeing them.

The agent asks for a secret by its name. sealkeep puts the value into the environment of one command, runs the command, and replaces the value with `[sealkeep:NAME]` in all the output. The value does not go into the context, the transcript or a file.

```
agent ──► sealkeep run OPENROUTER_API_KEY -- sh -c 'curl -H "Authorization: Bearer $OPENROUTER_API_KEY" …'
              │
              ├─ reads the value from a store ──► OS keyring  (macOS Keychain, Secret Service, Windows Credential Manager)
              │                               └─► Proxium project (sealed on the server, each read logged)
              ├─ starts the command with the value in its environment
              └─ redacts the value from stdout and stderr ──► agent sees [sealkeep:OPENROUTER_API_KEY]
```

It has four parts:

1. **A CLI** (`sealkeep`): `set`, `list`, `run`, `import` and the store commands.
2. **An MCP server** (`sealkeep mcp`): the tools `list_secrets`, `run_with_secrets` and `store_status`. No tool returns a value.
3. **A guard hook** (`sealkeep guard`): it refuses the tool calls that would print a secret, for example `cat .env` or `sealkeep get`.
4. **A skill** that tells the agent when and how to use the CLI.

## Install

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/munhq/sealkeep/main/install.sh | sh
```

The script downloads the binary of the newest release, checks it against `SHA256SUMS`, copies it to `~/.local/bin`, and runs `sealkeep install`.

With Rust:

```sh
cargo install --locked --git https://github.com/munhq/sealkeep
sealkeep install
```

`sealkeep install` finds the AI clients on the machine. It adds the skill, the MCP server and the guard hook to each client:

| Client | Skill | MCP server | Guard hook |
|---|---|---|---|
| Claude Code (each config folder) | `<config>/skills/sealkeep` | `claude mcp add --scope user` | `<config>/settings.json`, PreToolUse on `Bash`, `Read`, `Grep` |
| Codex | `$CODEX_HOME/skills/sealkeep` | `codex mcp add` | `$CODEX_HOME/hooks.json`, PreToolUse (approve it one time with `/hooks`) |
| Cursor | `~/.cursor/skills/sealkeep` | `~/.cursor/mcp.json` | `~/.cursor/hooks.json`, beforeShellExecution |

Options: `--client claude,codex` installs into the named clients only. `--dry-run` shows the plan. `--no-skills`, `--no-mcp` and `--no-hooks` leave out a part. Before sealkeep changes a JSON file, it writes a backup (`<file>.bak-<unix time>`). `sealkeep uninstall` removes what `install` added.

Run `sealkeep doctor` to check the stores and the clients.

## Use it

### Store a secret

```sh
sealkeep set OPENROUTER_API_KEY -d "OpenRouter, personal account"
```

sealkeep asks for the value two times, with no echo. To pipe a value in, use `--stdin`:

```sh
some-password-tool show openrouter | sealkeep set OPENROUTER_API_KEY --stdin
```

A name is an environment variable name: `A-Z`, `0-9` and `_`, and it starts with a letter.

To copy the entries of a `.env` file:

```sh
sealkeep import ../example-app/.env --prefix EXAMPLE_APP_
```

`import` prints the names only. After the import, delete the `.env` file or keep it out of the reach of the agent.

### Let the agent use it

Tell the agent what to do. The skill tells it to run `sealkeep list` for the names, and `sealkeep run` for the command:

```sh
sealkeep run OPENROUTER_API_KEY -- sh -c 'curl -sS -H "Authorization: Bearer $OPENROUTER_API_KEY" https://openrouter.ai/api/v1/key'
sealkeep run -e GITHUB_TOKEN=GH_PAT -- gh api user
```

`-e VAR=NAME` sets a variable with a different name. `STORE:NAME` reads from one store only.

For a tool that reads its secrets from a file, `--dotenv` writes a temporary file that only you can read. The file is in `$XDG_RUNTIME_DIR/sealkeep` when it exists. sealkeep puts the path where the command has `{dotenv}`, and it removes the file when the command ends. This example gives Playwright MCP the login of a test account. The agent types the name `ADMIN_PASSWORD`, and Playwright puts in the value:

```sh
sealkeep run --dotenv ADMIN_EMAIL --dotenv ADMIN_PASSWORD -- npx @playwright/mcp@latest --secrets {dotenv}
```

`--secrets <path>` is an option of `@playwright/mcp` (see its README).

### See a value yourself

```sh
sealkeep get OPENROUTER_API_KEY
```

`get` works only when stdin and stdout are a terminal. An agent runs commands without a terminal, so `get` refuses, and the guard hook also refuses it.

## Stores

sealkeep looks up a bare name in the stores in the order of the config file. The first store that has the name gives the value.

The config file is `~/.config/sealkeep/config.toml` on Linux and `~/Library/Application Support/sealkeep/config.toml` on macOS. `$SEALKEEP_CONFIG` sets another path. With no file, sealkeep has one keyring store named `local`.

```toml
[[store]]
name = "local"
kind = "keyring"

[[store]]
name = "team"
kind = "proxium"
url = "https://proxium.tech"
project = "acme"

[guard]
block_dotenv = true
deny = ["vault kv get", "ansible-vault view"]
```

### The OS keyring

| OS | Store |
|---|---|
| macOS | the login Keychain |
| Linux, BSD | the Secret Service (GNOME Keyring, KWallet) on the session D-Bus |
| Windows | the Credential Manager |

Each secret is one entry with the service `sealkeep` and the secret name as the account. An index entry (`__index__`) keeps the names and the descriptions.

On Linux, the keyring must be unlocked. A desktop session unlocks it when you log in. A session with no desktop (SSH, a login with no keyring password) has a locked keyring, and no unlock prompt can show. Run this one time after each boot:

```sh
sealkeep unlock
```

It asks for the password of the login keyring and gives it to `gnome-keyring-daemon --unlock`. Each keyring call waits at most 30 seconds (`SEALKEEP_KEYRING_TIMEOUT`), so an agent gets an error, and the call does not hang.

### A Proxium project

[Proxium](https://proxium.tech) keeps the secrets of a project on the server. It seals each value with the data key of the project, and it logs each read with the person, the version and the purpose. The members of the project can read a value, and only the owners can change one.

```sh
sealkeep store add-proxium team --url https://proxium.tech --project acme
sealkeep login team          # device sign-in: approve the code in the browser
sealkeep set STRIPE_SECRET_KEY --store team
```

`login` keeps the session token in the OS keyring. For each call, sealkeep exchanges it for a token that is valid for 15 minutes. The purpose of each read is the command line that `run` starts, so the log of the project shows what each read was for.

## MCP

`sealkeep mcp` serves these tools on stdio:

| Tool | What it does |
|---|---|
| `list_secrets` | The names, stores and descriptions. |
| `run_with_secrets` | Runs `command` (a list of arguments, with no shell) with `secrets` in the environment and `dotenv` in a temporary file. Returns the exit code, stdout and stderr, redacted. The time limit is 120 s by default and 900 s at most. Each stream is cut at 100 KiB. |
| `store_status` | Whether each store can be used now. |

## The guard hook

The hook refuses these tool calls, and it tells the agent to use `sealkeep run`:

1. `sealkeep get`, also inside `$(…)`, backticks and `bash -c`.
2. A read of the sealkeep keyring entries: `secret-tool lookup service sealkeep …`, `security find-generic-password -s sealkeep … -w`, `keyring get sealkeep …`.
3. A read of a `.env` file by a shell command or by the Read and Grep tools, when `block_dotenv` is on. `.env.example`, `.env.sample`, `.env.template` and `.env.dist` stay readable.
4. Each command prefix in `guard.deny`.

## What sealkeep protects, and what it does not

sealkeep keeps secrets out of the context of the agent, out of the transcript and out of the files of the project. Each use goes into the audit log (`~/.local/share/sealkeep/audit.jsonl` on Linux, or `$SEALKEEP_AUDIT_LOG`), with the names and the command and never a value. A Proxium store also logs each read on the server.

Redaction matches the value, its JSON-escaped form, its percent-encoded form and its base64 forms. A value that is shorter than 4 characters is not redacted. A command that transforms a value in another way (for example, a hash or a part of the value) can print it in a form that sealkeep does not match.

An agent that can run any shell command as your user can read what your user can read. sealkeep does not change that. It makes the safe path the easy one, it refuses the common paths to a value, and it records each use. Give an agent keys with a small scope: a restricted Stripe key, an OpenRouter key with a spend limit, a test account for a web login.

## Build and test

```sh
cargo build --release
cargo test --features test-store
```

The `test-store` feature replaces the OS keyring with a file, for the tests only. The release binaries are built without it.

## Licence

MIT or Apache-2.0, at your choice.

---
name: sealkeep
description: Use a password, API key or token without seeing it. Use when a task needs a credential - an API key (OpenRouter, Stripe, OVH, GitHub), a password for a web login, a database URL, a token in a .env file - or when the person says "use my key", "log in to the UI", "call the API with my token", "the password is in the keyring". sealkeep injects the secret into the command and redacts it from the output. Never ask the person to paste a secret, and never read a .env file to get one.
---

# sealkeep

sealkeep keeps secrets in the OS keyring or in a Proxium project. It gives a secret to a command, and it replaces the value with `[sealkeep:NAME]` in everything the command prints. You use the secret by its name and you never see the value.

## The rules

1. Do not ask the person for a secret value. Run `sealkeep list` and use a name from the list.
2. Do not print a value. Do not run `sealkeep get`, `cat .env`, `secret-tool lookup`, `security find-generic-password -w` or `printenv`. The guard hook refuses these commands.
3. Send a secret only to the service it belongs to. Do not write it to a file, a commit, a log, an issue or a message.
4. If the secret that the task needs is not in the list, stop. Tell the person the name to add with `sealkeep set NAME`. Do not look for the value somewhere else.

## Find the names

```sh
sealkeep list            # name, store, description
sealkeep list --json
```

A name looks like `OPENROUTER_API_KEY`. `STORE:NAME` picks a store, for example `team:STRIPE_SECRET_KEY`.

## Run a command with secrets

Each name becomes an environment variable of the same name. Refer to it as `$NAME` in a shell:

```sh
sealkeep run OPENROUTER_API_KEY -- sh -c 'curl -sS -H "Authorization: Bearer $OPENROUTER_API_KEY" https://openrouter.ai/api/v1/key'
```

To choose the variable name, use `-e VAR=NAME`:

```sh
sealkeep run -e GITHUB_TOKEN=GH_PAT -- gh api user
sealkeep run -e DATABASE_URL=team:APP_DB_URL -- psql "$DATABASE_URL" -c 'select 1'
```

Use single quotes around the shell script, so your shell does not expand `$NAME` before sealkeep sets it.

## A tool that reads a dotenv file

`--dotenv NAME` writes the secret to a temporary file that only the user can read, puts the file path where the command has `{dotenv}`, and removes the file when the command ends:

```sh
sealkeep run --dotenv ADMIN_EMAIL --dotenv ADMIN_PASSWORD -- npx @playwright/mcp@latest --secrets {dotenv}
```

## Web logins (Playwright)

When the Playwright MCP server was started with `--secrets` through sealkeep, type the secret NAME (for example `ADMIN_PASSWORD`) into the field. Playwright puts in the value, and you do not see it.

## Through MCP

If your client has the sealkeep MCP server, use the tools `list_secrets`, `run_with_secrets` and `store_status`. They work the same as the CLI. `run_with_secrets` runs the command without a shell, so use `["sh", "-c", "..."]` to refer to `$NAME`.

## When something fails

- `no store has a secret NAME`: the secret is not stored. Tell the person to run `sealkeep set NAME`.
- `store team is not signed in` or `the session ... has expired`: tell the person to run `sealkeep login team`.
- `the OS keyring is not available`: the session has no keyring (for example, a server with no desktop session). Tell the person; do not look for another way to get the value.
- Run `sealkeep doctor` to see the stores and the installed clients.

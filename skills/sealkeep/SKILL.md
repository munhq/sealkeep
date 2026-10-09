---
name: sealkeep
description: Use a password, API key or token without seeing it. Use when a task needs a credential - an API key (OpenRouter, Stripe, OVH, Cloudflare, GitHub), a password for a web login, a database URL, the variables of a .env file - or when the person says "use my key", "log in to the UI", "call the API with my token", "run it with the prod env". sealkeep injects the secret into the command and redacts it from the output. Never ask the person to paste a secret, never say that you do not have one before you check `sealkeep list`, and never read a .env file to get one.
---

# sealkeep

sealkeep keeps secrets in the OS keyring (and in Vault as a replica). It gives a secret to a command, and it replaces the value with `[sealkeep:NAME]` in everything the command prints. You use a secret by its name, and you never see the value.

## Names

`<scope>/<project>/<env>/<KEY>`:

- **scope**: `personal`, the name of an employer or a client, or `shared` (one account that several scopes use, for example Stripe).
- **project**: the repository or the service: `example-app`, `stripe`, `ovh`, `cloudflare`.
- **env**: `prod`, `dev`, `test`, `local`. It is absent when the secret has no environment.
- **KEY**: the environment variable that the program reads.

Examples: `personal/example-app/prod/DATABASE_URL`, `shared/stripe/test/SECRET_KEY`, `acme/ovh/ovh-eu/APPLICATION_KEY`. A project folder can have an alias to a shared secret, so the folder has every variable that the project needs.

## The rules

1. Before you say that a secret is missing, run `sealkeep list <folder>` (or `sealkeep list`). Look in the folder of the project, then in `shared/`.
2. Do not ask the person for a value. Do not print a value. Do not run `sealkeep get`, `cat .env`, `secret-tool lookup`, `security find-generic-password -w` or `printenv`. The guard hook refuses these commands.
3. Send a secret only to the service it belongs to. Do not write it to a file, a commit, a log, an issue or a message.
4. If the secret is not in the list, stop. Tell the person the exact name to add, in the convention above: `sealkeep set personal/example-app/prod/NEW_KEY`.

## Run a command

```sh
sealkeep list personal/example-app               # the names of a project
sealkeep run --all personal/example-app/dev -- npm run dev
sealkeep run shared/openrouter/API_KEY -- sh -c 'curl -sS -H "Authorization: Bearer $API_KEY" https://openrouter.ai/api/v1/key'
sealkeep run -e GITHUB_TOKEN=personal/github/PAT -- gh api user
```

- A name sets the variable named by its key (`shared/openrouter/API_KEY` sets `API_KEY`).
- `--all FOLDER` sets one variable for each secret in the folder, the same as a `.env` file. `--recursive` also takes the subfolders.
- `-e VAR=NAME` sets a variable with a different name.
- Use single quotes around a shell script, so your shell does not expand `$KEY` before sealkeep sets it.

## A tool that reads a dotenv file

```sh
sealkeep run --dotenv personal/example-app/dev/ADMIN_EMAIL --dotenv personal/example-app/dev/ADMIN_PASSWORD \
  -- npx @playwright/mcp@latest --secrets {dotenv}
```

sealkeep writes a temporary file that only the user can read, puts its path where the command has `{dotenv}`, and removes it when the command ends. For a web login with Playwright MCP, type the key (`ADMIN_PASSWORD`) into the field. Playwright puts in the value.

## Through MCP

If your client has the sealkeep MCP server, use `list_secrets` (with `folder`), `run_with_secrets` (with `folders` and `secrets`) and `store_status`. `run_with_secrets` runs the command without a shell, so use `["sh", "-c", "..."]` to refer to `$KEY`.

## When something fails

- `no store has a secret NAME`: tell the person the name to add with `sealkeep set NAME`.
- `both set KEY`: two secrets in the `--all` folders have the same key. Name one folder, or use `-e` for one of them.
- `the OS keyring did not answer` or `the keyring is locked`: tell the person to run `sealkeep unlock` in a terminal.
- Run `sealkeep doctor` to see the stores and the installed clients.

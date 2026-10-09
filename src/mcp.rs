//! The MCP server (stdio). It gives an agent the names of the secrets and a way to run
//! a command with them. No tool returns a value: the output of each run is redacted.

use crate::config::Config;
use crate::names::Binding;
use crate::run::{self, RunSpec};
use crate::store::Stores;
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_TIMEOUT_SECS: u64 = 120;
const MAX_TIMEOUT_SECS: u64 = 900;
const OUTPUT_LIMIT: usize = 100 * 1024;

const INSTRUCTIONS: &str = "sealkeep runs commands with secrets that you never see. \
Names are <scope>/<project>/<env>/<KEY>, for example shared/stripe/test/SECRET_KEY. \
Call list_secrets for the names. Call run_with_secrets with the command and the folders or \
names: each secret goes into the environment variable named by its KEY (or VAR=NAME to choose \
the variable), and each value is replaced with [sealkeep:NAME] in the output. Refer to a \
secret in the command as $NAME through a shell, for example \
[\"sh\", \"-c\", \"curl -H \\\"Authorization: Bearer $API_KEY\\\" https://api.example.com\"]. \
Do not try to print, encode or send a value anywhere other than the service it belongs to.";

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListArgs {
    /// Only this store. Leave out for every store.
    #[serde(default)]
    pub store: Option<String>,
    /// Only this folder and below, for example personal/example-app/dev.
    #[serde(default)]
    pub folder: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunArgs {
    /// The command and its arguments, for example ["sh", "-c", "curl -sS -H \"Authorization: Bearer $OPENROUTER_API_KEY\" https://openrouter.ai/api/v1/models"].
    pub command: Vec<String>,
    /// Folders: every secret in each folder goes into the variable named by its key, for example "personal/example-app/dev".
    #[serde(default)]
    pub folders: Vec<String>,
    /// With folders: also the secrets in their subfolders.
    #[serde(default)]
    pub recursive: bool,
    /// Single secrets: NAME (the variable is its key), STORE:NAME, or VAR=NAME to choose the variable.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Secrets that go into a temporary dotenv file instead. The argument {dotenv} in the command becomes its path. The file is removed when the command ends.
    #[serde(default)]
    pub dotenv: Vec<String>,
    /// The working folder. Leave out for the folder of the MCP server.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Text for the standard input of the command.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Seconds before the command is stopped. Default 120, at most 900.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Server {
    tool_router: ToolRouter<Self>,
}

fn tool_error(msg: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(msg.into())])
}

fn json_result(v: Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&v).unwrap_or_default(),
    )])
}

fn parse_bindings(list: &[String]) -> anyhow::Result<Vec<Binding>> {
    list.iter().map(|s| Binding::parse(s)).collect()
}

#[tool_router]
impl Server {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List the secret names that run_with_secrets can use, with their store and description. It never returns a value.",
        annotations(read_only_hint = true)
    )]
    async fn list_secrets(
        &self,
        Parameters(args): Parameters<ListArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let r = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
            let cfg = Config::load()?;
            let stores = Stores::from_config(&cfg);
            let (mut list, errors) = stores.list_all();
            if let Some(s) = &args.store {
                list.retain(|i| &i.store == s);
            }
            if let Some(f) = &args.folder {
                list.retain(|i| crate::names::under(&i.name, f));
            }
            list.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(json!({ "secrets": list, "errors": errors }))
        })
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(match r {
            Ok(v) => json_result(v),
            Err(e) => tool_error(format!("{e:#}")),
        })
    }

    #[tool(
        description = "Run a command with secrets in its environment (or in a temporary dotenv file). Returns the exit code, stdout and stderr, with each secret value replaced by [sealkeep:NAME]. The command runs without a shell; use [\"sh\", \"-c\", \"...\"] to refer to $NAME.",
        annotations(destructive_hint = true, open_world_hint = true)
    )]
    async fn run_with_secrets(
        &self,
        Parameters(args): Parameters<RunArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let r = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
            let cfg = Config::load()?;
            let stores = Stores::from_config(&cfg);
            let timeout = Duration::from_secs(
                args.timeout_secs
                    .unwrap_or(DEFAULT_TIMEOUT_SECS)
                    .clamp(1, MAX_TIMEOUT_SECS),
            );
            let mut env: Vec<Binding> = Vec::new();
            for f in &args.folders {
                for b in stores.folder_bindings(f.trim_end_matches('/'), None, args.recursive)? {
                    env.retain(|x| x.var != b.var);
                    env.push(b);
                }
            }
            for b in parse_bindings(&args.secrets)? {
                env.retain(|x| x.var != b.var);
                env.push(b);
            }
            let spec = RunSpec {
                argv: args.command,
                env,
                dotenv: parse_bindings(&args.dotenv)?,
                cwd: args.cwd.map(PathBuf::from),
                action: "mcp_run",
            };
            let prepared = run::prepare(&stores, spec)?;
            let c = prepared.run_captured(args.stdin, timeout, OUTPUT_LIMIT)?;
            Ok(json!({
                "exit_code": c.exit_code,
                "stdout": c.stdout,
                "stderr": c.stderr,
                "truncated": c.truncated,
                "timed_out": c.timed_out,
            }))
        })
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(match r {
            Ok(v) => json_result(v),
            Err(e) => tool_error(format!("{e:#}")),
        })
    }

    #[tool(
        description = "Show each configured store and whether it can be used now (for example, whether the keyring is unlocked and Vault answers).",
        annotations(read_only_hint = true)
    )]
    async fn store_status(&self) -> Result<CallToolResult, ErrorData> {
        let r = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
            let cfg = Config::load()?;
            let stores = Stores::from_config(&cfg);
            let rows: Vec<Value> = stores
                .stores
                .iter()
                .map(|s| match s.status() {
                    Ok(line) => json!({"store": s.name(), "kind": s.kind(), "ok": true, "status": line}),
                    Err(e) => json!({"store": s.name(), "kind": s.kind(), "ok": false, "status": format!("{e:#}")}),
                })
                .collect();
            Ok(json!({ "stores": rows }))
        })
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(match r {
            Ok(v) => json_result(v),
            Err(e) => tool_error(format!("{e:#}")),
        })
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("sealkeep", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

pub fn serve() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let service = Server::new()
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|e| anyhow::anyhow!("start the MCP server: {e}"))?;
        service
            .waiting()
            .await
            .map_err(|e| anyhow::anyhow!("MCP server: {e}"))?;
        Ok(())
    })
}

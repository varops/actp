//! `actp.yaml`, read with the same schema and rules as the Go `internal/config`.
//!
//! Unknown keys and duplicate keys are refused, like Go's strict decoder. The
//! tunnel, dashboard and remotes sections are read and validated so the same
//! file works with both implementations; this crate does not act on the tunnel
//! or dashboard settings.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_norway::Value;

/// The config file format version this build reads.
pub const CURRENT_VERSION: i64 = 1;

/// The whole file.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub version: i64,
    pub server: Option<Server>,
    pub remotes: Vec<Remote>,
    /// Remotes saved by `actp remote`, apart from the hand-edited file.
    pub remotes_file: String,
    pub dashboard: Dashboard,
    path: PathBuf,
}

/// Settings of the local dashboard (read for compatibility, not used here).
#[derive(Clone, Debug, Default)]
pub struct Dashboard {
    pub terminal: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Server {
    pub name: String,
    pub listen: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub insecure_listen: bool,
    pub idle_close: Duration,
    pub prompt_timeout: Duration,
    pub spool_limit: i64,
    pub log_dir: String,
    pub state_dir: String,
    pub shell_env: Option<bool>,
    pub audit: Audit,
    pub tunnel: Tunnel,
    pub workspaces: Vec<Workspace>,
    pub agents: Vec<Agent>,
    pub tokens: Vec<Token>,
    pub tokens_file: String,
}

#[derive(Clone, Debug, Default)]
pub struct Audit {
    pub log_prompts: bool,
}

/// The Cloudflare tunnel of the Go server. Validated, not run.
#[derive(Clone, Debug, Default)]
pub struct Tunnel {
    pub provider: String,
    pub mode: String,
    pub token_env: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Workspace {
    pub name: String,
    pub path: String,
}

#[derive(Clone, Debug, Default)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub description: String,
    pub preset: String,
    pub command: String,
    pub args: Vec<String>,
    /// Whether `args` was written in the file (a preset only fills in missing args).
    pub args_given: bool,
    pub env: BTreeMap<String, String>,
    pub env_remove: Vec<String>,
    pub permissions: String,
    pub max_links: i64,
    pub on_client_exit: String,
    pub max_unattended: Duration,
    /// Top-level `_meta` keys kept in session requests; the rest is dropped.
    pub keep_session_meta: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Token {
    pub name: String,
    pub hash: String,
    pub agents: Vec<String>,
    pub workspaces: Vec<String>,
    pub default_workspace: String,
    pub cwd_fallback: bool,
    pub mcp_servers: String,
    pub permissions: String,
    pub max_links: i64,
    pub map: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct Remote {
    pub name: String,
    pub url: String,
    pub token_env: String,
    pub token_file: String,
    /// The token is in the OS keychain (not supported by this build).
    pub token_keychain: bool,
}

/// A config error with the same text as Go's, where the text is actp's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err(msg: impl Into<String>) -> ConfigError {
    ConfigError(msg.into())
}

/// Known agent launches; built from docs/agents.md like the Go presets.
pub fn preset(name: &str) -> Option<(&'static str, &'static str, &'static [&'static str])> {
    Some(match name {
        "claude-code" => ("Claude Code", "claude-agent-acp", &[]),
        "codex" => ("Codex", "codex-acp", &[]),
        "droid" => ("Droid", "droid", &["exec", "--output-format", "acp"]),
        "gemini" => ("Gemini CLI", "gemini", &["--acp"]),
        "opencode" => ("OpenCode", "opencode", &["acp"]),
        "grok" => ("Grok", "grok", &["agent", "stdio"]),
        "pi" => ("Pi", "pi-acp", &[]),
        "prime-agent" => ("Prime Agent", "prime-agent", &["--mode", "acp"]),
        _ => return None,
    })
}

/// The actp home folder: `~/.actp`, or `%APPDATA%\actp` on Windows.
pub fn dir() -> PathBuf {
    if cfg!(windows)
        && let Some(app) = std::env::var_os("APPDATA").filter(|v| !v.is_empty())
    {
        return PathBuf::from(app).join("actp");
    }
    match home_dir() {
        Some(h) => h.join(".actp"),
        None => PathBuf::from(".actp"),
    }
}

/// The user's home folder, like Go's `os.UserHomeDir`.
pub fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// `~/.actp/actp.yaml`, or `%APPDATA%\actp\actp.yaml` on Windows.
pub fn default_path() -> PathBuf {
    dir().join("actp.yaml")
}

/// Where the dashboard installs agents (an npm prefix).
pub fn agents_prefix() -> PathBuf {
    dir().join("agents")
}

/// The folder with the commands of agents the dashboard installed.
pub fn agent_bin_dir() -> PathBuf {
    if cfg!(windows) {
        agents_prefix()
    } else {
        agents_prefix().join("bin")
    }
}

/// Replaces a leading `~` with the user's home folder.
pub fn expand_home(p: &str) -> String {
    if (p == "~" || p.starts_with("~/") || p.starts_with("~\\"))
        && let Some(home) = home_dir()
    {
        let rest = p[1..].trim_start_matches(['/', '\\']);
        return if rest.is_empty() {
            home.to_string_lossy().into_owned()
        } else {
            home.join(rest).to_string_lossy().into_owned()
        };
    }
    p.to_string()
}

impl Config {
    /// The file the config was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads, defaults and validates a config file. A missing file at the
    /// default path is an empty config, not an error.
    pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
        let explicit = path.is_some();
        let path = path.map(Path::to_path_buf).unwrap_or_else(default_path);
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => {
                let mut cfg = Config {
                    version: CURRENT_VERSION,
                    path,
                    ..Default::default()
                };
                cfg.finish()?;
                cfg.load_remotes_file()?;
                return Ok(cfg);
            }
            Err(e) => return Err(err(format!("open {}: {}", path.display(), e))),
        };
        let mut cfg = Config::parse(&data).map_err(|e| err(format!("{}: {e}", path.display())))?;
        cfg.path = path.clone();
        cfg.load_tokens_file()?;
        cfg.load_remotes_file()?;
        cfg.validate()
            .map_err(|e| err(format!("{}: {e}", path.display())))?;
        Ok(cfg)
    }

    /// Decodes and defaults a config without touching the file system.
    pub fn parse(data: &str) -> Result<Config, ConfigError> {
        let v = parse_yaml(data)?;
        let mut cfg = Config::default();
        let mut d = Decoder::default();
        if let Some(m) = d.mapping(&v, "") {
            for (k, val) in m {
                match k.as_str() {
                    "version" => cfg.version = d.int(val, "version").unwrap_or(cfg.version),
                    "server" => cfg.server = d.server(val),
                    "remotes" => cfg.remotes = d.remotes(val),
                    "remotes_file" => cfg.remotes_file = d.string(val, &k).unwrap_or_default(),
                    "dashboard" => {
                        if let Some(dm) = d.mapping(val, "dashboard") {
                            for (k, val) in dm {
                                match k.as_str() {
                                    "terminal" => {
                                        cfg.dashboard.terminal = d.boolean(val, &k).unwrap_or(false)
                                    }
                                    _ => d.unknown(&k),
                                }
                            }
                        }
                    }
                    _ => d.unknown(&k),
                }
            }
        }
        d.finish()?;
        if cfg.version == 0 {
            cfg.version = CURRENT_VERSION;
        }
        if cfg.version > CURRENT_VERSION {
            return Err(err(format!(
                "config version {} is newer than this actp (supports {CURRENT_VERSION})",
                cfg.version
            )));
        }
        cfg.finish()?;
        Ok(cfg)
    }

    fn finish(&mut self) -> Result<(), ConfigError> {
        if self.remotes_file.is_empty() {
            self.remotes_file = dir().join("remotes.yaml").to_string_lossy().into_owned();
        }
        self.remotes_file = expand_home(&self.remotes_file);
        let Some(s) = self.server.as_mut() else {
            return Ok(());
        };
        if s.listen.is_empty() {
            s.listen = "127.0.0.1:7860".into();
        }
        if s.idle_close.is_zero() {
            s.idle_close = Duration::from_secs(600);
        }
        if s.prompt_timeout.is_zero() {
            s.prompt_timeout = Duration::from_secs(24 * 3600);
        }
        if s.spool_limit == 0 {
            s.spool_limit = 1 << 30;
        }
        if s.log_dir.is_empty() {
            s.log_dir = dir().join("logs").to_string_lossy().into_owned();
        }
        if s.state_dir.is_empty() {
            s.state_dir = dir().join("state").to_string_lossy().into_owned();
        }
        if s.tokens_file.is_empty() {
            s.tokens_file = dir().join("tokens.yaml").to_string_lossy().into_owned();
        }
        if s.tunnel.mode.is_empty() {
            s.tunnel.mode = "off".into();
        }
        s.log_dir = expand_home(&s.log_dir);
        s.state_dir = expand_home(&s.state_dir);
        s.tokens_file = expand_home(&s.tokens_file);
        for w in &mut s.workspaces {
            w.path = expand_home(&w.path);
        }
        for a in &mut s.agents {
            if !a.preset.is_empty() {
                let Some((name, command, args)) = preset(&a.preset) else {
                    return Err(err(format!(
                        "agent {}: unknown preset {}",
                        quote(&a.id),
                        quote(&a.preset)
                    )));
                };
                if a.command.is_empty() {
                    a.command = command.into();
                    if !a.args_given {
                        a.args = args.iter().map(|s| s.to_string()).collect();
                    }
                }
                if a.name.is_empty() {
                    a.name = name.into();
                }
            }
            if a.permissions.is_empty() {
                a.permissions = "forward".into();
            }
            if a.max_links == 0 {
                a.max_links = 16;
            }
            if a.on_client_exit.is_empty() {
                a.on_client_exit = "finish".into();
            }
            if a.max_unattended.is_zero() {
                a.max_unattended = Duration::from_secs(3600);
            }
            if a.name.is_empty() {
                a.name = a.id.clone();
            }
        }
        for t in &mut s.tokens {
            apply_token_defaults(t);
        }
        Ok(())
    }

    fn load_tokens_file(&mut self) -> Result<(), ConfigError> {
        let Some(s) = self.server.as_mut() else {
            return Ok(());
        };
        for mut t in read_tokens_file(Path::new(&s.tokens_file))? {
            apply_token_defaults(&mut t);
            s.tokens.push(t);
        }
        Ok(())
    }

    fn load_remotes_file(&mut self) -> Result<(), ConfigError> {
        let extra = read_remotes_file(Path::new(&self.remotes_file))?;
        self.remotes.extend(extra);
        Ok(())
    }

    /// Checks references and enum values. Messages match the Go server's.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errs: Vec<String> = Vec::new();
        if let Some(s) = &self.server {
            let mut workspaces = std::collections::HashSet::new();
            for w in &s.workspaces {
                if w.name.is_empty() || w.path.is_empty() {
                    errs.push("every workspace needs a name and a path".into());
                    continue;
                }
                if workspaces.contains(&w.name) {
                    errs.push(format!("workspace {} is defined twice", quote(&w.name)));
                }
                if !Path::new(&w.path).is_absolute() {
                    errs.push(format!(
                        "workspace {}: path must be absolute",
                        quote(&w.name)
                    ));
                }
                workspaces.insert(w.name.clone());
            }
            let mut agents = std::collections::HashSet::new();
            for a in &s.agents {
                if !valid_id(&a.id) {
                    errs.push(format!(
                        "agent id {} must match ^[a-z0-9][a-z0-9_-]{{0,63}}$",
                        quote(&a.id)
                    ));
                }
                if agents.contains(&a.id) {
                    errs.push(format!("agent {} is defined twice", quote(&a.id)));
                }
                agents.insert(a.id.clone());
                if a.command.is_empty() {
                    errs.push(format!(
                        "agent {} needs a command or a preset",
                        quote(&a.id)
                    ));
                }
                if !["forward", "auto_allow", "auto_deny"].contains(&a.permissions.as_str()) {
                    errs.push(format!(
                        "agent {}: permissions must be forward, auto_allow or auto_deny",
                        quote(&a.id)
                    ));
                }
                if !["finish", "cancel"].contains(&a.on_client_exit.as_str()) {
                    errs.push(format!(
                        "agent {}: on_client_exit must be finish or cancel",
                        quote(&a.id)
                    ));
                }
            }
            let mut names = std::collections::HashSet::new();
            for t in &s.tokens {
                if t.name.is_empty() {
                    errs.push("every token needs a name".into());
                }
                if names.contains(&t.name) {
                    errs.push(format!("token {} is defined twice", quote(&t.name)));
                }
                names.insert(t.name.clone());
                if !t.hash.starts_with("sha256:") {
                    errs.push(format!(
                        "token {}: hash must start with sha256:",
                        quote(&t.name)
                    ));
                }
                for a in &t.agents {
                    if a != "*" && !agents.contains(a) {
                        errs.push(format!(
                            "token {}: unknown agent {}",
                            quote(&t.name),
                            quote(a)
                        ));
                    }
                }
                for w in &t.workspaces {
                    if w != "*" && !workspaces.contains(w) {
                        errs.push(format!(
                            "token {}: unknown workspace {}",
                            quote(&t.name),
                            quote(w)
                        ));
                    }
                }
                if !t.default_workspace.is_empty() && !workspaces.contains(&t.default_workspace) {
                    errs.push(format!(
                        "token {}: unknown default_workspace {}",
                        quote(&t.name),
                        quote(&t.default_workspace)
                    ));
                }
                for (from, to) in &t.map {
                    if !workspaces.contains(to) {
                        errs.push(format!(
                            "token {}: map {} points to unknown workspace {}",
                            quote(&t.name),
                            quote(from),
                            quote(to)
                        ));
                    }
                }
                if !["none", "remote", "all"].contains(&t.mcp_servers.as_str()) {
                    errs.push(format!(
                        "token {}: mcp_servers must be none, remote or all",
                        quote(&t.name)
                    ));
                }
                if !t.permissions.is_empty()
                    && !["forward", "auto_allow", "auto_deny"].contains(&t.permissions.as_str())
                {
                    errs.push(format!(
                        "token {}: permissions must be forward, auto_allow or auto_deny",
                        quote(&t.name)
                    ));
                }
            }
            if !["off", "quick", "named"].contains(&s.tunnel.mode.as_str()) {
                errs.push("tunnel mode must be off, quick or named".into());
            }
            if s.tunnel.mode == "named" && s.tunnel.token_env.is_empty() {
                errs.push("a named tunnel needs token_env: the variable holding the Cloudflare tunnel token".into());
            }
            if s.tls_cert.is_empty() != s.tls_key.is_empty() {
                errs.push("tls_cert and tls_key must be set together".into());
            }
        }
        let mut remotes = std::collections::HashSet::new();
        for r in &self.remotes {
            if r.name.is_empty() || r.url.is_empty() {
                errs.push("every remote needs a name and a url".into());
            }
            if remotes.contains(&r.name) {
                errs.push(format!("remote {} is defined twice", quote(&r.name)));
            }
            remotes.insert(r.name.clone());
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(err(errs.join("\n")))
        }
    }

    /// The saved remote with this name.
    pub fn remote(&self, name: &str) -> Option<&Remote> {
        self.remotes.iter().find(|r| r.name == name)
    }

    /// Builds a config in code (for tests and embedders).
    pub fn with_server(server: Server) -> Config {
        let mut c = Config {
            version: CURRENT_VERSION,
            server: Some(server),
            ..Default::default()
        };
        let _ = c.finish();
        c
    }
}

fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Fills in default values for a token entry.
pub fn apply_token_defaults(t: &mut Token) {
    if t.mcp_servers.is_empty() {
        t.mcp_servers = "remote".into();
    }
    if t.max_links == 0 {
        t.max_links = 8;
    }
}

impl Server {
    /// The agent with this id.
    pub fn agent(&self, id: &str) -> Option<&Agent> {
        self.agents.iter().find(|a| a.id == id)
    }

    /// The workspace with this name.
    pub fn workspace(&self, name: &str) -> Option<&Workspace> {
        self.workspaces.iter().find(|w| w.name == name)
    }
}

impl Token {
    /// Whether the token may use the agent.
    pub fn allows_agent(&self, id: &str) -> bool {
        self.agents.iter().any(|a| a == id || a == "*")
    }

    /// The workspace names the token may use.
    pub fn allowed_workspaces(&self, s: &Server) -> Vec<String> {
        if self.workspaces.iter().any(|w| w == "*") {
            return s.workspaces.iter().map(|w| w.name.clone()).collect();
        }
        self.workspaces.clone()
    }

    /// The token override, else the agent setting.
    pub fn effective_permissions(&self, a: &Agent) -> String {
        if self.permissions.is_empty() {
            a.permissions.clone()
        } else {
            self.permissions.clone()
        }
    }
}

/// Reads a tokens file (`tokens: [...]`). A missing file is empty.
pub fn read_tokens_file(path: &Path) -> Result<Vec<Token>, ConfigError> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(err(format!("open {}: {e}", path.display()))),
    };
    let v = parse_yaml(&data).map_err(|e| err(format!("{}: {e}", path.display())))?;
    let mut d = Decoder::default();
    let mut out = Vec::new();
    if let Some(m) = d.mapping(&v, "") {
        for (k, val) in m {
            match k.as_str() {
                "tokens" => out = d.tokens(val),
                _ => d.unknown(&k),
            }
        }
    }
    d.finish()
        .map_err(|e| err(format!("{}: {e}", path.display())))?;
    Ok(out)
}

/// Reads a remotes file (`remotes: [...]`). A missing file is empty.
pub fn read_remotes_file(path: &Path) -> Result<Vec<Remote>, ConfigError> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(err(format!("open {}: {e}", path.display()))),
    };
    let v = parse_yaml(&data).map_err(|e| err(format!("{}: {e}", path.display())))?;
    let mut d = Decoder::default();
    let mut out = Vec::new();
    if let Some(m) = d.mapping(&v, "") {
        for (k, val) in m {
            match k.as_str() {
                "remotes" => out = d.remotes(val),
                _ => d.unknown(&k),
            }
        }
    }
    d.finish()
        .map_err(|e| err(format!("{}: {e}", path.display())))?;
    for r in &mut out {
        r.token_file = expand_home(&r.token_file);
    }
    Ok(out)
}

/// The SHA-256 form tokens are stored in.
pub fn hash_token(token: &str) -> String {
    use sha2::Digest;
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(token.as_bytes()))
    )
}

fn parse_yaml(data: &str) -> Result<Value, ConfigError> {
    if data.trim().is_empty() {
        return Ok(Value::Null);
    }
    let mut v: Value = serde_norway::from_str(data).map_err(|e| err(e.to_string()))?;
    v.apply_merge().map_err(|e| err(e.to_string()))?;
    Ok(v)
}

/// Decodes YAML values into Go-shaped fields, with goccy/go-yaml's
/// conversions: scalars become strings, quoted numbers become ints, only real
/// booleans are booleans, `null` leaves a field empty.
#[derive(Default)]
struct Decoder {
    errs: Vec<String>,
}

fn untag(v: &Value) -> &Value {
    match v {
        Value::Tagged(t) => untag(&t.value),
        v => v,
    }
}

fn key_string(k: &Value) -> String {
    match untag(k) {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => number_string(n),
        Value::Null => String::new(),
        _ => format!("{k:?}"),
    }
}

fn number_string(n: &serde_norway::Number) -> String {
    if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(u) = n.as_u64() {
        u.to_string()
    } else {
        let f = n.as_f64().unwrap_or(0.0);
        if f.is_infinite() {
            if f > 0.0 {
                "+Inf".into()
            } else {
                "-Inf".into()
            }
        } else if f.is_nan() {
            "NaN".into()
        } else if f.fract() == 0.0 && f.abs() < 1e21 {
            format!("{f:.0}")
        } else {
            actp_proto::gojson::format_float(f)
        }
    }
}

impl Decoder {
    fn finish(self) -> Result<(), ConfigError> {
        match self.errs.into_iter().next() {
            Some(e) => Err(err(e)),
            None => Ok(()),
        }
    }

    fn unknown(&mut self, key: &str) {
        self.errs.push(format!("unknown field {}", quote(key)));
    }

    fn mapping<'a>(&mut self, v: &'a Value, what: &str) -> Option<Vec<(String, &'a Value)>> {
        match untag(v) {
            Value::Null => None,
            Value::Mapping(m) => Some(m.iter().map(|(k, v)| (key_string(k), v)).collect()),
            _ => {
                self.errs.push(format!("{what}: a mapping is expected"));
                None
            }
        }
    }

    fn sequence<'a>(&mut self, v: &'a Value, what: &str) -> Option<&'a Vec<Value>> {
        match untag(v) {
            Value::Null => None,
            Value::Sequence(s) => Some(s),
            _ => {
                self.errs.push(format!("{what}: a sequence is expected"));
                None
            }
        }
    }

    fn string(&mut self, v: &Value, what: &str) -> Option<String> {
        match untag(v) {
            Value::Null => None,
            Value::String(s) => Some(s.clone()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Number(n) => Some(number_string(n)),
            _ => {
                self.errs.push(format!(
                    "{what}: cannot unmarshal a collection into a string"
                ));
                None
            }
        }
    }

    fn int(&mut self, v: &Value, what: &str) -> Option<i64> {
        match untag(v) {
            Value::Null => None,
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Some(i)
                } else if let Some(f) = n.as_f64().filter(|f| f.is_finite()) {
                    Some(f.trunc() as i64)
                } else {
                    self.errs.push(format!("{what}: number out of range"));
                    None
                }
            }
            Value::String(s) => match s.parse::<i64>() {
                Ok(i) => Some(i),
                Err(_) => {
                    self.errs
                        .push(format!("{what}: cannot unmarshal string into an int"));
                    None
                }
            },
            _ => {
                self.errs
                    .push(format!("{what}: cannot unmarshal into an int"));
                None
            }
        }
    }

    fn boolean(&mut self, v: &Value, what: &str) -> Option<bool> {
        match untag(v) {
            Value::Null => None,
            Value::Bool(b) => Some(*b),
            _ => {
                self.errs
                    .push(format!("{what}: cannot unmarshal into a bool"));
                None
            }
        }
    }

    fn strings(&mut self, v: &Value, what: &str) -> Vec<String> {
        let Some(seq) = self.sequence(v, what) else {
            return Vec::new();
        };
        seq.iter()
            .map(|it| self.string(it, what).unwrap_or_default())
            .collect()
    }

    fn string_map(&mut self, v: &Value, what: &str) -> BTreeMap<String, String> {
        let Some(m) = self.mapping(v, what) else {
            return BTreeMap::new();
        };
        m.into_iter()
            .map(|(k, v)| (k, self.string(v, what).unwrap_or_default()))
            .collect()
    }

    fn duration(&mut self, v: &Value, what: &str) -> Option<Duration> {
        let s = self.string(v, what)?;
        match parse_go_duration(&s) {
            Some(d) if d < 0 => {
                self.errs
                    .push(format!("duration {} must not be negative", quote(&s)));
                None
            }
            Some(d) => Some(Duration::from_nanos(d as u64)),
            None => {
                self.errs.push(format!("invalid duration {}", quote(&s)));
                None
            }
        }
    }

    fn byte_size(&mut self, v: &Value, what: &str) -> Option<i64> {
        let s = self.string(v, what)?;
        match parse_byte_size(&s) {
            Ok(n) => Some(n),
            Err(e) => {
                self.errs.push(e.0);
                None
            }
        }
    }

    fn server(&mut self, v: &Value) -> Option<Server> {
        let m = self.mapping(v, "server")?;
        let mut s = Server::default();
        for (k, v) in m {
            match k.as_str() {
                "name" => s.name = self.string(v, &k).unwrap_or_default(),
                "listen" => s.listen = self.string(v, &k).unwrap_or_default(),
                "tls_cert" => s.tls_cert = self.string(v, &k).unwrap_or_default(),
                "tls_key" => s.tls_key = self.string(v, &k).unwrap_or_default(),
                "insecure_listen" => s.insecure_listen = self.boolean(v, &k).unwrap_or(false),
                "idle_close" => s.idle_close = self.duration(v, &k).unwrap_or_default(),
                "prompt_timeout" => s.prompt_timeout = self.duration(v, &k).unwrap_or_default(),
                "spool_limit" => s.spool_limit = self.byte_size(v, &k).unwrap_or(0),
                "log_dir" => s.log_dir = self.string(v, &k).unwrap_or_default(),
                "state_dir" => s.state_dir = self.string(v, &k).unwrap_or_default(),
                "shell_env" => s.shell_env = self.boolean(v, &k),
                "tokens_file" => s.tokens_file = self.string(v, &k).unwrap_or_default(),
                "audit" => {
                    if let Some(am) = self.mapping(v, "audit") {
                        for (k, v) in am {
                            match k.as_str() {
                                "log_prompts" => {
                                    s.audit.log_prompts = self.boolean(v, &k).unwrap_or(false)
                                }
                                _ => self.unknown(&k),
                            }
                        }
                    }
                }
                "tunnel" => {
                    if let Some(tm) = self.mapping(v, "tunnel") {
                        for (k, v) in tm {
                            match k.as_str() {
                                "provider" => {
                                    s.tunnel.provider = self.string(v, &k).unwrap_or_default()
                                }
                                "token_env" => {
                                    s.tunnel.token_env = self.string(v, &k).unwrap_or_default()
                                }
                                // `off` may arrive as a boolean false; true is never valid.
                                "mode" => match untag(v) {
                                    Value::Bool(false) => s.tunnel.mode = "off".into(),
                                    Value::Bool(true) => self
                                        .errs
                                        .push("tunnel mode must be off, quick or named".into()),
                                    other => {
                                        s.tunnel.mode = self.string(other, &k).unwrap_or_default()
                                    }
                                },
                                _ => self.unknown(&k),
                            }
                        }
                    }
                }
                "workspaces" => {
                    if let Some(seq) = self.sequence(v, "workspaces") {
                        for it in seq {
                            let mut w = Workspace::default();
                            if let Some(wm) = self.mapping(it, "workspace") {
                                for (k, v) in wm {
                                    match k.as_str() {
                                        "name" => w.name = self.string(v, &k).unwrap_or_default(),
                                        "path" => w.path = self.string(v, &k).unwrap_or_default(),
                                        _ => self.unknown(&k),
                                    }
                                }
                            }
                            s.workspaces.push(w);
                        }
                    }
                }
                "agents" => {
                    if let Some(seq) = self.sequence(v, "agents") {
                        for it in seq {
                            s.agents.push(self.agent(it));
                        }
                    }
                }
                "tokens" => s.tokens = self.tokens(v),
                _ => self.unknown(&k),
            }
        }
        Some(s)
    }

    fn agent(&mut self, v: &Value) -> Agent {
        let mut a = Agent::default();
        let Some(m) = self.mapping(v, "agent") else {
            return a;
        };
        for (k, v) in m {
            match k.as_str() {
                "id" => a.id = self.string(v, &k).unwrap_or_default(),
                "name" => a.name = self.string(v, &k).unwrap_or_default(),
                "description" => a.description = self.string(v, &k).unwrap_or_default(),
                "preset" => a.preset = self.string(v, &k).unwrap_or_default(),
                "command" => a.command = self.string(v, &k).unwrap_or_default(),
                "args" => {
                    a.args_given = !matches!(untag(v), Value::Null);
                    a.args = self.strings(v, &k);
                }
                "env" => a.env = self.string_map(v, &k),
                "env_remove" => a.env_remove = self.strings(v, &k),
                "permissions" => a.permissions = self.string(v, &k).unwrap_or_default(),
                "max_links" => a.max_links = self.int(v, &k).unwrap_or(0),
                "on_client_exit" => a.on_client_exit = self.string(v, &k).unwrap_or_default(),
                "max_unattended" => a.max_unattended = self.duration(v, &k).unwrap_or_default(),
                "keep_session_meta" => a.keep_session_meta = self.strings(v, &k),
                _ => self.unknown(&k),
            }
        }
        a
    }

    fn tokens(&mut self, v: &Value) -> Vec<Token> {
        let mut out = Vec::new();
        let Some(seq) = self.sequence(v, "tokens") else {
            return out;
        };
        for it in seq {
            let mut t = Token::default();
            if let Some(m) = self.mapping(it, "token") {
                for (k, v) in m {
                    match k.as_str() {
                        "name" => t.name = self.string(v, &k).unwrap_or_default(),
                        "hash" => t.hash = self.string(v, &k).unwrap_or_default(),
                        "agents" => t.agents = self.strings(v, &k),
                        "workspaces" => t.workspaces = self.strings(v, &k),
                        "default_workspace" => {
                            t.default_workspace = self.string(v, &k).unwrap_or_default()
                        }
                        "cwd_fallback" => t.cwd_fallback = self.boolean(v, &k).unwrap_or(false),
                        "mcp_servers" => t.mcp_servers = self.string(v, &k).unwrap_or_default(),
                        "permissions" => t.permissions = self.string(v, &k).unwrap_or_default(),
                        "max_links" => t.max_links = self.int(v, &k).unwrap_or(0),
                        "map" => t.map = self.string_map(v, &k),
                        _ => self.unknown(&k),
                    }
                }
            }
            out.push(t);
        }
        out
    }

    fn remotes(&mut self, v: &Value) -> Vec<Remote> {
        let mut out = Vec::new();
        let Some(seq) = self.sequence(v, "remotes") else {
            return out;
        };
        for it in seq {
            let mut r = Remote::default();
            if let Some(m) = self.mapping(it, "remote") {
                for (k, v) in m {
                    match k.as_str() {
                        "name" => r.name = self.string(v, &k).unwrap_or_default(),
                        "url" => r.url = self.string(v, &k).unwrap_or_default(),
                        "token_env" => r.token_env = self.string(v, &k).unwrap_or_default(),
                        "token_file" => r.token_file = self.string(v, &k).unwrap_or_default(),
                        "token_keychain" => r.token_keychain = self.boolean(v, &k).unwrap_or(false),
                        _ => self.unknown(&k),
                    }
                }
            }
            out.push(r);
        }
        out
    }
}

/// Go's `strconv.Quote` for the plain strings config errors show.
pub fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Reads sizes such as "512", "8KB", "8MB" or "1GB" (powers of 1024).
pub fn parse_byte_size(s: &str) -> Result<i64, ConfigError> {
    let mut t = s.trim().to_uppercase();
    let mut mult: i64 = 1;
    for (suffix, m) in [
        ("GB", 1i64 << 30),
        ("MB", 1 << 20),
        ("KB", 1 << 10),
        ("B", 1),
    ] {
        if let Some(rest) = t.strip_suffix(suffix) {
            mult = m;
            t = rest.trim().to_string();
            break;
        }
    }
    match go_parse_int(&t) {
        Some(n) if n >= 0 => Ok(n.wrapping_mul(mult)),
        _ => Err(err(format!("invalid size {}", quote(s)))),
    }
}

/// `strconv.ParseInt(s, 10, 64)`: an optional sign and decimal digits.
fn go_parse_int(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

/// Go's `time.ParseDuration`, in nanoseconds.
pub fn parse_go_duration(orig: &str) -> Option<i64> {
    let mut s = orig.as_bytes();
    let mut neg = false;
    if let Some(&c) = s.first()
        && (c == b'-' || c == b'+')
    {
        neg = c == b'-';
        s = &s[1..];
    }
    if s == b"0" {
        return Some(0);
    }
    if s.is_empty() {
        return None;
    }
    const LIMIT: u64 = 1 << 63;
    let mut d: u64 = 0;
    while !s.is_empty() {
        if !(s[0] == b'.' || s[0].is_ascii_digit()) {
            return None;
        }
        // leading int
        let mut i = 0;
        let mut v: u64 = 0;
        while i < s.len() && s[i].is_ascii_digit() {
            if v > LIMIT / 10 {
                return None;
            }
            v = v * 10 + (s[i] - b'0') as u64;
            if v > LIMIT {
                return None;
            }
            i += 1;
        }
        let pre = i > 0;
        s = &s[i..];
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0;
        let mut post = false;
        if s.first() == Some(&b'.') {
            s = &s[1..];
            let mut i = 0;
            let mut overflow = false;
            while i < s.len() && s[i].is_ascii_digit() {
                if !overflow {
                    if f > (LIMIT - 1) / 10 {
                        overflow = true;
                    } else {
                        let y = f * 10 + (s[i] - b'0') as u64;
                        if y > LIMIT {
                            overflow = true;
                        } else {
                            f = y;
                            scale *= 10.0;
                        }
                    }
                }
                i += 1;
            }
            post = i > 0;
            s = &s[i..];
        }
        if !pre && !post {
            return None;
        }
        let mut i = 0;
        while i < s.len() && !(s[i] == b'.' || s[i].is_ascii_digit()) {
            i += 1;
        }
        if i == 0 {
            return None;
        }
        let unit: u64 = match std::str::from_utf8(&s[..i]).ok()? {
            "ns" => 1,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return None,
        };
        s = &s[i..];
        if v > LIMIT / unit {
            return None;
        }
        v *= unit;
        if f > 0 {
            v += (f as f64 * (unit as f64 / scale)) as u64;
            if v > LIMIT {
                return None;
            }
        }
        d += v;
        if d > LIMIT {
            return None;
        }
    }
    if neg {
        return Some((d as i64).wrapping_neg());
    }
    if d > LIMIT - 1 {
        return None;
    }
    Some(d as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
version: 1
server:
  name: workstation
  idle_close: 5m
  spool_limit: 8MB
  tunnel:
    mode: off
  workspaces:
    - name: website
      path: WORKSPACE
  agents:
    - id: claude
      preset: claude-code
    - id: mine
      command: my-agent
      args: [--acp]
  tokens:
    - name: bot
      hash: "sha256:abc"
      agents: [claude]
      workspaces: [website]
      default_workspace: website
remotes:
  - name: workstation
    url: https://agents.example.com
"#;

    fn sample() -> String {
        SAMPLE.replace(
            "WORKSPACE",
            &format!("{:?}", std::env::temp_dir().to_string_lossy()),
        )
    }

    #[test]
    fn parse_applies_defaults_and_presets() {
        let cfg = Config::parse(&sample()).unwrap();
        cfg.validate().unwrap();
        let s = cfg.server.as_ref().unwrap();
        assert_eq!(s.listen, "127.0.0.1:7860");
        assert_eq!(s.idle_close, Duration::from_secs(300));
        assert_eq!(s.prompt_timeout, Duration::from_secs(86400));
        assert_eq!(s.spool_limit, 8 << 20);
        assert_eq!(s.tunnel.mode, "off");
        let claude = s.agent("claude").unwrap();
        assert_eq!(
            (
                claude.command.as_str(),
                claude.name.as_str(),
                claude.max_links,
                claude.on_client_exit.as_str()
            ),
            ("claude-agent-acp", "Claude Code", 16, "finish")
        );
        let tok = &s.tokens[0];
        assert_eq!(tok.mcp_servers, "remote");
        assert!(tok.allows_agent("claude") && !tok.allows_agent("mine"));
        assert!(cfg.remote("workstation").is_some());
    }

    #[test]
    fn validate_catches_bad_references() {
        let bad = sample()
            .replace("agents: [claude]", "agents: [nope]")
            .replace("default_workspace: website", "default_workspace: other");
        let e = Config::parse(&bad).unwrap().validate().unwrap_err().0;
        assert!(
            e.contains(r#"unknown agent "nope""#)
                && e.contains(r#"unknown default_workspace "other""#),
            "{e}"
        );
    }

    #[test]
    fn strict_like_go() {
        // Each case and whether the Go server accepts it (from goccy/go-yaml).
        let cases: &[(&str, bool)] = &[
            ("server:\n  lisen: x\n", false),
            ("foo: 1\n", false),
            ("server:\n  Name: x\n", false),
            ("server:\n  dashboard: {}\n", false),
            ("dashboard:\n  terminal: true\n  other: 1\n", false),
            ("server:\n  name: a\n  name: b\n", false),
            (
                "server:\n  agents:\n    - id: a\n      command: x\n      env:\n        A: 1\n        A: 2\n",
                false,
            ),
            ("version: 2\n", false),
            ("version: \"1\"\n", true),
            ("server:\n  idle_close: 10\n", false),
            ("server:\n  idle_close: -1s\n", false),
            (
                "server:\n  idle_close: 1.5h\n  prompt_timeout: 1h30m\n",
                true,
            ),
            ("server:\n  spool_limit: 1.5GB\n", false),
            ("server:\n  spool_limit: -1\n", false),
            ("server:\n  spool_limit: 1024\n", true),
            ("server:\n  insecure_listen: \"true\"\n", false),
            ("server:\n  insecure_listen: yes\n", false),
            ("server:\n  insecure_listen: True\n", true),
            ("server:\n  insecure_listen: 1\n", false),
            ("server:\n  tunnel:\n    mode: off\n", true),
            ("server:\n  tunnel:\n    mode: \"off\"\n", true),
            ("server:\n  tunnel:\n    mode: false\n", true),
            ("server:\n  tunnel:\n    mode: true\n", false),
            ("server:\n  tunnel:\n    mode: Off\n", false),
            ("server:\n  tunnel:\n    mode: named\n", false),
            ("server:\n  name: [a]\n", false),
            ("server: []\n", false),
            ("server:\n", true),
            ("server: null\n", true),
            (
                "server:\n  agents:\n    - id: a\n      command: x\n      max_links: \"5\"\n",
                true,
            ),
            (
                "server:\n  agents:\n    - id: a\n      command: x\n      max_links: true\n",
                false,
            ),
            (
                "server:\n  agents:\n    - id: a\n      command: x\n      max_links: \" 7\"\n",
                false,
            ),
            (
                "server:\n  agents:\n    - id: a\n      command: x\n      args: x\n",
                false,
            ),
            (
                "server:\n  agents:\n    - id: a\n      command: x\n      args: [1, true, 2.5]\n      env: {A: 1, B: true}\n",
                true,
            ),
            (
                "server:\n  agents:\n    - {id: a, command: x}\n    - {id: a, command: y}\n",
                false,
            ),
            ("server:\n  agents:\n    - id: A\n      command: x\n", false),
            (
                "server:\n  agents:\n    - id: a\n      preset: nope\n",
                false,
            ),
            (
                "remotes:\n  - name: r\n    url: u\n    token_keychain: true\n",
                true,
            ),
            ("remotes:\n  - name: r\n", false),
        ];
        for (yaml, ok) in cases {
            let got = Config::parse(yaml).and_then(|c| c.validate());
            assert_eq!(got.is_ok(), *ok, "{yaml:?}: {got:?}");
        }
    }

    #[test]
    fn conversions_like_go() {
        let c = Config::parse("server:\n  name: 123\n  agents:\n    - id: a\n      command: x\n      args: [1, true, 2.5, null]\n      max_links: 1.5\n      env: {A: null}\n").unwrap();
        let s = c.server.unwrap();
        assert_eq!(s.name, "123");
        assert_eq!(s.agents[0].args, ["1", "true", "2.5", ""]);
        assert_eq!(s.agents[0].max_links, 1);
        assert_eq!(s.agents[0].env["A"], "");
        let c = Config::parse("server:\n  shell_env: false\n  idle_close: 0s\n").unwrap();
        assert_eq!(
            c.server.as_ref().unwrap().idle_close,
            Duration::from_secs(600)
        );
        assert_eq!(c.server.as_ref().unwrap().shell_env, Some(false));
    }

    #[test]
    fn durations_like_go() {
        for (s, want) in [
            ("10m", Some(600_000_000_000i64)),
            ("1.5h", Some(5_400_000_000_000)),
            ("1h30m", Some(5_400_000_000_000)),
            ("300ms", Some(300_000_000)),
            ("0", Some(0)),
            ("-1s", Some(-1_000_000_000)),
            ("10", None),
            ("", None),
            ("1x", None),
            (".5s", Some(500_000_000)),
            ("1.s", Some(1_000_000_000)),
            ("2\u{b5}s", Some(2000)),
        ] {
            assert_eq!(parse_go_duration(s), want, "{s}");
        }
    }

    #[test]
    fn byte_sizes() {
        for (s, n) in [
            ("512", 512),
            ("8KB", 8 << 10),
            ("8MB", 8 << 20),
            ("1GB", 1 << 30),
            (" 2 mb ", 2 << 20),
        ] {
            assert_eq!(parse_byte_size(s).unwrap(), n, "{s}");
        }
        assert!(parse_byte_size("lots").is_err());
    }

    #[test]
    fn tokens_hash_like_go() {
        assert_eq!(
            hash_token("actp_testtoken"),
            format!(
                "sha256:{}",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"actp_testtoken"))
            )
        );
    }
}

# actp in Docker

The Docker image runs an actp server on any machine with Docker: a VPS, a home server, a spare PC. It has actp, Node.js, Git and `cloudflared`. It has **no agents**: you pick them, and actp installs them on first start or from the dashboard. Each agent keeps its own license and login.

## Quick start

Create a client token on any machine with actp (or skip this and create one in the dashboard later):

```bash
actp token generate
```

Start the container:

```bash
docker run -d --name actp --restart unless-stopped \
  -e ACTP_AGENTS=claude-code,codex \
  -e ACTP_TOKEN=actp_… \
  -e ANTHROPIC_API_KEY=… -e OPENAI_API_KEY=… \
  -v actp-data:/data -v "$PWD/code:/workspaces" \
  -p 127.0.0.1:7861:7861 \
  ghcr.io/varops/actp:latest
```

Find the tunnel URL and the dashboard password in the log:

```bash
docker logs actp
```

On the client machine:

```bash
echo 'actp_…' | actp remote add vps https://….trycloudflare.com --token-stdin
```

```bash
actp claude@vps -p "What is in this folder?"
```

There is also a Compose file in [`packaging/docker/compose.yaml`](../packaging/docker/compose.yaml).

## What the container does

On every start, `actp container`:

1. Writes `/data/.actp/actp.yaml` if it is missing.
2. Adds every subfolder of `/workspaces` as a folder agents may use (`actp://<name>`). With no subfolders, agents work in `/data/workspace`.
3. Installs the agents in `ACTP_AGENTS` that are not installed yet, and turns them on.
4. Accepts the token in `ACTP_TOKEN` as the client `env`.
5. Starts the server, a quick Cloudflare tunnel and the dashboard.

Everything that should last lives in the `/data` volume: the config, client tokens, installed agents and their logins (`/data/.claude`, `/data/.codex`, …). Keep the volume and you can replace the image without losing anything.

## Settings

| Variable | Default | What it does |
| --- | --- | --- |
| `ACTP_AGENTS` | – | Agents to install and turn on: `claude-code`, `codex`, `droid`, `gemini`, `opencode`, `pi`. |
| `ACTP_TOKEN` | – | A client token to accept. Make one with `actp token generate`. |
| `ACTP_ADMIN_PASSWORD` | generated | The dashboard password. If empty, actp makes one, prints it once and saves it in `/data/.actp/admin-password`. |
| `ACTP_TUNNEL` | `quick` | `quick` (no account, the URL changes on restart), `named` or `off`. |
| `ACTP_TUNNEL_TOKEN` | – | The Cloudflare tunnel token, for `ACTP_TUNNEL=named`. |
| `ACTP_NAME` | hostname | The server's name. |
| `ACTP_WORKSPACES` | `/workspaces` | The folder whose subfolders agents may use. |
| `ACTP_LISTEN` | `0.0.0.0:7860` | The server's address inside the container. |
| `ACTP_DASHBOARD` | `0.0.0.0:7861` | The dashboard's address, or `off`. |
| `ACTP_TERMINAL` | `on` | `off` removes the terminal from the dashboard. |
| `PUID`, `PGID` | `1000` | The user and group actp and the agents run as. Set them to the owner of your mounted folders. `PUID=0` runs as root. |

Agents get every other variable as it is, so API keys such as `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` or `FACTORY_API_KEY` just work. They do not get the `ACTP_*` variables.

## The dashboard

The dashboard listens on port 7861 and asks for the admin password. On top of the usual pages it has:

- **Install agents**: install, update or remove an agent with one click. actp runs npm and shows its output, then turns the agent on (or off) for clients. Update installs the latest version.
- **Terminal**: a shell in the container, as the user the agents run as. Use it to log agents in, for example `claude /login`, or to clone a repository into `/workspaces`.

The dashboard is plain HTTP and is never reachable through the tunnel. Keep port 7861 private:

- On a server, publish it only on loopback (`-p 127.0.0.1:7861:7861`) and open it through SSH: `ssh -L 7861:localhost:7861 your-server`, then go to `http://localhost:7861`.
- Or put it behind your own HTTPS proxy. actp marks the login cookie `Secure` when the proxy sends `X-Forwarded-Proto: https`.

## Without the tunnel

Set `ACTP_TUNNEL=off` and publish port 7860 behind your own HTTPS reverse proxy. The server speaks plain HTTP inside the container and expects the proxy to add TLS.

## Security

- **A client token is close to a shell in the container.** The same goes for the dashboard password, which also opens the terminal. Use a long password and keep tokens to clients you trust.
- Agents can read and change everything in `/data` and `/workspaces`. Mount only what they need.
- The container runs as a normal user, not root, unless you set `PUID=0`.

## Build it yourself

```bash
docker build -t actp .
```

The image installs the same pinned `cloudflared` as `actp tunnel install`, checked against the SHA-256 built into actp.

# OpenSCM — Open Security Compliance Manager

![License](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue)
![Client License](https://img.shields.io/badge/client-Apache%202.0-green)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20Windows%20|%20macOS%20|%20FreeBSD-lightgrey)
![Architectures](https://img.shields.io/badge/arch-x86__64%20|%20ARM%20|%20RISC--V-blue)

OpenSCM is a centralized, open-source platform designed to help organizations audit, manage, and report on IT security compliance — across every system in your infrastructure.

Unlike traditional compliance tools that collect and centralize sensitive system data, OpenSCM uses a **privacy-first architecture** where raw data never leaves your systems. Agents execute tests locally and only report `PASS`, `FAIL`, or `NA` — your configuration files, user data, and system details stay on your machines.

From legacy servers to modern ARM-based devices, OpenSCM provides a unified interface to define security policies, deploy compliance tests across diverse architectures, and visualize your real-time security posture — all powered by a high-performance Rust backend.

---

## ⚡ Quick Start

**Option 1 — Docker (fastest)**
```bash
docker run -d \
  --name openscm \
  -p 8000:8000 \
  -v openscm_data:/var/lib/openscm \
  -v openscm_keys:/etc/openscm/keys \
  openscm/scmserver:latest
```

**Option 2 — Docker Compose**
```bash
curl -O https://raw.githubusercontent.com/openscm/scmserver/main/docker-compose.yml
docker compose up -d
```

**Option 3 — Native Package (Linux)**
```bash
# Ubuntu / Debian
sudo apt install scmserver

# RedHat / CentOS
sudo yum install scmserver
```

Access the dashboard at **http://localhost:8000**
Default credentials: `admin` / `admin` — **change immediately after first login.**

**Install the agent on your servers:**
```bash
# Linux x86_64
wget https://github.com/openscm/scmclient/releases/latest/download/scmclient-linux-x86_64
chmod +x scmclient-linux-x86_64
./scmclient-linux-x86_64 --url http://your-server:8000
```

---

## 🚀 Key Features

- **Privacy-First Architecture:** Raw system data never leaves the client. Only `PASS`, `FAIL`, or `NA` is reported back to the server.
- **Mutual Ed25519 Signing:** Every payload exchanged between agent and server is cryptographically signed in both directions — ensuring authenticity and preventing tampering.
- **Universal Platform Support:** Native support for Linux, Windows, FreeBSD, and macOS across **x86, ARM, and RISC-V** architectures.
- **UI-Driven Policy Builder:** Define compliance tests visually — no YAML, no XML, no scripting required.
- **Automated Inventory:** Automatically discover system metadata including hostname, IP, OS version, and hardware architecture.
- **Flexible Compliance Engine:** Build multi-condition tests with AND/ALL or OR/ANY logic and deploy them to thousands of endpoints.
- **Evidence-Grade Reporting:** Generate and archive compliance reports as formal audit evidence — downloadable as PDF.
- **Scheduled Scanning:** Automate compliance scans on daily, weekly, or monthly schedules.
- **Real-Time Dashboard:** Interactive compliance visualization with trend graphs and risk rankings.
- **Role-Based Access Control:** Four-tier permission model — Administrator, Editor, Runner, Viewer.
- **Lightweight Rust Agent:** High-performance, low-footprint agent with a minimal attack surface.
- **Single Binary Deployment:** Server ships as a single binary with all assets embedded — no web server, no asset pipeline required.

---

## 🛠 Tech Stack

### Server
| Component | Technology |
| :--- | :--- |
| Language | Rust |
| Web Framework | Axum |
| Database | SQLite (via sqlx) |
| Templating | Tera |
| PDF Generation | genpdf |
| Cryptography | ed25519-dalek |

### Agent (Client)
| Component | Technology |
| :--- | :--- |
| Language | Rust |
| HTTP Client | reqwest |
| Cryptography | ed25519-dalek |
| Config | TOML (Linux/macOS/FreeBSD) / Registry (Windows) |

### Frontend
| Component | Technology |
| :--- | :--- |
| UI Framework | AdminLTE / Bootstrap 4 |
| Charts | Chart.js |
| Tables | DataTables |
| Forms | Select2, Bootstrap Duallistbox |

---

## ⚖️ Licensing

OpenSCM uses a dual-license structure to balance open collaboration with sustainable development:

| Component | License |
| :--- | :--- |
| **Server & Dashboard** | [Functional Source License 1.1 (FSL-1.1-ALv2)](LICENSE-FSL) — converts to Apache 2.0 after 2 years |
| **Client Agent** | [Apache License 2.0](LICENSE-APACHE) — no restrictions for production use |

The client agent is Apache 2.0 to ensure zero friction for installation on production servers, including in corporate environments with strict software policies.

---

## 🔧 Installation

### 🐳 Docker

```bash
docker run -d \
  --name openscm \
  -p 8000:8000 \
  -v openscm_data:/var/lib/openscm \
  -v openscm_keys:/etc/openscm/keys \
  openscm/scmserver:latest
```

> **Important:** The `openscm_keys` volume contains your server's Ed25519 keypair.
> All registered agents will need to re-register if this volume is lost.
> **Always back up your keys volume.**

### 🐧 Ubuntu / Debian

**1. Set up the repository:**
```bash
curl -sS https://repo.openscm.io/openscm.gpg | sudo gpg --dearmor -o /usr/share/keyrings/openscm.gpg
echo "deb [signed-by=/usr/share/keyrings/openscm.gpg] https://repo.openscm.io/stable/debian stable main" | sudo tee /etc/apt/sources.list.d/openscm.list
sudo apt update
```

**2. Install:**
```bash
# Server
sudo apt install scmserver

# Agent (on systems to be monitored)
sudo apt install scmclient
```

### 🐧 RedHat / CentOS / SUSE

**1. Set up the repository:**
```bash
sudo tee /etc/yum.repos.d/openscm.repo <<EOF
[openscm]
name=OpenSCM Stable
baseurl=https://repo.openscm.io/stable/redhat/
enabled=1
gpgcheck=1
gpgkey=https://repo.openscm.io/openscm.gpg
EOF
```

**2. Install:**
```bash
# Server
sudo yum install scmserver

# Agent (on systems to be monitored)
sudo yum install scmclient
```

### 🪟 Windows

1. Download the latest installer from [openscm.io/download](https://openscm.io/download)
2. Run the `.msi` setup wizard
3. The agent can be configured to run as a **Windows Service** during installation
4. Configuration is stored in the Windows Registry under `HKLM\SOFTWARE\OpenSCM`

### 😈 FreeBSD

```bash
pkg update
pkg install openscm-server   # Server
pkg install openscm-client   # Agent
```

Or download binaries directly from [openscm.io/download](https://openscm.io/download).

### 🍎 macOS

1. Download the latest `.dmg` from [openscm.io/download](https://openscm.io/download)
2. Run the installer
3. The agent registers itself as a `launchd` service for automatic startup

---

## ⚙️ Configuration

### 🖥️ Agent Configuration

**Linux / macOS / FreeBSD:** `/etc/openscm/scmclient.config`
**Windows:** Registry at `HKLM\SOFTWARE\OpenSCM\Client`

```toml
[server]
url = "http://192.168.1.100:8000"   # OpenSCM Server URL
tenant_id = "default"               # Tenant identifier

[client]
heartbeat = "300"                   # Check-in interval in seconds
loglevel = "info"                   # error | warn | info | debug

[key]
key_path = "/etc/openscm/keys"      # Directory for agent keypair
```

> The agent generates its own Ed25519 keypair on first run.
> Keys are namespaced per server URL — one agent can connect to multiple servers.

### 🌐 Server Configuration

**Linux / macOS / FreeBSD:** `/etc/openscm/scmserver.config`
**Windows:** Registry at `HKLM\SOFTWARE\OpenSCM\Server`

```toml
[server]
port = "8000"                       # Listening port
loglevel = "info"                   # error | warn | info | debug

[database]
path = "/var/lib/openscm/scm.db"   # SQLite database path

[key]
key_path = "/etc/openscm/keys"      # Directory for server keypair
public_key = "scmserver.pub"
private_key = "scmserver.key"
```

---

## 🔐 Authentication

### Default Credentials

| Field | Value |
| :--- | :--- |
| **Username** | `admin` |
| **Password** | `admin` |

> [!IMPORTANT]
> **Change the default password immediately after your first login.**
> The default credentials are for initial setup only.
> In production, always run the server behind a reverse proxy (Nginx, Caddy) with HTTPS enabled.

### Session Management

- Sessions are secured with signed cookies using a key derived from your server's Ed25519 private key
- Sessions expire after **8 hours** of inactivity
- All session cookies are `HttpOnly` and `SameSite=Lax`

### Reverse Proxy (Production)

OpenSCM is designed to run behind a reverse proxy for TLS termination.
Example with Caddy:

```
# Caddyfile
openscm.yourdomain.com {
    reverse_proxy localhost:8000
}
```

---

## 🛡️ Privacy & Security

OpenSCM is built with a privacy-first philosophy — monitoring your infrastructure should never create new risks.

### 🔒 Mutual Ed25519 Signing

Every payload exchanged between agent and server is **cryptographically signed**:

- Each agent has its own Ed25519 keypair generated locally on first run
- The server has its own Ed25519 keypair
- **Agents only accept signed commands from their registered server**
- **The server only accepts signed results from registered agents**

This provides mutual authentication and payload integrity — a tampered or forged payload is immediately rejected.

> **Note:** Payloads are signed, not encrypted. Transport encryption is handled by
> TLS via your reverse proxy. This is the correct separation of concerns —
> signing ensures authenticity, TLS ensures confidentiality in transit.

### 🙈 Privacy-Preserving Audits

This is OpenSCM's core design principle:

```
Traditional tools:    Agent → sends file contents, configs, user data → Server
OpenSCM:             Agent → sends PASS / FAIL / NA only             → Server
```

The agent runs all compliance checks **locally** and only reports the outcome. Your configuration files, user lists, database contents, and system state **never leave your network**.

This makes OpenSCM suitable for:
- Environments with strict data residency requirements
- Air-gapped or isolated networks
- Organizations where sending system data to a central server is prohibited by policy

### ⚡ Memory Safety

Both the client and server are written in **Rust**, providing compile-time guarantees against:
- Buffer overflows
- Use-after-free vulnerabilities
- Data races
- Null pointer dereferences

### 👥 Role-Based Access Control

| Role | Permissions |
| :--- | :--- |
| **Administrator** | Full system access, user management, global configuration |
| **Editor** | Create and manage tests, policies, and system groups |
| **Runner** | Execute compliance scans against system groups |
| **Viewer** | Read-only access to dashboards, inventory, and reports |

---

## 🧪 Compliance Tests

Tests are the building blocks of OpenSCM policies. Each test defines what to check and what the expected state should be.

### Supported Elements

| Element | Description | Platforms |
| :--- | :--- | :--- |
| `File` | Check file existence, content, permissions, ownership, SHA1/SHA256 | All |
| `Directory` | Check directory existence, content, permissions, ownership | All |
| `User` | Check local user existence | All |
| `Group` | Check local group existence and membership | All |
| `Process` | Check if a process is running | All |
| `Package` | Check package installation and version | Linux, Windows, macOS |
| `Port` | Check if a TCP port is open | All |
| `OS` | Check OS type and version | All |
| `Hostname` | Check system hostname | All |
| `IP` | Check IP address presence | All |
| `Domain` | Check domain/workgroup membership | All |
| `Architecture` | Check CPU architecture | All |
| `Agent` | Check agent version | All |
| `Registry` | Check Windows registry values | Windows only |

### Supported Conditions

`Contains` · `Not Contains` · `Equals` · `Not Equals` · `More Than` · `Less Than` · `Regular Expression`

### Test Logic

Each test supports up to 5 conditions combined with **ALL** (every condition must pass) or **ANY** (at least one condition must pass) logic.

---

## 📑 Documentation

Full documentation is available at [openscm.io/docs](https://openscm.io/docs), including:

- Installation and configuration guides
- Writing your first compliance test
- Building and deploying policies
- Managing agents and system groups
- Generating compliance reports
- Production deployment best practices

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a PR.

For major changes, please open an issue first to discuss what you would like to change.

---

## 🔒 Security Disclosure

Please **do not** open public GitHub issues for security vulnerabilities.

If you discover a security issue, please report it responsibly:
- **Email:** security@openscm.io
- We will acknowledge receipt within 48 hours
- We will provide a fix timeline within 5 business days

---

## 🛡️ Support

- **Documentation:** [openscm.io/docs](https://openscm.io/docs)
- **Bug Reports:** [GitHub Issues](https://github.com/openscm/scmserver/issues)
- **Discussions:** [GitHub Discussions](https://github.com/openscm/scmserver/discussions)

---

## ⭐ Acknowledgements

OpenSCM is built on the shoulders of excellent open-source projects:
[Rust](https://rust-lang.org) ·
[Axum](https://github.com/tokio-rs/axum) ·
[sqlx](https://github.com/launchbadge/sqlx) ·
[AdminLTE](https://adminlte.io) ·
[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)

---

<div align="center">
  <strong>Built with ❤️ and Rust</strong><br>
  <a href="https://openscm.io">openscm.io</a>
</div>

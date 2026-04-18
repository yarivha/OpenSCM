# OpenSCM — Open Security Compliance Manager

![License](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue)
![Client License](https://img.shields.io/badge/client-Apache%202.0-green)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20Windows-lightgrey)
![Architectures](https://img.shields.io/badge/arch-x86__64%20|%20ARM%20|%20RISC--V-blue)

A self-hosted, privacy-first security compliance platform built in Rust.

Unlike traditional compliance tools, OpenSCM agents execute tests locally and only report `PASS`, `FAIL`, or `NA` — your configuration files, user data, and system details **never leave your network**.

For full documentation, installation guides, and user manual visit **[openscm.io](https://openscm.io)**.

---

## 🚀 Key Features

- **Privacy-First** — agents report results only, no raw system data leaves your network
- **Mutual Ed25519 Signing** — every payload is cryptographically signed in both directions
- **UI-Driven Policy Builder** — define compliance tests visually, no scripting required
- **Evidence-Grade Reports** — archive compliance results as formal audit evidence (PDF)
- **Universal Platform Support** — Linux and Windows on x86, ARM, and RISC-V (macOS and FreeBSD coming soon)
- **Single Binary Deployment** — server ships with all assets embedded, no setup required
- **Scheduled Scanning** — automate compliance scans on any schedule
- **Role-Based Access Control** — Administrator, Editor, Runner, Viewer

---

## ⚡ Installation

### 🐧 Ubuntu / Debian

```bash
# Add repository
curl -sS https://repo.openscm.io/openscm.gpg | sudo gpg --dearmor -o /usr/share/keyrings/openscm.gpg
echo "deb [signed-by=/usr/share/keyrings/openscm.gpg] https://repo.openscm.io/stable/debian stable main" | sudo tee /etc/apt/sources.list.d/openscm.list
sudo apt update

# Install server
sudo apt install scmserver

# Install agent (on systems to be monitored)
sudo apt install scmclient
```

### 🐧 RedHat / CentOS / SUSE

```bash
# Add repository
sudo tee /etc/yum.repos.d/openscm.repo <<EOF
[openscm]
name=OpenSCM Stable
baseurl=https://repo.openscm.io/stable/redhat/
enabled=1
gpgcheck=1
gpgkey=https://repo.openscm.io/openscm.gpg
EOF

# Install server
sudo yum install scmserver

# Install agent (on systems to be monitored)
sudo yum install scmclient
```

### 🪟 Windows

Download the latest installer from **[openscm.io/download](https://openscm.io/download)**.

The agent can be configured to run as a Windows Service during installation.

### 😈 FreeBSD / 🍎 macOS

Coming soon — follow us on [GitHub](https://github.com/openscm/scmserver) for updates.

### 🐳 Docker

Coming soon — follow us on [GitHub](https://github.com/openscm/scmserver) for updates.

---

After installation, access the dashboard at **http://your-server:8000**

Default credentials: `admin` / `admin` — **change immediately after first login.**

> For production deployments, run the server behind a reverse proxy (Nginx, Caddy)
> with HTTPS enabled. See [openscm.io/docs](https://openscm.io/docs) for details.

---

## ⚖️ Licensing

| Component | License |
| :--- | :--- |
| **Server & Dashboard** | [FSL-1.1-ALv2](LICENSE-FSL) — converts to Apache 2.0 after 2 years |
| **Client Agent** | [Apache 2.0](LICENSE-APACHE) — no restrictions |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

For major changes please open an issue first to discuss what you'd like to change.

---

## 🔒 Security Disclosure

Please **do not** open public issues for security vulnerabilities.
Report them responsibly to **security@openscm.io** — we respond within 48 hours.

---

## 🛡️ Support

- **Docs & User Guide:** [openscm.io/docs](https://openscm.io/docs)
- **Bugs:** [GitHub Issues](https://github.com/openscm/scmserver/issues)
- **Discussion:** [GitHub Discussions](https://github.com/openscm/scmserver/discussions)

---

<div align="center">
  <strong>Built with ❤️ and Rust</strong><br>
  <a href="https://openscm.io">openscm.io</a>
</div>

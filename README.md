# OpenSCM (Open Security Compliance Manager)

OpenSCM is a centralized, open-standard platform designed to help organizations audit, manage, and report on corporate IT security compliance.

From legacy servers to modern ARM-based devices, OpenSCM provides a unified interface to define security policies, deploy compliance tests across diverse architectures, and visualize real-time security posture via a high-performance Rust backend.

---

## 🚀 Key Features

*   **Universal Support:** Native support for Linux, Windows, FreeBSD, and macOS across **x86, ARM, and RISC-V** architectures.
*   **Automated Inventory:** Automatically discover system metadata including Hostname, IP, OS version, and Hardware architecture.
*   **Lightweight Rust Agent:** A high-performance, low-footprint agent ensures secure, encrypted communication with the server.
*   **Real-Time Dashboards:** Interactive compliance visualization using Chart.js and DataTables for immediate insight.
*   **Flexible Policy Engine:** Build comprehensive compliance tests and deploy them to thousands of endpoints effortlessly.
*   **Mobile-Friendly GUI:** Manage your compliance posture from the office or on the go with a responsive web interface.

## 🛠 Tech Stack

### Backend & Agent
*   **Language:** Rust
*   **Framework:** Axum (Server)
*   **Database:** SQLite (with Rusqlite)
*   **Templating:** Tera

### Frontend (AdminLTE)
*   **UI:** Bootstrap 4 & jQuery
*   **Charts:** Chart.js
*   **Data:** DataTables, Select2, DateRangePicker

---

## ⚖️ Licensing

OpenSCM uses a dual-license structure to balance open collaboration with sustainable development:

*   **Client & Common Logic:** Licensed under [Apache License 2.0](LICENSE-APACHE).
*   **Server & Dashboard:** Licensed under [Functional Source License (FSL) 1.1](LICENSE-FSL).

---

## 🔧 Installation

OpenSCM provides native packages via our official stable repositories for easy management and updates.

### 🐧 Ubuntu / Debian
**1. Setup the Repository:**
```bash
curl -sS [https://repo.openscm.io/openscm.gpg](https://repo.openscm.io/openscm.gpg) | sudo gpg --dearmor -o /usr/share/keyrings/openscm.gpg
echo "deb [signed-by=/usr/share/keyrings/openscm.gpg] [https://repo.openscm.io/stable/debian](https://repo.openscm.io/stable/debian) stable main" | sudo tee /etc/apt/sources.list.d/openscm.list
sudo apt update
```

**2. Install:**

*Server: sudo apt install scmserver

*Client: sudo apt install scmclient


### 🐧 RedHat / CentOS/ Suse 
**1. Setup the Repository:**

```bash
sudo tee /etc/yum.repos.d/openscm.repo <<EOF
[openscm]
name=OpenSCM Stable
baseurl=[https://repo.openscm.io/stable/redhat/](https://repo.openscm.io/stable/redhat/)
enabled=1
gpgcheck=1
gpgkey=[https://repo.openscm.io/openscm.gpg](https://repo.openscm.io/openscm.gpg)
EOF
```

**2. Install:**

*Server: sudo yum install scmserver

*Client: sudo yum install scmclient



### Windows
Download the latest installer from openscm.io.

Run the .msi or .exe setup.

The client can be configured to run as a Windows Service during installation.


### FreeBSD
Download the latest installer from openscm.io.

Install via PKG:
```bash
pkg update
pkg install openscm-server
pkg install openscm-agent
```

### MacOS
Download the latest installer from openscm.io.

Run the .dmg setup.


---
## ⚙️ Configuration

OpenSCM uses a simple configuration format to bridge the communication between the central server and distributed agents.

### 🖥️ Agent (Client) Configuration
Default location: `/opt/openscm/scmclient.config` (Linux/Unix) or the installation root (Windows).

```toml
# OpenSCM Agent Configuration
server_host = "192.168.1.100"   # The IP or Hostname of your OpenSCM Server
server_port = 8000              # The port the server is listening on
log_level   = "info"            # options: error, warn, info, debug
```


### Server Configuration 
Default location: `/opt/openscm/scmserver.config` (Linux/Unix) or the installation root (Windows).

```toml
# OpenSCM Server Configuration
[server]
port = "8000"                   # The port the server is listening on
loglevel = "info"               # options: error, warn, info, debug
```


## 🔐 Authentication

OpenSCM provides a secure web-based dashboard to manage your fleet and compliance policies. Upon initial installation, the system is provisioned with a default administrative account.

### Default Credentials
| Field    | Value   |
| :------- | :------ |
| **Username** | `admin` |
| **Password** | `admin` |

> [!IMPORTANT]  
> **Security Requirement:** These credentials are for initial setup purposes only. For production environments, you **must** change the default password immediately after your first successful login to prevent unauthorized access.

### Session Management
The OpenSCM server handles authentication through secure session cookies. For enhanced security in production:
* Ensure the server is hosted behind a reverse proxy (like Nginx or Caddy) with **HTTPS** enabled.
* Periodically audit the user list within the dashboard to remove inactive accounts.



## Project Structure

- `src/` - Server source code
  - `db.rs` - Database operations
  - `handlers.rs` - Request handlers
  - `models.rs` - Data models
  - `schema.rs` - Database schema initialization
  - `main.rs` - Application entry point
- `templates/` - HTML templates using Tera
- `debian/`    - Debian OS configuration files
- `redhat/`    - RedHat OS configuration files
- `static/` - Static assets (CSS, JS, images)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch

## Support

For support, please open an issue in the GitHub repository.


# Blue Team MCP Server

A defensive security MCP server for Claude Desktop — the defender's counterpart to [mcp-kali-server](https://www.kali.org/blog/kali-llm-claude-desktop/).

Where Kali gives Claude offensive tools (nmap, gobuster, sqlmap), this gives Claude **blue team / SOC analyst tools** to investigate, monitor, and harden your systems.

---

## Architecture

```
┌─────────────────────┐        SSH (stdio)       ┌─────────────────────────┐
│   Your Workstation  │ ──────────────────────── │    Defender Host        │
│   Claude Desktop    │                          │   Ubuntu/Debian Server  │
│   (macOS/Windows)   │                          │   blue_team_server.py   │
└─────────────────────┘                          └─────────────────────────┘
         │                                                    │
         │                                          ┌─────────┴──────────┐
    Anthropic API                                   │  System tools:     │
    (Claude Sonnet)                                 │  ss, tcpdump,      │
                                                    │  fail2ban-client,  │
                                                    │  journalctl, lynis │
                                                    │  rkhunter, etc.    │
                                                    └────────────────────┘
```

### Consolidated deployment (Ubuntu-SOC + Wazuh)

When Wazuh Docker and the MCP run on the same host, use `localhost` for Wazuh endpoints:

```
┌─────────────────────┐        SSH          ┌────────────────────────────────────┐
│   Claude Desktop    │ ──────────────────► │         Ubuntu-SOC                 │
│   (macOS)           │  192.168.153.5      │  • 192.168.153.5 (NAT)             │
└─────────────────────┘   or 172.16.101.5   │  • 172.16.101.5 (LAB)              │
                                            │                                     │
                                            │  ┌─────────────────────────────────┐ │
                                            │  │ Wazuh Docker                    │ │
                                            │  │  • Manager API :55000           │ │
                                            │  │  • Indexer (OpenSearch) :9200    │ │
                                            │  └─────────────────────────────────┘ │
                                            │  ┌─────────────────────────────────┐ │
                                            │  │ mcp-server-blueteam             │ │
                                            │  │  WAZUH_API_URL=localhost:55000  │ │
                                            │  │  WAZUH_INDEXER_URL=localhost:9200│ │
                                            │  └─────────────────────────────────┘ │
                                            └────────────────────────────────────┘
```

---

## Quick Start

### 1. On your Defender Host (Ubuntu/Debian)

```bash
git clone https://github.com/not2cleverdotme/blue-team-mcp
cd blue-team-mcp
sudo bash setup.sh
```

The setup script will:
- Install system packages (tcpdump, fail2ban, lynis, rkhunter, chkrootkit)
- Create a Python virtualenv with MCP dependencies
- Place the `mcp-server-blueteam` command in `/usr/local/bin`
- Grant tcpdump network capture capabilities

### 2. Set API Keys and Wazuh (optional but recommended)

Edit the config file created by setup:

```bash
sudo nano /opt/blue-team-mcp/config.env
```

Uncomment and set the variables you need:

- **ABUSEIPDB_API_KEY** — https://www.abuseipdb.com/account/api
- **VIRUSTOTAL_API_KEY** — https://www.virustotal.com/gui/my-apikey
- **WAZUH_API_URL** — `https://localhost:55000` (if Wazuh is on same host) or `https://<host>:55000`
- **WAZUH_API_USER** — `wazuh-wui` (Wazuh Docker default)
- **WAZUH_API_PASSWORD** — e.g. `MyS3cr37P450r.*-` (Wazuh Docker default)
- **WAZUH_API_VERIFY_SSL** — `false` for self-signed certs
- **WAZUH_INDEXER_URL** — `https://localhost:9200` (if on same host) or `https://<host>:9200`
- **WAZUH_INDEXER_USER** — `admin` (indexer default)
- **WAZUH_INDEXER_PASSWORD** — indexer password (often different from Wazuh API)
- **WAZUH_INDEXER_VERIFY_SSL** — `false` for self-signed certs

**Note:** The indexer (port 9200) stores HYDRA-DC Windows events in OpenSearch. Its password may differ from the Wazuh API. For Wazuh Docker, check your `docker-compose` or `.env` for `OPENSEARCH_INITIAL_ADMIN_PASSWORD`. If adding Indexer support to an existing install, re-run `setup.sh` to update the wrapper with the new exports.

### 3. Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "blue-team-mcp": {
      "command": "ssh",
      "args": [
        "-i", "/Users/you/.ssh/ubuntu-soc",
        "soc-admin@192.168.153.5",
        "mcp-server-blueteam"
      ],
      "transport": "stdio"
    }
  }
}
```

Use the IP reachable from your workstation: `192.168.153.5` (NAT) or `172.16.101.5` (LAB).

Restart Claude Desktop. You should see the blue-team-mcp tools available.

---

## Available Tools

### 📋 Log Analysis
| Tool | Description |
|------|-------------|
| `blueteam_read_auth_log` | SSH/sudo/PAM events from auth.log |
| `blueteam_read_syslog` | General system events |
| `blueteam_read_web_log` | nginx/Apache access & error logs |
| `blueteam_journalctl` | Query any systemd unit's journal |

### 🌐 Network Monitoring
| Tool | Description |
|------|-------------|
| `blueteam_list_listening_ports` | All open/listening ports with process |
| `blueteam_list_connections` | Established TCP connections |
| `blueteam_capture_traffic` | Live packet capture via tcpdump |

### 📊 Wazuh SIEM
| Tool | Description |
|------|-------------|
| `blueteam_wazuh_agents` | List all Wazuh agents (status, IP, OS) |
| `blueteam_wazuh_agents_summary` | Agent count by status (active/disconnected) |
| `blueteam_wazuh_manager_logs` | Manager daemon logs (api, cluster, integrations) |
| `blueteam_wazuh_alerts` | Security alerts from alerts.json (when MCP runs on manager host) |
| `blueteam_wazuh_indexer_search` | Query OpenSearch for agent alerts/events (HYDRA-DC Windows events) |

### 🔍 Threat Intelligence
| Tool | Description |
|------|-------------|
| `blueteam_lookup_ip_abuseipdb` | IP reputation via AbuseIPDB |
| `blueteam_lookup_hash_virustotal` | File hash lookup via VirusTotal |
| `blueteam_lookup_domain_virustotal` | Domain reputation via VirusTotal |

### 🚫 Fail2Ban
| Tool | Description |
|------|-------------|
| `blueteam_fail2ban_status` | List all jails and ban counts |
| `blueteam_fail2ban_jail_status` | Detailed status of a specific jail |
| `blueteam_fail2ban_unban` | Unban an IP from a jail |

### 🔐 File Integrity
| Tool | Description |
|------|-------------|
| `blueteam_hash_file` | Hash any file (MD5/SHA1/SHA256/SHA512) |
| `blueteam_find_suid_files` | Find unexpected SUID/SGID binaries |
| `blueteam_find_world_writable` | Find world-writable files (persistence indicator) |
| `blueteam_rootkit_scan` | Run rkhunter or chkrootkit |

### 🛡️ System Hardening
| Tool | Description |
|------|-------------|
| `blueteam_lynis_audit` | Full Lynis hardening audit |
| `blueteam_check_updates` | Check for pending security updates |
| `blueteam_check_open_firewall` | View ufw/nftables/iptables rules |

### 👤 User & Session Monitoring
| Tool | Description |
|------|-------------|
| `blueteam_who_is_logged_in` | Active user sessions with source IPs |
| `blueteam_last_logins` | Login history (last 50) |
| `blueteam_failed_logins` | Failed login attempts |
| `blueteam_sudo_history` | Sudo command usage |
| `blueteam_list_users` | All local accounts with risk flags |
| `blueteam_check_ssh_authorized_keys` | All authorized_keys files |

### ⚙️ Process & Persistence
| Tool | Description |
|------|-------------|
| `blueteam_list_processes` | All running processes |
| `blueteam_list_cron_jobs` | System and user cron jobs |

### 💻 System Health
| Tool | Description |
|------|-------------|
| `blueteam_system_health` | Uptime, disk, memory, CPU load |

---

## Example Prompts

Once connected via Claude Desktop, you can ask:

```
"Check the last 2 hours of auth.log and tell me if there are any brute force 
 attempts. Group by source IP."

"Show me all listening ports. Are any unexpected services running?"

"Here are 5 IPs from my nginx access log: 1.2.3.4, 5.6.7.8, 9.10.11.12,
 13.14.15.16, 200.1.2.3 — look them all up on AbuseIPDB."

"Run a Lynis audit and give me the top 5 highest priority hardening items."

"Check for any SUID binaries that aren't in the standard list of expected ones."

"Who is currently logged into this server, and when did they log in?"

"Scan all user cron jobs and flag anything that looks suspicious."

"Hash /usr/bin/sshd and check it against VirusTotal."
```

---

## MAESTRO Framework Alignment

This server aligns with the [CSA MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) framework for agentic AI security. See [MAESTRO.md](MAESTRO.md) for the threat model and mitigations.

### Optional: Audit Logging (Repudiation Mitigation)

Enable audit logging to record tool invocations:

```bash
export BLUETEAM_AUDIT_LOG=/var/log/blue-team-mcp-audit.jsonl
```

Ensure log rotation (e.g., logrotate) to prevent unbounded growth.

### Optional: Rate Limiting (DoS Mitigation)

Limit tool calls per minute:

```bash
export BLUETEAM_RATE_LIMIT=60
```

---

## Security Notes

- The MCP server runs with **whatever privileges the SSH user has**. Running as a dedicated low-privilege user (with sudo for specific tools) is recommended for production.
- Threat intel tools make **outbound API calls** to AbuseIPDB/VirusTotal. Ensure this is acceptable in your environment.
- `blueteam_capture_traffic` requires `CAP_NET_RAW` or root. The setup script attempts to grant this to tcpdump via `setcap`.
- Log files under `/var/log/` often require root or membership in the `adm` group to read. Add your SSH user to the `adm` group: `usermod -aG adm youruser`
- **Path restrictions:** `blueteam_hash_file` allows paths under `/var`, `/etc`, `/home`, `/opt`, `/usr` (configurable via `BLUETEAM_ALLOWED_PATHS`). `blueteam_capture_traffic` writes pcap files only under `BLUETEAM_CAPTURE_DIR` (default `/tmp`).

---

## Requirements

**Defender Host:**
- Ubuntu 20.04+ or Debian 11+ (other distros work with minor adjustments)
- Python 3.8+
- OpenSSH server

**Optional system tools** (setup.sh installs these):
- `tcpdump`, `fail2ban`, `lynis`, `rkhunter`, `chkrootkit`

**Python packages** (auto-installed in venv, pinned for supply chain security):
- `mcp>=1.0.0,<2.0.0`
- `httpx>=0.27.0,<0.28.0`
- `pydantic>=2.0.0,<3.0.0`

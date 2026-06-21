# node-privacy-audit

**Can your Sentinel dVPN node see or log its own clients? This tells you — and how to fix it.**

Sentinel says it plainly: *"no-log is a legal promise, not a technical guarantee."* The control plane doesn't log traffic — but **the individual node operator sits on the path of client traffic.** A misconfigured node can resolve client domains, write connection logs to disk, or run software that inspects traffic — usually without the operator even realising it.

Everyone tests *"is my VPN leaking?"* (client side). **Nobody audits the other side: can my node spy on the people using it?** This tool does.

It is **read-only**. It inspects, scores, and tells you exactly what to change. It never modifies your node.

## What it checks (13 checks)

| Check | What it catches |
|-------|-----------------|
| `domain_strategy` | Whether the node resolves DNS *for* clients (sees their domains) or passes traffic through blind (`AsIs`) |
| `v2ray_dns` | A V2Ray DNS block that funnels client lookups through a logging resolver |
| `access_log` | V2Ray writing client connection records to disk |
| `config_permissions` | Config (with client keys/IDs) readable by other users on the box |
| `wireguard` | Detects WireGuard nodes and their client-visibility surface |
| `wireguard_config_perms` | WG config holding **private keys** readable by other users |
| `wireguard_postup_logging` | PostUp/PostDown hooks that LOG client traffic |
| `wireguard_debug` | WireGuard kernel debug logging (prints peer handshakes) |
| `system_resolver` | Whether the OS resolves via external/logging resolvers |
| `system_logging` | iptables LOG rules — distinguishes harmless UFW block-logging from real client-traffic logging |
| `journald_verbosity` | Verbose service logs recording per-connection client detail in journald |
| `traffic_interception` | Packet sniffers, TLS MITM, Pi-hole/DNS-loggers, IDS/DPI running on the node |
| `promiscuous_mode` | Network interfaces capturing all segment traffic |

Each finding comes with a severity and a concrete fix. The privacy score is **honest**: if the tool can't read your node config, it caps the score and tells you — it never hands out a high score on incomplete data.

## Usage

```bash
# audit the local node (auto-detects config in /root or ~/.sentinel-dvpnx)
python3 node_privacy_audit.py

# if the config is root-owned, run with sudo so the core checks actually run
sudo python3 node_privacy_audit.py

# custom config path
python3 node_privacy_audit.py --config /home/youruser/.sentinel-dvpnx/v2ray/server.json

# machine-readable output (for dashboards / CI)
python3 node_privacy_audit.py --json
```

No dependencies beyond Python 3 standard library. Works on any Linux node.

## Reading the result

- **STRONG (≥90)** — node reveals nothing meaningful about clients
- **GOOD (≥78)** — only minor, low-risk items
- **MODERATE (≥55)** — some client visibility, fixable
- **WEAK (<55)** — node can see/log client traffic, act on the fixes
- **INCOMPLETE** — couldn't read the node config; re-run with sudo

## Why this matters

A privacy node that can see its clients isn't private — it's surveillance with extra steps, and the client has no way to know. This tool turns "trust me, I don't log" into something you can actually **check**. Run it on your own node before you ask anyone to trust it.

## What this does NOT do (read this)

This tool audits **one node's configuration** — what *your* node can see or log about its clients. That is a real, fixable piece of the privacy picture, but it is **not the whole picture**:

- It does **not** prevent traffic-correlation attacks. On any 2-hop / dVPN setup, an observer who can watch both ends of the traffic can correlate patterns and potentially link a client to a destination — regardless of how your node is configured. That is an **architectural** property of the network, not something a single node can fix.
- It does **not** make a node "anonymous" or "private at 100%". It reduces *operator-side visibility*, which is one concrete attack surface among several.
- It is **not** an antivirus, IDS, or full security audit.

In short: a clean score here means *your node is configured so it doesn't needlessly see or log its clients*. It does not mean the network is unconditionally private. Use it as one honest layer, not a silver bullet.

## Scope & honesty

This audits **operator-side visibility** — what your node can see/log about clients. It is not an antivirus or a full intrusion-detection system. It checks the concrete, known paths by which a dVPN node can observe client traffic, and it's deliberately precise: it won't cry wolf over a normal UFW firewall log.

Read-only. MIT licensed. Built by a node operator, for node operators.

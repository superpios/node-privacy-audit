#!/usr/bin/env python3
"""
node-privacy-audit  —  DNS-leak & client-visibility auditor for Sentinel dVPN nodes
====================================================================================

READ-ONLY. Does not modify anything. It inspects your node and tells you, in plain
terms, what your node CAN see or log about your clients' traffic — and how to fix it.

The blind spot it covers: everyone tests "is MY vpn leaking?" (client side).
Nobody audits "can my NODE spy on its clients?" (operator side). This does the latter.

Checks (all read-only):
  1. V2Ray DNS object        — does the node resolve client queries via a logging resolver?
  2. V2Ray domainStrategy    — does the node resolve DNS for the client (sees domains) or pass through?
  3. V2Ray access log        — is V2Ray writing client connections to disk?
  4. System resolver         — where does the machine send DNS, is it encrypted/no-log?
  5. System-level logging     — journald/conntrack capturing client connections?

Usage:
  python3 node_privacy_audit.py                      # audit live node (default paths)
  python3 node_privacy_audit.py --config PATH        # custom v2ray config path
  python3 node_privacy_audit.py --json               # machine-readable output
"""

import os, json, sys, subprocess, argparse

import getpass
CANDIDATE_PATHS = [
    "/root/.sentinel-dvpnx/v2ray/server.json",
    os.path.expanduser("~/.sentinel-dvpnx/v2ray/server.json"),
    "/home/%s/.sentinel-dvpnx/v2ray/server.json" % getpass.getuser(),
]
def find_v2ray_config():
    for p in CANDIDATE_PATHS:
        if os.path.exists(p):
            return p
    return CANDIDATE_PATHS[0]  # fallback for the error message
DEFAULT_V2RAY = find_v2ray_config()

# ---------- helpers ----------
class Result:
    def add(self, check, status, severity, detail, fix=""):
        self.findings.append({"check": check, "status": status,
                              "severity": severity, "detail": detail, "fix": fix})
    def __init__(self):
        self.findings = []
        self.config_unreadable = False
    def score(self):
        pen = {"critical": 40, "high": 25, "medium": 12, "low": 5, "ok": 0, "info": 0}
        s = 100 - sum(pen.get(f["severity"], 0) for f in self.findings)
        s = max(0, s)
        # honesty cap: if the V2Ray config could not be read, the core checks did
        # not run -> we cannot claim a high score, whatever the other checks say.
        if self.config_unreadable:
            s = min(s, 50)
        return s

def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f), None
    except FileNotFoundError:
        return None, f"file not found: {path}"
    except json.JSONDecodeError as e:
        return None, f"invalid JSON in {path}: {e}"
    except PermissionError:
        return None, f"permission denied: {path} (run as the node user/root)"

def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return ""

# ---------- the 5 checks ----------
def check_v2ray_dns(cfg, r):
    dns = cfg.get("dns")
    if not dns:
        r.add("v2ray_dns", "no explicit DNS block", "ok",
              "V2Ray has no custom 'dns' object — it does not force client queries through a chosen resolver here.",
              "")
        return
    servers = dns.get("servers", [])
    plain = []
    for s in servers:
        host = s if isinstance(s, str) else s.get("address", "")
        # a logging-capable plaintext resolver (not DoH/DoT, not localhost)
        if host and not host.startswith(("https://", "tls://", "localhost", "127.", "::1")):
            plain.append(host)
    if plain:
        r.add("v2ray_dns", "client DNS forced through plaintext resolver(s)", "high",
              f"V2Ray 'dns' routes client lookups through: {', '.join(plain)}. "
              f"These see every domain your clients visit and may log it.",
              "Use an encrypted/no-log resolver (DoH/DoT) or a local non-logging resolver, "
              "or remove the dns block so lookups aren't centralised through a logger.")
    else:
        r.add("v2ray_dns", "DNS block uses encrypted/local resolvers", "ok",
              "Client lookups go through encrypted or local resolvers — good.", "")

def check_domain_strategy(cfg, r):
    outs = cfg.get("outbounds", [])
    leaky = []
    for o in outs:
        if o.get("protocol") == "freedom":
            strat = (o.get("settings") or {}).get("domainStrategy", "AsIs")
            if strat in ("UseIP", "UseIPv4", "UseIPv6"):
                leaky.append(strat)
    if leaky:
        r.add("domain_strategy", "node resolves DNS on behalf of clients", "critical",
              f"freedom outbound uses domainStrategy={leaky[0]}. This means YOUR NODE "
              f"performs the DNS resolution for client traffic — so the node (and anyone "
              f"who can read its memory/logs) sees the destination domains.",
              "Set domainStrategy to 'AsIs' so the client resolves the domain and the node "
              "only ever sees an IP it forwards to — it cannot see the domain name.")
    else:
        r.add("domain_strategy", "node passes traffic AsIs (does not resolve for clients)", "ok",
              "freedom outbound uses AsIs — the node does not resolve client domains. Good.", "")

def check_access_log(cfg, r):
    log = cfg.get("log", {})
    access = log.get("access", "")
    loglevel = log.get("loglevel", "warning")
    if access and access not in ("none", "/dev/null", ""):
        r.add("access_log", "V2Ray access log is writing client connections to disk", "critical",
              f"log.access = '{access}'. V2Ray is recording client connection records "
              f"(source, destination) to a file. This is a persistent privacy leak on disk.",
              "Set log.access to 'none' (or '/dev/null') so client connections are not written to disk.")
    elif loglevel in ("debug", "info"):
        r.add("access_log", f"verbose loglevel ({loglevel}) may expose client info", "medium",
              f"log.loglevel = '{loglevel}'. Debug/info levels can print client connection "
              f"details to stdout/journald.",
              "Set loglevel to 'warning' or 'error' to avoid logging per-connection client detail.")
    else:
        r.add("access_log", "no access log, conservative loglevel", "ok",
              "V2Ray is not writing client connection records. Good.", "")

def check_system_resolver(r):
    content = ""
    try:
        with open("/etc/resolv.conf") as f:
            content = f.read()
    except Exception:
        r.add("system_resolver", "could not read /etc/resolv.conf", "info",
              "Unable to read the system resolver config.", "")
        return
    servers = [l.split()[1] for l in content.splitlines()
               if l.strip().startswith("nameserver") and len(l.split()) > 1]
    local = [s for s in servers if s.startswith(("127.", "::1"))]
    external = [s for s in servers if not s.startswith(("127.", "::1"))]
    known_loggers = {"8.8.8.8": "Google", "8.8.4.4": "Google",
                     "1.1.1.1": "Cloudflare", "208.67.222.222": "OpenDNS"}
    if local and not external:
        r.add("system_resolver", "system uses a local resolver", "ok",
              f"Resolver is local ({', '.join(local)}) — lookups stay on the box "
              f"(verify that local resolver itself doesn't log).", "")
    elif external:
        tagged = [f"{s} ({known_loggers[s]})" if s in known_loggers else s for s in external]
        r.add("system_resolver", "system resolves via external resolver(s)", "medium",
              f"/etc/resolv.conf points to: {', '.join(tagged)}. If the node ever resolves "
              f"client domains, these external resolvers see them.",
              "Point the system at a local non-logging resolver (e.g. a local dnscrypt-proxy "
              "in no-log mode) so external parties don't receive client-derived lookups.")

def check_system_logging(r):
    """Distinguish three cases precisely (avoid crying wolf):
       - LOG rules on FORWARD that are generic (catch ALL forwarded traffic) -> real risk
       - UFW LOG rules on FORWARD (only log BLOCKED/rate-limited packets) -> low, informational
       - LOG only on INPUT/OUTPUT (node's own traffic, not clients) -> fine
    """
    all_log = _run(["sh", "-c", "iptables -S 2>/dev/null | grep -i ' -j LOG'"]).strip()
    if not all_log:
        r.add("system_logging", "no iptables LOG rules", "ok",
              "No iptables LOG rules recording connections were found.", "")
        return

    # is there any LOG rule that fires on the FORWARD path?
    fwd_chains = _run(["sh", "-c",
        "iptables -L FORWARD -n 2>/dev/null | grep -iE 'logging-forward|LOG'"]).strip()
    is_ufw = ("ufw" in all_log.lower())

    if not fwd_chains:
        # LOG only on INPUT/OUTPUT — the node's own traffic, not client traffic
        r.add("system_logging", "LOG rules only on node's own traffic (not forwarded)", "ok",
              "iptables LOG rules exist but only on INPUT/OUTPUT (the node's own connections). "
              "Forwarded client traffic is not logged.", "")
    elif is_ufw:
        # UFW forward logging: only blocked/rate-limited packets get logged, not normal client flow
        r.add("system_logging", "UFW logs only BLOCKED packets on forward (normal client flow not logged)", "low",
              "UFW logging chains are present on FORWARD, but UFW only writes a log line for "
              "packets it BLOCKS or rate-limits — not for the normal client traffic the node "
              "forwards. Real client-traffic exposure is minimal. The only metadata that could "
              "appear is the src/dst of a blocked packet.",
              "Optional: if you want zero forward logging, set UFW 'LOGLEVEL=off' or disable "
              "logging on the forward chain. Trade-off: you lose visibility into blocked attacks. "
              "For most operators UFW's default is an acceptable balance.")
    else:
        # generic LOG on FORWARD that may catch all forwarded traffic — real concern
        r.add("system_logging", "non-UFW LOG rule on FORWARD may record client connections", "medium",
              "A LOG rule on the FORWARD chain (not from UFW) could record metadata of client "
              "connections the node forwards.",
              "Review the FORWARD LOG rule; remove it if it captures normal forwarded client traffic.")

def check_traffic_interception(r):
    """Detect software/processes that can SEE or LOG client traffic on this node:
    packet sniffers, MITM proxies, DNS-logging resolvers (Pi-hole etc.), IDS/DPI,
    and promiscuous interfaces. Read-only (ps / ip link / ss)."""

    # known traffic-visibility tools -> (category, severity, why)
    watch = {
        "tcpdump": ("packet sniffer", "high", "captures raw packets, can record client traffic"),
        "tshark": ("packet sniffer", "high", "captures raw packets"),
        "dumpcap": ("packet sniffer", "high", "wireshark capture backend"),
        "ngrep": ("packet sniffer", "high", "greps live traffic"),
        "mitmproxy": ("TLS MITM", "critical", "intercepts and can decrypt client TLS"),
        "mitmdump": ("TLS MITM", "critical", "intercepts and can decrypt client TLS"),
        "sslsplit": ("TLS MITM", "critical", "active man-in-the-middle on TLS"),
        "bettercap": ("MITM toolkit", "critical", "active network MITM toolkit"),
        "squid": ("transparent proxy", "high", "proxy that sees client destinations"),
        "pihole-FTL": ("DNS logger", "high", "Pi-hole logs every DNS query — sees client domains"),
        "dnsmasq": ("DNS resolver", "medium", "if log-queries is on, records client domains"),
        "named": ("DNS resolver", "medium", "BIND can query-log client domains"),
        "ntopng": ("traffic analyzer", "high", "inspects and displays all traffic"),
        "suricata": ("IDS/DPI", "high", "deep packet inspection, logs connections"),
        "snort": ("IDS/DPI", "high", "deep packet inspection, logs connections"),
        "zeek": ("network monitor", "high", "logs detailed connection records"),
    }

    ps_out = _run(["ps", "-eo", "comm"]).lower()
    found = []
    for name, (cat, sev, why) in watch.items():
        if name.lower() in ps_out:
            found.append((name, cat, sev, why))

    if found:
        # report the most severe ones explicitly
        for name, cat, sev, why in sorted(found, key=lambda x: {"critical":0,"high":1,"medium":2}.get(x[2],3)):
            r.add("traffic_interception", f"{name} is running ({cat})", sev,
                  f"'{name}' is active on the node — {why}. On a privacy node this is a "
                  f"red flag: it can observe traffic that should pass through blindly.",
                  f"If you did not intentionally run {name} for a legitimate reason, stop and "
                  f"investigate it. A dVPN node should not run traffic-inspection software.")
    else:
        r.add("traffic_interception", "no traffic-interception software detected", "ok",
              "No packet sniffers, MITM proxies, DNS-loggers, or IDS were found running.", "")

    # promiscuous interfaces (capture ALL traffic on the segment)
    iplink = _run(["ip", "-o", "link", "show"])
    promisc = [line.split(":")[1].strip() for line in iplink.splitlines()
               if "PROMISC" in line and ":" in line]
    if promisc:
        r.add("promiscuous_mode", f"interface(s) in promiscuous mode: {', '.join(promisc)}", "high",
              "A promiscuous interface captures all traffic on its segment, not just its own — "
              "a strong sign of sniffing.",
              "Disable promiscuous mode unless a legitimate tool requires it.")
    else:
        r.add("promiscuous_mode", "no promiscuous interfaces", "ok",
              "No interface is capturing all segment traffic.", "")

def check_config_permissions(path, r):
    """The V2Ray/WireGuard config holds client keys/IDs. If it's world-readable,
    any user or compromised process on the box can read it."""
    try:
        st = os.stat(path)
    except Exception:
        return
    mode = st.st_mode & 0o777
    world = mode & 0o007
    group = mode & 0o070
    if world:
        r.add("config_permissions", f"config is world-readable ({oct(mode)})", "high",
              f"{path} can be read by ANY user on this machine. It contains client "
              f"VMess IDs / keys — a leak path if the box has other users or services.",
              f"Restrict it: chmod 600 {path} (owner-only) so only the node can read it.")
    elif group:
        r.add("config_permissions", f"config is group-readable ({oct(mode)})", "medium",
              f"{path} is readable by its group. Tighten if the group has other members.",
              f"Consider chmod 600 {path}.")
    else:
        r.add("config_permissions", "config is owner-only", "ok",
              f"{path} is not readable by other users. Good.", "")

def check_wireguard(r):
    """WireGuard nodes have their OWN privacy surface, distinct from V2Ray:
       - config holds PRIVATE KEYS (permissions matter a lot)
       - PostUp/PostDown scripts can contain LOG rules on client traffic
       - the kernel module can debug-print peers
    """
    wg_show = _run(["sh", "-c", "wg show 2>/dev/null | head -1"])
    iplink = _run(["sh", "-c", "ip -o link show type wireguard 2>/dev/null"])
    has_wg = bool(wg_show.strip() or iplink.strip())
    if not has_wg:
        r.add("wireguard", "no WireGuard interface detected", "info",
              "This node does not appear to run WireGuard (V2Ray-only, or WG not up).", "")
        return

    r.add("wireguard", "WireGuard active — forwards packets without resolving domains", "ok",
          "WireGuard moves encrypted packets; it does not resolve DNS for clients, so the "
          "WG layer itself does not see destination domains.", "")

    # WG-1: config file permissions (configs hold PRIVATE KEYS)
    import glob, os as _os
    wg_confs = glob.glob("/etc/wireguard/*.conf")
    for cf in wg_confs:
        try:
            mode = _os.stat(cf).st_mode & 0o777
        except Exception:
            continue
        if mode & 0o077:  # any access for group/other
            r.add("wireguard_config_perms", f"WG config {_os.path.basename(cf)} is too open ({oct(mode)})", "high",
                  f"{cf} contains WireGuard PRIVATE KEYS and is readable beyond its owner. "
                  f"Anyone who reads it can impersonate the node or decrypt its tunnels.",
                  f"Lock it down: chmod 600 {cf}")
        else:
            r.add("wireguard_config_perms", f"WG config {_os.path.basename(cf)} is owner-only", "ok",
                  f"{cf} is not readable by other users. Good.", "")

    # WG-2: PostUp/PostDown scripts containing LOG rules on client traffic
    for cf in wg_confs:
        try:
            content = open(cf).read()
        except Exception:
            continue
        post_lines = [l for l in content.splitlines()
                      if l.strip().lower().startswith(("postup", "postdown"))]
        logging_posts = [l for l in post_lines if " -j log" in l.lower() or "log-prefix" in l.lower()]
        if logging_posts:
            r.add("wireguard_postup_logging", "PostUp/PostDown rule logs traffic", "high",
                  f"A PostUp/PostDown hook in {_os.path.basename(cf)} adds an iptables LOG rule — "
                  f"this can record client connection metadata when the tunnel is up.",
                  "Remove the LOG rule from the PostUp/PostDown hook unless strictly needed for debugging.")

    # WG-3: kernel module dynamic debug (prints peer handshakes to dmesg)
    dbg = _run(["sh", "-c", "cat /sys/module/wireguard/parameters/dyndbg 2>/dev/null"])
    if dbg.strip() and dbg.strip() not in ("", "0", "off"):
        r.add("wireguard_debug", "WireGuard kernel debug logging is enabled", "medium",
              "WireGuard dynamic debug is on — it prints peer handshakes/endpoints to the kernel log.",
              "Disable WG debug: echo 'module wireguard -p' | sudo tee /sys/kernel/debug/dynamic_debug/control")

def check_journald_verbosity(r):
    """Even with no access log, a verbose service can dump per-connection detail
    into systemd-journald (persistent on disk)."""
    # look at the sentinel/v2ray unit logs verbosity hint
    out = _run(["sh", "-c",
        "journalctl -u sentinel* -u v2ray* --no-pager -n 200 2>/dev/null | "
        "grep -ciE 'accepted|connection from|tcp:|udp:|->' "])
    try:
        hits = int(out.strip() or "0")
    except ValueError:
        hits = 0
    if hits >= 20:
        r.add("journald_verbosity", "service logs show per-connection lines in journald", "high",
              f"Recent node logs contain ~{hits} connection-like lines. systemd-journald "
              f"persists these to disk — a record of client activity outside V2Ray's own log.",
              "Lower the node/V2Ray loglevel (warning/error) and consider "
              "'Storage=volatile' for journald, or a short retention, so client-derived "
              "connection lines are not kept on disk.")
    else:
        r.add("journald_verbosity", "no per-connection spam in service journald logs", "ok",
              "Node service logs in journald don't appear to record per-connection client detail.", "")

# ---------- runner ----------
def audit(v2ray_path):
    r = Result()
    cfg, err = _read_json(v2ray_path)
    if err:
        # CRITICAL for honesty: if we cannot read the V2Ray config, the three most
        # important checks did NOT run. We must NOT hand out a high score.
        r.config_unreadable = True
        hint = err
        if "permission denied" in err.lower():
            hint += "  ->  re-run with sudo so the audit can read the node config."
        r.add("config", "V2Ray config NOT audited (could not read it)", "high", hint,
              "Re-run the audit so it can read the V2Ray config — e.g. 'sudo python3 "
              "node_privacy_audit.py' or '--config /home/<user>/.sentinel-dvpnx/v2ray/server.json'. "
              "Until then, the 3 most important checks (DNS, domainStrategy, access log) are UNKNOWN.")
    else:
        r.config_unreadable = False
        check_v2ray_dns(cfg, r)
        check_domain_strategy(cfg, r)
        check_access_log(cfg, r)
        check_config_permissions(v2ray_path, r)
    check_wireguard(r)
    check_system_resolver(r)
    check_system_logging(r)
    check_journald_verbosity(r)
    check_traffic_interception(r)
    return r

def print_report(r):
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}
    icon = {"critical": "[!!]", "high": "[!]", "medium": "[~]", "low": "[.]",
            "ok": "[OK]", "info": "[i]"}
    print("\n" + "="*66)
    print("  node-privacy-audit — can your node see/log its clients?")
    print("="*66)
    for f in sorted(r.findings, key=lambda x: sev_order.get(x["severity"], 9)):
        print(f"\n{icon.get(f['severity'],'[?]')} {f['check']}: {f['status']}")
        print(f"     {f['detail']}")
        if f["fix"]:
            print(f"     FIX: {f['fix']}")
    score = r.score()
    print("\n" + "-"*66)
    if getattr(r, "config_unreadable", False):
        verdict = "INCOMPLETE — could not read V2Ray config; core checks did not run (re-run with sudo)"
    else:
        verdict = ("STRONG — node reveals nothing meaningful about clients" if score >= 90 else
                   "GOOD — minor, low-risk items only" if score >= 78 else
                   "MODERATE — some client visibility, fixable" if score >= 55 else
                   "WEAK — node can see/log client traffic, act on the FIX lines")
    print(f"  PRIVACY SCORE: {score}/100  — {verdict}")
    print("-"*66)

def main():
    ap = argparse.ArgumentParser(description="DNS-leak & client-visibility auditor for Sentinel dVPN nodes (read-only)")
    ap.add_argument("--config", default=DEFAULT_V2RAY, help="path to V2Ray server.json")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()
    r = audit(args.config)
    if args.json:
        print(json.dumps({"score": r.score(), "findings": r.findings}, indent=2))
    else:
        print_report(r)

if __name__ == "__main__":
    main()

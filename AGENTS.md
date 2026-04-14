# AGENTS.md

This file provides guidance to Qoder (qoder.com) when working with code in this repository.

## Environment requirements

- Linux with **Mininet**, **Open vSwitch**, and **Ryu** installed (course VM or Ubuntu + packages).
- Python dependency: `ryu>=4.34` (see `requirements.txt`).
- Install in a venv if desired: `pip install -r requirements.txt`.
- Ubuntu system packages: `sudo apt install -y mininet openvswitch-switch python3-pip`.

## Running the project

Always start the controller **before** Mininet; switches must register before heavy traffic arrives.

```bash
# Terminal A — must be run from the repo root (rules.json is resolved relative to cwd)
ryu-manager controller.py --verbose

# Terminal B
sudo python3 topology.py
```

Inspect dataplane state:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s2
sudo ovs-ofctl -O OpenFlow13 dump-flows s3
```

Cleanup after an unclean Mininet exit:

```bash
sudo mn -c
```

## Architecture overview

### controller.py — single Ryu application (`Controller` class)

The app handles **all three switches** in one process, dispatching differently based on DPID:

| DPID | Role | Handler |
|------|------|---------|
| 1 (`s1`) | L4 learning switch | `switch()` |
| 2 (`s2`) | Firewall (drop rules) + L2 learning | `firewall()` |
| 3 (`s3`) | L4 learning switch | `switch()` |

**Flow priority hierarchy** (higher = higher priority):

| Constant | Value | Purpose |
|----------|-------|---------|
| `FLOW_PRIO_MISS` | 0 | Table-miss → send to controller |
| `FLOW_PRIO_L4_SW` | 15 | L4-matched learned flows on s1/s3 |
| `FLOW_PRIO_L2_FW` | 20 | L2-matched allow flows on s2 |
| `FLOW_PRIO_FW_DROP` | 100 | Static firewall drop rules from `rules.json` |
| `FLOW_PRIO_SYN_BLOCK` | 250 | Dynamic SYN-flood mitigation block |

**Key methods:**

- `handle_features_request` — registers datapaths, installs table-miss rule, installs firewall drops on s2, spawns the stats loop (once).
- `handle_packet_in` — dispatches to `switch()` or `firewall()` based on DPID.
- `ofmatch_from_packet` — builds a full L4 OFPMatch (IP, TCP/UDP/ICMP fields) from a parsed packet, used for L4 flow installation on s1/s3.
- `track_syn_if_needed` — called on every packet-in; counts TCP SYNs per source IP within a sliding 10 s window; if >20 SYNs triggers `install_syn_block()` (drops all IPv4 + ARP from that IP for 60 s via hard timeout).
- `_stats_loop` — Ryu hub greenthread; polls `OFPFlowStatsRequest` every 5 s on all known datapaths; results logged by `handle_stats_response`.

### topology.py / topo.py

`CourseTopo` (Mininet `Topo` subclass) wires up the fixed topology:

```
[h1,h2,h3] — s1 — s2 — s3 — [h4,h5,h6]
```

DPIDs are hardcoded (`0000000000000001`–`0003`). `autoSetMacs=False` — do **not** assume predictable MACs. The `RemoteController` connects to `127.0.0.1:6653`.

### rules.json

Firewall rules consumed at startup by `parse_rules()`. Top-level key is `"datapath"`, mapping DPID string → `{"rules": [...]}`. Each rule is a flat dict of OFPMatch field names → values (string digits are auto-coerced to `int` by `ofmatch_from_dict`). Rules are installed as permanent drop flows (`i_timeout=0, h_timeout=0`) at priority 100 on s2.

`rules_template.json` shows the minimal shape for adding a new rule.

## Key behaviours to preserve

- `rules.json` **must be in cwd** when `ryu-manager` is launched (path is relative).
- The stats greenthread is spawned exactly once (guarded by `_stats_spawned`); do not break this guard when modifying `handle_features_request`.
- `cleanup_syntrack` runs as a daemon `Thread` (not a hub greenthread) to avoid blocking the Ryu event loop.
- Firewall (s2) installs **L2-only** allow flows (no L4 match), intentionally lower priority than the drop rules so drop rules always win.
- Do **not** use `mn --mac`; host MACs are random by design.

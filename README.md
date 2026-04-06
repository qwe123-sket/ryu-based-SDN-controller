# Ryu-based SDN controller

OpenFlow 1.3 controller built with **Ryu**, tested with **Mininet** and **Open vSwitch**.  
Implements an integrated network application: Layer-4 learning switches on edge datapaths, a middle firewall driven by JSON rules, periodic flow statistics, and SYN-flood mitigation.

## Project structure

```text
.
├── controller.py           # Single integrated Ryu app (Tasks 1–4)
├── topology.py             # Mininet topology (Task 0)
├── topo.py                 # Optional entry, same as topology.py
├── rules.json              # Firewall rules for s2 (Task 2)
├── rules_template.json     # JSON rule shape reference
├── requirements.txt
└── README.md
```

## Topology

- Switches: `s1`, `s2`, `s3` (DPIDs `1`, `2`, `3` in hex form `0000000000000001` … `0003`).
- Hosts: `h1`–`h6` with addresses `10.0.0.1`–`10.0.0.6/24`.
- Layout: `[h1,h2,h3] — s1 — s2 — s3 — [h4,h5,h6]`. Inter-segment traffic passes through `s2`.

## Repository layout

| Path | Role |
|------|------|
| `controller.py` | Ryu application (L4 learning, firewall, stats, SYN defence) |
| `topology.py` | Mininet topology + CLI (`python3 topology.py`) |
| `topo.py` | Same topology entry if the brief requires `topo.py` |
| `rules.json` | Active firewall rules for datapath `0000000000000002` |
| `rules_template.json` | Minimal JSON shape for adding rules |
| `requirements.txt` | Python packages (`ryu`) |

## Prerequisites

- Linux environment with **Mininet**, **Open vSwitch**, and **Ryu** (e.g. course VirtualBox image or Ubuntu + packages).
- **Do not** rely on `mn --mac` for this assignment; keep default host MAC behaviour unless the brief says otherwise.
- Controller and Mininet must reach each other: default `RemoteController` is `127.0.0.1:6653`. If the controller runs on the host and Mininet inside a VM, set the host IP that the guest can reach.

## Installation (after the VM / tools are ready)

```bash
# Optional: isolated environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

On Ubuntu, Mininet/OVS are usually from the distro, not pip:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-pip
```

## Run 

1. Open a terminal in the **same directory as `rules.json`** (relative path used by the app).
2. Start the controller:

   ```bash
   ryu-manager controller.py --verbose
   ```

3. Start the emulated network:

   ```bash
   sudo python3 topology.py
   ```

4. Follow **Testing procedure** below (Mininet CLI commands are entered at the `mininet>` prompt unless noted).

5. Inspect dataplane rules when needed:

   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s1
   sudo ovs-ofctl -O OpenFlow13 dump-flows s2
   sudo ovs-ofctl -O OpenFlow13 dump-flows s3
   ```

## Testing procedure (Task 0–5)

**Setup:** Terminal A — `ryu-manager controller.py --verbose` (from the directory that contains `rules.json`). Terminal B — `sudo python3 topology.py` (or `topo.py`). Optional terminal C — `ovs-ofctl` on the same machine.

**Note:** Firewall rules apply to traffic that **crosses `s2`**. Traffic between two hosts that only use `s1` (e.g. some paths between `h1`–`h3`) may **not** traverse `s2`; use **left-segment ↔ right-segment** pairs for firewall tests.

### Task 0 — Topology

| Step | Action | Expected |
|------|--------|----------|
| 1 | Start Mininet with `topology.py` / `topo.py` | CLI shows `mininet>` with no fatal errors |
| 2 | `pingall` | All hosts can ping each other (baseline) |

### Task 1 — L4 learning switches (`s1`, `s3`)

| Step | Action (at `mininet>`) | Expected |
|------|------------------------|----------|
| 1 | `h1 ping -c 3 10.0.0.4` | ICMP succeeds (crosses `s1` → `s2` → `s3`) |
| 2 | `h4 python3 -m http.server 8080 &` then `h1 curl -s -o /dev/null -w "%{http_code}\n" http://10.0.0.4:8080/` | HTTP `200` or successful TCP to **8080** (avoids conflict with firewall **TCP 80**) |
| 3 | (Optional) UDP: e.g. `h4 iperf -s -u -p 5001 &` and `h1 iperf -c 10.0.0.4 -u -p 5001 -t 5` if `iperf` is installed | UDP traffic completes |
| 4 | On the host: `sudo ovs-ofctl -O OpenFlow13 dump-flows s1` and `s3` | Flows show IPv4 and L4 fields (e.g. `eth_type=0x0800`, `ipv4_*`, `tcp_*` / `udp_*` / `icmp_*`), not only L2 flood |

### Task 2 — Firewall (`s2`, `rules.json`)

| Rule (summary) | Suggested test (cross-segment) | Expected |
|----------------|--------------------------------|----------|
| UDP/443 to `h5` | `h1 sh -c "echo test \| nc -u -w1 10.0.0.5 443"` | Dropped / no useful reply (compare with allowed cases) |
| TCP/80 through firewall | On `h4`: `python3 -m http.server 80` (if permitted); on `h1`: `curl --connect-timeout 2 http://10.0.0.4:80/` | Fails; compare with **:8080** success |
| ICMP echo **from** `h4` | `h4 ping -c 2 10.0.0.1` | Blocked vs other hosts’ ping |
| All IPv4 **to** `h3` | `h4 ping -c 2 10.0.0.3` (traverses `s2`) | Blocked |
| Default allow | e.g. `h1 ping -c 2 10.0.0.4`, or TCP not matching drop rules | Succeeds |

Check drops and L2 forward on `s2`:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s2
```

### Task 3 — Flow statistics

| Step | Action | Expected |
|------|--------|----------|
| 1 | Generate traffic (`ping`, `curl`, etc.) for several seconds | Controller log shows periodic **`[flow-stats]`** lines with packet/byte totals and sample `match` fields |

### Task 4 — SYN flood mitigation

| Step | Action | Expected |
|------|--------|----------|
| 1 | From a host or the VM, use `hping3` (or similar) to send many TCP SYNs to a target within the brief’s time window | Log warns on threshold and installs a **temporary drop** (e.g. ~60 s hard timeout) |
| 2 | After the timeout, retry `ping`/`curl` from that source | Traffic resumes |

Use **low intensity** and duration; stop after the demo.

### Task 5 — Integration

Run **Task 1 → 2 → 3 → 4** in one session with the same `controller.py` and topology.

### Command summary

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s2
sudo ovs-ofctl -O OpenFlow13 dump-flows s3
sudo mn -c
```

## Firewall rules (reference)

`rules.json` is configured for switch `s2` to **drop**:

- UDP destination port 443 to host `h5` (`10.0.0.5`) — QUIC-style match as specified.
- TCP destination port 80 (HTTP) for traffic through the firewall.
- ICMP echo requests (`type 8`) sourced from `h4` (`10.0.0.4`).
- All IPv4 to `h3` (`10.0.0.3`).

Other traffic is allowed by default (handled by L2 learning on `s2` plus higher-priority drop rules above).

## After everything is installed — checklist

1. **Versions**: `ryu-manager --version`, `mn --version`, `ovs-vsctl --version` respond without errors.
2. **Paths**: Run `ryu-manager` from the directory that contains `rules.json`, or set working directory accordingly.
3. **Controller first, then Mininet**, so switches register before heavy traffic.
4. **Run the full Testing procedure** (section *Testing procedure (Task 0–5)* above; Tasks 0–5).

## Cleanup

If Mininet exits uncleanly:

```bash
sudo mn -c
```

## License / course use

Provided for academic coursework; adapt only within your institution’s rules.

# Ryu-based SDN controller

OpenFlow 1.3 controller built with **Ryu**, tested with **Mininet** and **Open vSwitch**.  
Implements an integrated network application: Layer-4 learning switches on edge datapaths, a middle firewall driven by JSON rules, periodic flow statistics, and SYN-flood mitigation.

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

## Run (every lab session)

1. Open a terminal in the **same directory as `rules.json`** (relative path used by the app).
2. Start the controller:

   ```bash
   ryu-manager controller.py --verbose
   ```

3. Start the emulated network:

   ```bash
   sudo python3 topology.py
   ```

4. In the Mininet CLI, verify connectivity (e.g. `pingall`), then run scenario tests (HTTP, UDP 443, ICMP, `iperf`, etc.) as required by the brief.

5. Inspect dataplane rules when needed:

   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s1
   sudo ovs-ofctl -O OpenFlow13 dump-flows s2
   sudo ovs-ofctl -O OpenFlow13 dump-flows s3
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
4. **Functional tests**: `pingall`; blocked cases (e.g. `h4` → ping, HTTP across `s2`, QUIC-like UDP/443 to `h5`, traffic to `h3`); allowed cases that should still pass.
5. **Statistics**: Watch controller logs for periodic flow-stat summaries.
6. **SYN mitigation**: Use a controlled tool (e.g. `hping3` in the lab image) to exceed the SYN threshold and confirm temporary blocking, then recovery after the timeout.
7. **Submission**: Package `controller.py`, topology script(s), `rules.json`, and your short test plan as required by the module leader.

## Cleanup

If Mininet exits uncleanly:

```bash
sudo mn -c
```

## License / course use

Provided for academic coursework; adapt only within your institution’s rules.

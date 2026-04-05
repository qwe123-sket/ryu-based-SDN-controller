# SDN coursework — Ryu + Mininet

Integrated OpenFlow 1.3 controller (`controller.py`), Mininet topology, and firewall rules for a three-switch, six-host network.

## Contents

| File | Description |
|------|-------------|
| `controller.py` | Ryu application: L4 learning on edge switches, L2 + JSON rules on firewall switch, flow statistics, SYN flood mitigation |
| `topology.py` | Mininet topology and CLI entry |
| `topo.py` | Alternate entry that runs the same topology |
| `rules.json` | Firewall drop rules for datapath `0000000000000002` |
| `rules_template.json` | Example rule structure from the lab brief |

## Environment

Use the course VirtualBox image (Mininet, Ryu, Open vSwitch) or a comparable Linux setup. Mininet is not installed via pip; on Ubuntu:

```bash
sudo apt install mininet openvswitch-switch
```

Python dependencies:

```bash
pip install -r requirements.txt
```

## Run

Terminal 1 (from this directory, so `rules.json` is found):

```bash
ryu-manager controller.py --verbose
```

Terminal 2:

```bash
sudo python3 topology.py
```

If the controller runs on another address than `127.0.0.1`, edit `RemoteController` in `topology.py`.

## Note

Do not start Mininet with the `mn --mac` option for this assignment; host MACs should remain default.

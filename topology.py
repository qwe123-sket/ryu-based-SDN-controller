#!/usr/bin/env python3
"""
Task 0: Mininet topology — 3 switches (s1,s2,s3), 6 hosts (h1–h6), 10.0.0.1–10.0.0.6.
Layout: [h1,h2,h3] — s1 — s2 — s3 — [h4,h5,h6]
DPIDs 1,2,3 for controller logic. Do not rely on mn --mac; MACs stay default (random).
Run Ryu first:  ryu-manager controller.py
Then:          sudo python3 topology.py
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel


class CourseTopo(Topo):
    """Coursework topology with fixed IPs in 10.0.0.0/24."""

    def build(self):
        s1 = self.addSwitch("s1", dpid="0000000000000001")
        s2 = self.addSwitch("s2", dpid="0000000000000002")
        s3 = self.addSwitch("s3", dpid="0000000000000003")

        h1 = self.addHost("h1", ip="10.0.0.1/24")
        h2 = self.addHost("h2", ip="10.0.0.2/24")
        h3 = self.addHost("h3", ip="10.0.0.3/24")
        h4 = self.addHost("h4", ip="10.0.0.4/24")
        h5 = self.addHost("h5", ip="10.0.0.5/24")
        h6 = self.addHost("h6", ip="10.0.0.6/24")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(h4, s3)
        self.addLink(h5, s3)
        self.addLink(h6, s3)


def run():
    setLogLevel("info")
    topo = CourseTopo()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
        autoSetMacs=False,
        autoStaticArp=False,
    )
    net.start()
    CLI(net)
    net.stop()


if __name__ == "__main__":
    run()

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, tcp, udp, icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto as inet
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub

from threading import Thread, Lock
import os
import time
import json


class Controller(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    RULES_FILE = "rules.json"

    IP_FIELDS = ["ip_proto", "ipv4_src", "ipv4_dst"]
    ICMP_FIELDS = ["icmpv4_type", "icmpv4_code"]
    TCP_FIELDS = ["tcp_src", "tcp_dst"]
    UDP_FIELDS = ["udp_src", "udp_dst"]

    MAX_SYN = 20
    SYN_WINDOW_SEC = 10
    SYN_BLOCK_SEC = 60
    SYN_MUTEX = Lock()

    FLOW_PRIO_MISS = 0
    FLOW_PRIO_L2_FW = 20
    FLOW_PRIO_L4_SW = 15
    FLOW_PRIO_FW_DROP = 100
    FLOW_PRIO_SYN_BLOCK = 250

    STATS_INTERVAL = 5

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.parsed_rule_file = {}
        self.syn_track = {}
        self._stats_spawned = False

        try:
            self.parse_rules()
        except FileNotFoundError:
            self.logger.warning(
                "rules.json not found (cwd=%s); firewall drops skipped until file exists.",
                os.getcwd(),
            )
        except Exception as e:
            self.logger.warning("Failed to parse rules.json: %s", e)

        self.clean_thread = Thread(target=self.cleanup_syntrack, daemon=True)
        self.clean_thread.start()

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_features_request(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.install_entry_miss_mod(datapath)
        if datapath.id == 2:
            self.install_firewall_drops(datapath)

        if not self._stats_spawned:
            self._stats_spawned = True
            hub.spawn(self._stats_loop)

        self.logger.info("Datapath added DPID=%s", dpid_lib.dpid_to_str(datapath.id))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        in_port = ev.msg.match["in_port"]
        data = ev.msg.data
        buffer_id = ev.msg.buffer_id

        if dpid == 2:
            self.firewall(datapath, in_port, data, buffer_id)
        else:
            self.switch(datapath, in_port, data, buffer_id)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def handle_stats_response(self, ev):
        dp = ev.msg.datapath
        dpid = dpid_lib.dpid_to_str(dp.id)
        stats = ev.msg.body
        total_pkt = sum(s.packet_count for s in stats)
        total_byte = sum(s.byte_count for s in stats)
        self.logger.info(
            "[flow-stats] DPID=%s flows=%d total_pkts=%d total_bytes=%d",
            dpid,
            len(stats),
            total_pkt,
            total_byte,
        )
        for st in stats[:20]:
            self.logger.info(
                "  pkts=%d bytes=%d priority=%d match=%s",
                st.packet_count,
                st.byte_count,
                st.priority,
                st.match,
            )
        if len(stats) > 20:
            self.logger.info("  ... %d more flow(s) omitted", len(stats) - 20)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def install_flow_mod(
        self, datapath, priority, match, actions=None, i_timeout=60, h_timeout=0
    ):
        if actions is None:
            actions = []
        inst = [
            datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions
            )
        ]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=i_timeout,
            hard_timeout=h_timeout,
        )
        datapath.send_msg(mod)

    def install_entry_miss_mod(self, datapath):
        match = datapath.ofproto_parser.OFPMatch()
        actions = [
            datapath.ofproto_parser.OFPActionOutput(
                datapath.ofproto.OFPP_CONTROLLER,
                datapath.ofproto.OFPCML_NO_BUFFER,
            )
        ]
        self.install_flow_mod(
            datapath, self.FLOW_PRIO_MISS, match, actions, i_timeout=0, h_timeout=0
        )

    def send_packet_out(self, datapath, buffer_id, in_port, actions, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        bid = buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER
        data_out = None if bid != ofproto.OFP_NO_BUFFER else data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=bid,
            in_port=in_port,
            actions=actions,
            data=data_out,
        )
        datapath.send_msg(out)

    def add_l2_mapping(self, datapath_id, pkt, in_port):
        eth_header = pkt.get_protocol(ethernet.ethernet)
        if eth_header is None:
            return
        self.mac_to_port.setdefault(datapath_id, {})
        self.mac_to_port[datapath_id][eth_header.src] = in_port

    def use_l2_mapping(self, datapath, pkt):
        eth_header = pkt.get_protocol(ethernet.ethernet)
        out_port = datapath.ofproto.OFPP_FLOOD
        install = False
        m2p = self.mac_to_port.setdefault(datapath.id, {})
        if eth_header is not None and eth_header.dst in m2p:
            out_port = m2p[eth_header.dst]
            install = True
        return [datapath.ofproto_parser.OFPActionOutput(out_port)], install

    # ------------------------------------------------------------------
    # Task 1 / s1 & s3: L4 learning switch
    # ------------------------------------------------------------------

    def switch(self, datapath, in_port, data, buffer_id):
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        self.add_l2_mapping(datapath.id, pkt, in_port)
        if self.track_syn_if_needed(datapath, pkt):
            return

        actions, known_dst = self.use_l2_mapping(datapath, pkt)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            if known_dst:
                m = datapath.ofproto_parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_ARP, eth_dst=eth.dst
                )
                self.install_flow_mod(
                    datapath,
                    self.FLOW_PRIO_L4_SW,
                    m,
                    actions,
                    i_timeout=60,
                    h_timeout=0,
                )
            else:
                actions = [
                    datapath.ofproto_parser.OFPActionOutput(
                        datapath.ofproto.OFPP_FLOOD
                    )
                ]
            self.send_packet_out(datapath, buffer_id, in_port, actions, data)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            if known_dst:
                match = self.ofmatch_from_packet(datapath, pkt, in_port)
                self.install_flow_mod(
                    datapath,
                    self.FLOW_PRIO_L4_SW,
                    match,
                    actions,
                    i_timeout=60,
                    h_timeout=0,
                )
            else:
                actions = [
                    datapath.ofproto_parser.OFPActionOutput(
                        datapath.ofproto.OFPP_FLOOD
                    )
                ]
            self.send_packet_out(datapath, buffer_id, in_port, actions, data)
            return

        if known_dst:
            m = datapath.ofproto_parser.OFPMatch(eth_dst=eth.dst, eth_src=eth.src)
            self.install_flow_mod(
                datapath, self.FLOW_PRIO_L4_SW, m, actions, i_timeout=60, h_timeout=0
            )
        else:
            actions = [
                datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)
            ]
        self.send_packet_out(datapath, buffer_id, in_port, actions, data)

    def ofmatch_from_packet(self, datapath, pkt, in_port):
        match_dict = {"in_port": in_port}
        eth_h = pkt.get_protocol(ethernet.ethernet)
        match_dict["eth_type"] = eth_h.ethertype
        match_dict["eth_src"] = eth_h.src
        match_dict["eth_dst"] = eth_h.dst
        if eth_h.ethertype == ether_types.ETH_TYPE_IP:
            ip_h = pkt.get_protocol(ipv4.ipv4)
            match_dict["ip_proto"] = ip_h.proto
            match_dict["ipv4_src"] = ip_h.src
            match_dict["ipv4_dst"] = ip_h.dst
            if ip_h.proto == inet.IPPROTO_TCP:
                tcp_h = pkt.get_protocol(tcp.tcp)
                match_dict["tcp_src"] = tcp_h.src_port
                match_dict["tcp_dst"] = tcp_h.dst_port
            elif ip_h.proto == inet.IPPROTO_UDP:
                udp_h = pkt.get_protocol(udp.udp)
                match_dict["udp_src"] = udp_h.src_port
                match_dict["udp_dst"] = udp_h.dst_port
            elif ip_h.proto == inet.IPPROTO_ICMP:
                icmp_h = pkt.get_protocol(icmp.icmp)
                match_dict["icmpv4_type"] = icmp_h.type
                match_dict["icmpv4_code"] = icmp_h.code
        return datapath.ofproto_parser.OFPMatch(**match_dict)

    # ------------------------------------------------------------------
    # Task 2: Firewall on s2 (DPID 2) — drops from rules.json; allow = L2 only
    # ------------------------------------------------------------------

    def firewall(self, datapath, in_port, data, buffer_id):
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        self.add_l2_mapping(datapath.id, pkt, in_port)
        if self.track_syn_if_needed(datapath, pkt):
            self.logger.info("[FW] SYN-mitigation drop (no forward) DPID=2")
            return

        actions, known_dst = self.use_l2_mapping(datapath, pkt)
        if known_dst:
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_dst=eth.dst)
            self.install_flow_mod(
                datapath,
                self.FLOW_PRIO_L2_FW,
                match,
                actions,
                i_timeout=60,
                h_timeout=0,
            )
            self.logger.debug("[FW] allow L2 flow eth_dst=%s -> installed", eth.dst)
        else:
            actions = [
                datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)
            ]
        self.send_packet_out(datapath, buffer_id, in_port, actions, data)

    def parse_rules(self):
        path = self.RULES_FILE
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        self.parsed_rule_file = {}
        for dpid_str, entry in doc.get("datapath", {}).items():
            self.parsed_rule_file[dpid_str] = entry.get("rules", [])
        self.logger.info("Loaded rules for %d datapath(s)", len(self.parsed_rule_file))

    def ofmatch_from_dict(self, match_dict):
        fixed = {}
        for k, v in match_dict.items():
            if isinstance(v, str) and v.isdigit():
                fixed[k] = int(v)
            else:
                fixed[k] = v
        return OFPMatch(**fixed)

    def install_firewall_drops(self, datapath):
        dpid_str = dpid_lib.dpid_to_str(datapath.id)
        rules = self.parsed_rule_file.get(dpid_str, [])
        for rule in rules:
            match = self.ofmatch_from_dict(rule)
            self.install_flow_mod(
                datapath,
                self.FLOW_PRIO_FW_DROP,
                match,
                [],
                i_timeout=0,
                h_timeout=0,
            )
            self.logger.info("[FW] installed DROP prio=%s match=%s", self.FLOW_PRIO_FW_DROP, rule)

    # ------------------------------------------------------------------
    # Task 3: periodic flow stats
    # ------------------------------------------------------------------

    def _stats_loop(self):
        while True:
            hub.sleep(self.STATS_INTERVAL)
            for dp in list(self.datapaths.values()):
                self.request_flow_stats(dp, None)

    def request_flow_stats(self, datapath, ofmatch):
        parser = datapath.ofproto_parser
        if ofmatch is None:
            ofmatch = parser.OFPMatch()
        req = parser.OFPFlowStatsRequest(datapath=datapath, match=ofmatch, table_id=0)
        datapath.send_msg(req)

    # ------------------------------------------------------------------
    # Task 4: SYN flood — >20 SYN in 10s => drop all from src IP for 60s
    # ------------------------------------------------------------------

    def track_syn_if_needed(self, datapath, pkt):
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype != ether_types.ETH_TYPE_IP:
            return False
        ip_h = pkt.get_protocol(ipv4.ipv4)
        if ip_h is None or ip_h.proto != inet.IPPROTO_TCP:
            return False
        tcp_h = pkt.get_protocol(tcp.tcp)
        if tcp_h is None:
            return False
        if not (tcp_h.bits & tcp.TCP_SYN) or (tcp_h.bits & tcp.TCP_ACK):
            return False

        src_ip = ip_h.src
        now = time.time()
        with self.SYN_MUTEX:
            lst = self.syn_track.setdefault(src_ip, [])
            lst = [t for t in lst if now - t <= self.SYN_WINDOW_SEC]
            lst.append(now)
            self.syn_track[src_ip] = lst
            if len(lst) > self.MAX_SYN:
                self.logger.warning(
                    "[SYN] threshold exceeded src=%s count=%d in %ds — block %ds on DPID=%s",
                    src_ip,
                    len(lst),
                    self.SYN_WINDOW_SEC,
                    self.SYN_BLOCK_SEC,
                    datapath.id,
                )
                self.install_syn_block(datapath, src_ip)
                self.syn_track[src_ip] = []
                return True
        return False

    def install_syn_block(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        match_ip = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip
        )
        self.install_flow_mod(
            datapath,
            self.FLOW_PRIO_SYN_BLOCK,
            match_ip,
            [],
            i_timeout=0,
            h_timeout=self.SYN_BLOCK_SEC,
        )
        match_arp = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_ARP, arp_spa=src_ip
        )
        self.install_flow_mod(
            datapath,
            self.FLOW_PRIO_SYN_BLOCK,
            match_arp,
            [],
            i_timeout=0,
            h_timeout=self.SYN_BLOCK_SEC,
        )

    def cleanup_syntrack(self):
        while True:
            time.sleep(1.0)
            now = time.time()
            with self.SYN_MUTEX:
                empty = []
                for ip, times in list(self.syn_track.items()):
                    self.syn_track[ip] = [t for t in times if now - t <= self.SYN_WINDOW_SEC]
                    if not self.syn_track[ip]:
                        empty.append(ip)
                for ip in empty:
                    del self.syn_track[ip]

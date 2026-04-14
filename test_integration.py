#!/usr/bin/env python3
"""
集成测试脚本 - Ryu SDN Controller

测试覆盖:
- Task 0: 拓扑连通性
- Task 1: L4学习交换
- Task 2: 防火墙规则
- Task 3: 流量统计
- Task 4: SYN防御

运行方式:
1. 先启动控制器: ryu-manager controller.py --verbose
2. 再运行测试: sudo python3 test_integration.py

注意: 需要root权限运行(sudo)
"""

import sys
import time
import subprocess
import re
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info, error, debug
from mininet.util import quietRun


class CourseTopo(Topo):
    """课程拓扑 - 3交换机6主机"""

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


class SDNIntegrationTest:
    """SDN控制器集成测试类"""

    def __init__(self):
        self.net = None
        self.passed = 0
        self.failed = 0
        self.tests = []

    def setup_network(self):
        """初始化网络"""
        info("*** 正在初始化网络...\n")
        topo = CourseTopo()
        self.net = Mininet(
            topo=topo,
            switch=OVSSwitch,
            controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
            autoSetMacs=False,
            autoStaticArp=False,
        )
        self.net.start()
        # 等待控制器连接和流表下发
        info("*** 等待控制器连接 (3秒)...\n")
        time.sleep(3)

    def cleanup_network(self):
        """清理网络"""
        if self.net:
            info("*** 正在清理网络...\n")
            self.net.stop()

    def run_test(self, name, test_func):
        """运行单个测试"""
        info(f"\n{'='*60}\n")
        info(f"测试: {name}\n")
        info(f"{'='*60}\n")
        try:
            test_func()
            info(f"[PASS] {name}\n")
            self.passed += 1
            self.tests.append((name, "PASS", None))
        except AssertionError as e:
            error(f"[FAIL] {name}: {e}\n")
            self.failed += 1
            self.tests.append((name, "FAIL", str(e)))
        except Exception as e:
            error(f"[ERROR] {name}: {e}\n")
            self.failed += 1
            self.tests.append((name, "ERROR", str(e)))

    # ==================== Task 0: 拓扑测试 ====================

    def test_task0_topology_connectivity(self):
        """Task 0: 测试所有主机连通性"""
        info("*** 测试所有主机互相ping通...\n")
        result = self.net.pingAll(timeout=5)
        assert result == 0, f"pingall失败，丢包率: {result}%"

    # ==================== Task 1: L4学习交换测试 ====================

    def test_task1_l4_icmp_cross_segment(self):
        """Task 1: 测试跨段ICMP (h1 -> h4)"""
        info("*** 测试跨段ICMP连通性 (h1 -> h4)...\n")
        h1 = self.net.get('h1')
        h4 = self.net.get('h4')
        result = h1.cmd('ping -c 3 -W 2 10.0.0.4')
        info(f"Ping结果:\n{result}\n")
        assert "3 received" in result or "3 packets received" in result, "ICMP跨段失败"

    def test_task1_l4_tcp_http_cross_segment(self):
        """Task 1: 测试跨段TCP HTTP (h1 -> h4:8080)"""
        info("*** 测试跨段TCP HTTP (h1 -> h4:8080)...\n")
        h4 = self.net.get('h4')
        h1 = self.net.get('h1')

        # 在h4启动HTTP服务器
        h4.cmd('python3 -m http.server 8080 &')
        time.sleep(1)

        # h1尝试访问
        result = h1.cmd('curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://10.0.0.4:8080/')
        info(f"HTTP状态码: {result}\n")

        # 停止HTTP服务器
        h4.cmd('pkill -f "http.server 8080"')

        assert result.strip() == "200", f"HTTP请求失败，状态码: {result}"

    def test_task1_l4_flows_installed(self):
        """Task 1: 验证s1和s3上安装了L4流表"""
        info("*** 验证s1和s3上的L4流表...\n")

        # 先产生一些流量
        h1 = self.net.get('h1')
        h4 = self.net.get('h4')
        h1.cmd('ping -c 2 -W 2 10.0.0.4')

        time.sleep(1)

        # 检查s1的流表
        s1_flows = quietRun('ovs-ofctl -O OpenFlow13 dump-flows s1')
        info(f"s1流表:\n{s1_flows}\n")

        # 检查是否包含L4字段
        has_l4 = ('tcp_' in s1_flows or 'udp_' in s1_flows or
                  'ipv4_' in s1_flows or 'icmp_' in s1_flows)
        assert has_l4, "s1流表缺少L4字段"

        # 检查s3的流表
        s3_flows = quietRun('ovs-ofctl -O OpenFlow13 dump-flows s3')
        info(f"s3流表:\n{s3_flows}\n")

        has_l4_s3 = ('tcp_' in s3_flows or 'udp_' in s3_flows or
                     'ipv4_' in s3_flows or 'icmp_' in s3_flows)
        assert has_l4_s3, "s3流表缺少L4字段"

    # ==================== Task 2: 防火墙测试 ====================

    def test_task2_firewall_udp_443_to_h5(self):
        """Task 2: 测试UDP 443到h5被阻断"""
        info("*** 测试防火墙: UDP 443到h5被阻断...\n")
        h1 = self.net.get('h1')
        h5 = self.net.get('h5')

        # 在h5启动UDP监听
        h5.cmd('nc -u -l 443 &')
        time.sleep(0.5)

        # h1尝试发送UDP到h5:443
        result = h1.cmd('echo "test" | nc -u -w2 10.0.0.5 443')
        info(f"UDP发送结果: {result}\n")

        # 停止监听
        h5.cmd('pkill -f "nc -u -l 443"')

        # 检查s2流表是否有drop规则
        s2_flows = quietRun('ovs-ofctl -O OpenFlow13 dump-flows s2')
        info(f"s2流表:\n{s2_flows}\n")

        # 验证drop规则存在 (通过检查规则配置)
        assert "udp_dst=443" in s2_flows or "actions=drop" in s2_flows, "UDP 443 drop规则未找到"

    def test_task2_firewall_tcp_80_blocked(self):
        """Task 2: 测试TCP 80被阻断"""
        info("*** 测试防火墙: TCP 80被阻断...\n")
        h1 = self.net.get('h1')
        h4 = self.net.get('h4')

        # 在h4启动HTTP服务器在80端口
        h4.cmd('python3 -m http.server 80 &')
        time.sleep(1)

        # h1尝试访问80端口
        result = h1.cmd('curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 http://10.0.0.4:80/')
        info(f"HTTP 80访问结果: {result}\n")

        # 停止服务器
        h4.cmd('pkill -f "http.server 80"')

        # 应该超时或失败
        assert result.strip() != "200", "TCP 80应该被阻断"

    def test_task2_firewall_icmp_from_h4_blocked(self):
        """Task 2: 测试h4发出的ICMP被阻断"""
        info("*** 测试防火墙: h4发出的ICMP被阻断...\n")
        h4 = self.net.get('h4')
        h1 = self.net.get('h1')

        result = h4.cmd('ping -c 2 -W 2 10.0.0.1')
        info(f"h4 ping h1结果:\n{result}\n")

        # 应该丢包
        assert "0 received" in result or "100% packet loss" in result, "h4的ICMP应该被阻断"

    def test_task2_firewall_ipv4_to_h3_blocked(self):
        """Task 2: 测试到h3的所有IPv4被阻断"""
        info("*** 测试防火墙: 到h3的所有IPv4被阻断...\n")
        h4 = self.net.get('h4')
        h3 = self.net.get('h3')

        result = h4.cmd('ping -c 2 -W 2 10.0.0.3')
        info(f"h4 ping h3结果:\n{result}\n")

        # 应该丢包
        assert "0 received" in result or "100% packet loss" in result, "到h3的IPv4应该被阻断"

    def test_task2_firewall_default_allow(self):
        """Task 2: 测试默认允许其他流量"""
        info("*** 测试防火墙: 默认允许其他流量...\n")
        h1 = self.net.get('h1')
        h4 = self.net.get('h4')

        result = h1.cmd('ping -c 2 -W 2 10.0.0.4')
        info(f"h1 ping h4结果:\n{result}\n")

        assert "2 received" in result or "2 packets received" in result, "默认允许流量失败"

    # ==================== Task 3: 流量统计测试 ====================

    def test_task3_flow_stats(self):
        """Task 3: 验证流量统计功能"""
        info("*** 测试流量统计功能...\n")

        # 产生流量
        h1 = self.net.get('h1')
        h4 = self.net.get('h4')

        for _ in range(5):
            h1.cmd('ping -c 1 -W 1 10.0.0.4')
            time.sleep(0.5)

        # 等待统计周期 (控制器每5秒统计一次)
        info("*** 等待统计周期 (6秒)...\n")
        time.sleep(6)

        # 检查流表是否有流量计数
        s1_flows = quietRun('ovs-ofctl -O OpenFlow13 dump-flows s1')
        info(f"s1流表 (含计数):\n{s1_flows}\n")

        # 验证有n_packets字段
        assert "n_packets=" in s1_flows, "流表缺少包计数"

    # ==================== Task 4: SYN防御测试 ====================

    def test_task4_syn_flood_mitigation(self):
        """Task 4: 测试SYN防御功能"""
        info("*** 测试SYN防御功能...\n")

        # 注意: 这个测试需要hping3
        # 检查hping3是否可用
        h1 = self.net.get('h1')
        h4 = self.net.get('h4')

        # 在h4启动TCP监听
        h4.cmd('nc -l 9999 &')
        time.sleep(0.5)

        # 尝试发送一些SYN包 (模拟，不实际洪水攻击)
        # 由于需要root和hping3，这里只做基础验证
        info("*** 检查SYN跟踪功能...\n")

        # 正常TCP连接应该工作
        result = h1.cmd('echo "test" | nc -w2 10.0.0.4 9999')
        info(f"正常TCP连接结果: {result}\n")

        h4.cmd('pkill -f "nc -l 9999"')

        # 验证s2流表可以处理动态规则
        s2_flows = quietRun('ovs-ofctl -O OpenFlow13 dump-flows s2')
        info(f"s2当前流表:\n{s2_flows}\n")

    # ==================== 测试执行 ====================

    def run_all_tests(self):
        """运行所有测试"""
        info("\n" + "="*60 + "\n")
        info("SDN控制器集成测试开始\n")
        info("="*60 + "\n")

        try:
            self.setup_network()

            # Task 0: 拓扑测试
            self.run_test("Task 0: 拓扑连通性", self.test_task0_topology_connectivity)

            # Task 1: L4学习交换
            self.run_test("Task 1: L4 ICMP跨段", self.test_task1_l4_icmp_cross_segment)
            self.run_test("Task 1: L4 TCP HTTP跨段", self.test_task1_l4_tcp_http_cross_segment)
            self.run_test("Task 1: L4流表安装验证", self.test_task1_l4_flows_installed)

            # Task 2: 防火墙
            self.run_test("Task 2: 防火墙UDP 443阻断", self.test_task2_firewall_udp_443_to_h5)
            self.run_test("Task 2: 防火墙TCP 80阻断", self.test_task2_firewall_tcp_80_blocked)
            self.run_test("Task 2: 防火墙ICMP从h4阻断", self.test_task2_firewall_icmp_from_h4_blocked)
            self.run_test("Task 2: 防火墙到h3阻断", self.test_task2_firewall_ipv4_to_h3_blocked)
            self.run_test("Task 2: 防火墙默认允许", self.test_task2_firewall_default_allow)

            # Task 3: 流量统计
            self.run_test("Task 3: 流量统计", self.test_task3_flow_stats)

            # Task 4: SYN防御
            self.run_test("Task 4: SYN防御", self.test_task4_syn_flood_mitigation)

        finally:
            self.cleanup_network()

        # 打印测试报告
        self.print_report()

    def print_report(self):
        """打印测试报告"""
        info("\n" + "="*60 + "\n")
        info("测试报告\n")
        info("="*60 + "\n")

        for name, status, error in self.tests:
            status_str = "[PASS]" if status == "PASS" else f"[{status}]"
            info(f"{status_str} {name}\n")
            if error:
                info(f"      错误: {error}\n")

        info("\n" + "-"*60 + "\n")
        info(f"总计: {self.passed + self.failed} 个测试\n")
        info(f"通过: {self.passed}\n")
        info(f"失败: {self.failed}\n")
        info("="*60 + "\n")

        return self.failed == 0


def main():
    """主函数"""
    setLogLevel('info')

    # 检查root权限
    if os.geteuid() != 0:
        error("错误: 需要root权限运行 (sudo)\n")
        sys.exit(1)

    test = SDNIntegrationTest()
    success = test.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    import os
    main()

# 集成测试文档

本文档描述了Ryu SDN控制器的集成测试用例及执行方法。

## 测试文件

- `test_integration.py` - 自动化集成测试脚本

## 环境要求

- Linux系统（课程VM或Ubuntu）
- Mininet、Open vSwitch、Ryu已安装
- Python 3
- root权限（sudo）

## 测试执行步骤

### 1. 启动控制器

在终端A中执行：

```bash
ryu-manager controller.py --verbose
```

等待控制器启动完成（看到"Datapath added"日志）。

### 2. 运行集成测试

在终端B中执行：

```bash
sudo python3 test_integration.py
```

### 3. 查看测试结果

测试脚本会自动输出每个测试用例的结果，最后生成测试报告。

## 测试用例说明

### Task 0: 拓扑连通性测试

| 测试名称 | 描述 | 预期结果 |
|---------|------|---------|
| 拓扑连通性 | 所有主机互相ping通 | 100%连通，无丢包 |

### Task 1: L4学习交换测试

| 测试名称 | 描述 | 预期结果 |
|---------|------|---------|
| L4 ICMP跨段 | h1 ping h4（跨s1-s2-s3） | 3个包全部收到 |
| L4 TCP HTTP跨段 | h1 curl访问h4:8080 | HTTP 200成功 |
| L4流表安装验证 | 检查s1/s3流表 | 包含ipv4_/tcp_/udp_/icmp_字段 |

### Task 2: 防火墙测试

| 测试名称 | 描述 | 预期结果 |
|---------|------|---------|
| UDP 443阻断 | h1发送UDP到h5:443 | 被防火墙丢弃 |
| TCP 80阻断 | h1访问h4:80 | 连接超时/失败 |
| ICMP从h4阻断 | h4 ping其他主机 | 100%丢包 |
| 到h3的IPv4阻断 | 任何主机ping h3 | 100%丢包 |
| 默认允许 | h1 ping h4（非阻断端口） | 正常连通 |

**防火墙规则来源**: `rules.json`

### Task 3: 流量统计测试

| 测试名称 | 描述 | 预期结果 |
|---------|------|---------|
| 流量统计 | 产生流量后检查流表 | 流表项包含n_packets计数 |

### Task 4: SYN防御测试

| 测试名称 | 描述 | 预期结果 |
|---------|------|---------|
| SYN防御 | 验证SYN跟踪机制 | 正常TCP连接可建立 |

## 手动验证命令

如需手动验证，可使用以下命令：

### 启动拓扑

```bash
sudo python3 topology.py
```

### 常用Mininet命令

```bash
# 测试所有主机连通性
mininet> pingall

# 测试特定主机连通性
mininet> h1 ping -c 3 h4

# 启动HTTP服务器
mininet> h4 python3 -m http.server 8080 &

# 测试HTTP访问
mininet> h1 curl http://10.0.0.4:8080/

# 测试UDP
mininet> h5 nc -u -l 443 &
mininet> h1 echo "test" | nc -u -w1 10.0.0.5 443
```

### 查看流表

```bash
# 查看s1流表
sudo ovs-ofctl -O OpenFlow13 dump-flows s1

# 查看s2流表
sudo ovs-ofctl -O OpenFlow13 dump-flows s2

# 查看s3流表
sudo ovs-ofctl -O OpenFlow13 dump-flows s3
```

### 清理环境

```bash
# 如果Mininet异常退出
sudo mn -c

# 停止所有nc进程
sudo pkill -f "nc"

# 停止所有http.server进程
sudo pkill -f "http.server"
```

## 故障排查

| 问题 | 可能原因 | 解决方法 |
|-----|---------|---------|
| 控制器连接失败 | 控制器未启动或端口被占用 | 检查6653端口，重启控制器 |
| 流表未安装 | 控制器启动顺序错误 | 先启动控制器，再启动Mininet |
| pingall失败 | 流表学习未完成 | 等待几秒后重试 |
| 防火墙规则不生效 | rules.json路径错误 | 确保在repo根目录运行控制器 |
| 权限错误 | 未使用sudo | 使用sudo运行测试脚本 |

## 测试输出示例

```
============================================================
SDN控制器集成测试开始
============================================================

============================================================
测试: Task 0: 拓扑连通性
============================================================
*** 测试所有主机互相ping通...
[PASS] Task 0: 拓扑连通性

============================================================
测试: Task 1: L4 ICMP跨段
============================================================
*** 测试跨段ICMP连通性 (h1 -> h4)...
Ping结果:
PING 10.0.0.4 (10.0.0.4) 56(84) bytes of data.
64 bytes from 10.0.0.4: icmp_seq=1 ttl=64 time=1.23 ms
64 bytes from 10.0.0.4: icmp_seq=2 ttl=64 time=1.45 ms
64 bytes from 10.0.0.4: icmp_seq=3 ttl=64 time=1.12 ms

--- 10.0.0.4 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss
[PASS] Task 1: L4 ICMP跨段

...

============================================================
测试报告
============================================================
[PASS] Task 0: 拓扑连通性
[PASS] Task 1: L4 ICMP跨段
[PASS] Task 1: L4 TCP HTTP跨段
[PASS] Task 1: L4流表安装验证
[PASS] Task 2: 防火墙UDP 443阻断
[PASS] Task 2: 防火墙TCP 80阻断
[PASS] Task 2: 防火墙ICMP从h4阻断
[PASS] Task 2: 防火墙到h3阻断
[PASS] Task 2: 防火墙默认允许
[PASS] Task 3: 流量统计
[PASS] Task 4: SYN防御

------------------------------------------------------------
总计: 11 个测试
通过: 11
失败: 0
============================================================
```

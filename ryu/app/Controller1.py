from ryu.ofproto import ofproto_v1_0,ofproto_v1_3
from operator import attrgetter
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER,CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import simple_switch_13
from ryu.lib import hub
from ryu.base import app_manager
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib import stringify
from ryu.lib.mac import haddr_to_bin
import struct
import time
import socket
import threading
import SocketServer
import subprocess
import logging


TCP_OPTION_KIND_TIMESTAMPS = 8            # 时间戳
TCP_OPTION_KIND_USER_TIMEOUT = 28         # 用户超时option
class IsSynFlooding():
    while True:
        if timeme.total >= TCP_OPTION_KIND_USER_TIMEOUT:
            break

        else:
            add_flow(self, datapath, in_port, dst, actions)#超时则报错，认为是synflooding攻击，否则将其添加到openflow的flow entry中

            def add_flow(self, datapath, in_port, dst, actions):#添加流表功能
                ofproto = datapath.ofproto

                match = datapath.ofproto_parser.OFPMatch(
                    in_port=in_port, dl_dst=haddr_to_bin(dst))

                mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath, match=match, cookie=0,
                    command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                    priority=ofproto.OFP_DEFAULT_PRIORITY,
                    flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
                datapath.send_msg(mod)

class TcpSynFloodingDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

class TCPOption(stringify.StringifyMixin):
    _KINDS = {}
    _KIND_PACK_STR = '!B'  # kind
    NO_BODY_OFFSET = 1     # kind(1 byte)
    WITH_BODY_OFFSET = 2   # kind(1 byte) + length(1 byte)
    cls_kind = None
    cls_length = None

    def __init__(self,src_port=1, dst_port=1, seq=0, ack=0, offset=0,
                 bits=0, window_size=0, csum=0, urgent=0, option=None):
        super(TcpSynFloodingDetector,self).__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.offset = offset
        self.bits = bits
        self.window_size = window_size
        self.csum = csum
        self.urgent = urgent
        self.option = option

    def has_flags(self,*flags):
        pkt = tcp.tcp(bits=(tcp.TCP_SYN))
        pkt.has_flags(tcp.TCP_SYN)

@TCPOption.register(TCP_OPTION_KIND_USER_TIMEOUT, 4)#定义tcp握手的TIMEOUT，用来判断超时
class TCPOptionUserTimeout(TCPOption):
    _PACK_STR = '!BBH'  # kind, length, granularity(1bit)|user_timeout(15bit)

    def __init__(self, granularity, user_timeout, kind=None, length=None):
        super(TCPOptionUserTimeout, self).__init__(kind, length)
        self.granularity = granularity
        self.user_timeout = user_timeout

    @classmethod
    def parse(cls, buf):
        (_, _, body) = struct.unpack_from(cls._PACK_STR, buf)
        granularity = body >> 15
        user_timeout = body & 0x7fff
        return cls(granularity, user_timeout,
                   cls.cls_kind, cls.cls_length), buf[cls.cls_length:]

    def serialize(self):
        body = (self.granularity << 15) | self.user_timeout
        return struct.pack(self._PACK_STR, self.kind, self.length, body)

class timeme(object):/#计时器，用来判断等待客户端回复ack的时间
        __unitfactor = {'s': 1,
                        'ms': 1000,
                        'us': 1000000}

        def __init__(self, unit='s', precision=4):
            self.start = None
            self.end = None
            self.total = 0
            self.unit = unit
            self.precision = precision

        def __enter__(self):
            if self.unit not in timeme.__unitfactor:
                raise KeyError('Unsupported time unit.')
            self.start = time.time()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.end = time.time()
            self.total = (self.end - self.start) * timeme.__unitfactor[self.unit]
            self.total = round(self.total, self.precision)

        def __str__(self):
            return 'Running time is {0}'.format(self.total)

class arp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(arp,self).__init__(*args, **kwargs)
        self.mac_to_ipv4 = {}   #定义 mac_to_ipv4 ,MAC地址绑定到IP地址
        self.ipv4_to_mac = {}   #定义ipv4_to_mac ,Ip地址绑定到mac地址
        self.mac_to_port = {}   #定义mac_to_port
    #事件接收
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)   #将空匹配的数据包传递给控制器
#定义流表
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = [parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)]
        datapath.send_msg(mod)
    #事件接收
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg            #储存对应事件的openflow消息类别的实体
        datapath = msg.datapath     #储存openflow交换器的#ryu.ofproto.controller.controller.Datapath类别所对应的实体
        ofproto = datapath.ofproto   #ofproto 模块
        parser = datapath.ofproto_parser    #ofproto_parser 模块
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        in_port = msg.match['in_port']
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port   #加 mac_to_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]  #确定数据包转发端口
        data = None
        if msg.buffer_id == ofproto.OFPCML_NO_BUFFER:
            data = msg.data
        #OFPPacketOut 讯息
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port,actions=actions,data=data)
        #判断是否是 Ethernet 数据包
        if not eth :
            return
        if eth.ethertype == '0x0806':    #arp 数据包
            pkt_arp = pkt.get_protocol(arp.arp)
            ip_src = pkt_arp.src_ip
            mac_src = pkt_arp.src_mac
            #mac地址与ip地址绑定
            if (self.mac_to_ipv4.has_key(self.mac_to_ipv4[dpid][mac_src])==False) :
                if(self.ipv4_to_mac.has_key(self.ipv4_to_mac[dpid][ip_src])==False) :
                    self.mac_to_ipv4.setdefault(dpid, {})
                    self.logger.info("%s %s %s", dpid, mac_src, ip_src)
                    self.mac_to_ipv4[dpid][mac_src] = ip_src
                    self.ipv4_to_mac.setdefault(dpid, {})
                    self.logger.info("%s %s %s", dpid, ip_src, mac_src)
                    self.ipv4_to_mac[dpid][ip_src] = mac_src
            if pkt_arp.opcode == arp.ARP_REQUEST :
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port,eth_dst=dst,eth_src=src,arp_spa=ip_src)
                    self.add_flow(datapath, 1, match, actions)
                datapath.send_msg(out)    #发送openflow 讯息
            elif pkt_arp.opcode == arp.ARP_REPLY :
                if(self.mac_to_ipv4[dpid][mac_src]==ip_src) :  #如果表中匹配，则发送openflow消息并下发流表
                    match = parser.OFPMatch(in_port=in_port,eth_dst=dst,eth_src=src,arp_spa=ip_src)
                    self.add_flow(datapath, 1, match, actions)
                    datapath.send_msg(out)
                else :    #判断是arp攻击数据包
                    return  #不发送openflow消息也不下发流表
        else :  #判断不是 Ethernet 数据包则不操作
            return

#日志信息
logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(logging.INFO)
logging.getLogger("ofp_event").setLevel(logging.WARNING)


# 收到请求后上传给controller
# which handles the request
class RequestHandler(SocketServer.BaseRequestHandler):
    # Set to the handle method in the controller thread
    handler = None

    def handle(self):
        data = self.request.recv(1024)
        RequestHandler.handler(data)


# 服务器为新的请求创建线程
class Server(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


#客户端发送请求
class Client:
    # Initialize with IP + Port of server
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    # 为发送行为创建线程
    def send(self, message):
        def do():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, self.port))
            try:
                sock.sendall(message)
                response = sock.recv(1024)
            finally:
                sock.close()

        thread = threading.Thread(target=do)
        thread.daemon = True
        thread.start()


# 继承给出的simple_switch_13
class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    # 轮询间隔
    QUERY_INTERVAL = 2
    # 攻击带宽阈值（Kbit/s）
    ATTACK_THRESHOLD = 4000
    # 安全带宽阈值（Kbit/s）
    PEACE_THRESHOLD = 10
    # 攻击持续数
    SUSTAINED_COUNT = 5
    # 攻击者判定阈值（Kbit/s）
    ATTACKER_THRESHOLD = 1000
    # 是否报告数据
    REPORT_STATS = True

    def __init__(self, *args, **kwargs):
        # 流量监控
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        # 设定已知攻击者
        self.attackers = set()
        self.sustainedAttacks, self.sustainedPushbackRequests = 0, 0
        # 默认所有交换机端口不实行入栈流量策略
        self.ingressApplied = {"s1": [False, False, False],
                               "s11": [False, False, False],
                               "s12": [False, False, False],}

        self.noAttackCounts = {"s1": [0] * 3,
                               "s11": [0] * 3,
                               "s12": [0] * 3,}

        self.rates = {"s1": [{}, {}, {}],
                      "s11": [{}, {}, {}],
                      "s12": [{}, {}, {}],}

        # 端口映射
        self.portMaps = {"s1": ["s11", "s12", "s2"],
                         "s11": ["AAh1", "AAh2", "s1"],
                         "s12": ["ABh1", "ABh2", "s1"],}

        # datapath_ID映射
        self.dpids = {0x1: "s1",
                      0xb: "s11",
                      0xc: "s12",}

        # OpenFlow datapaths标识
        self.datapaths = {}
        # 流量带宽计数
        self.flow_byte_counts = {}
        # 端口流量计数
        self.port_byte_counts = {}
        # 监控进程
        self.monitor_thread = hub.spawn(self._monitor)

        # 被攻击的主机
        self.pushbacks = set()
        self.other_victims = set()

        #服务器端

        # 锁定受害者
        self.lock = threading.Lock()
        # cotroller端服务器IP+端口号
        ip, port = "localhost", 2000
        # 另一个cotroller端服务器IP+端口号
        ip_other, port_other = "localhost", 2001

        # RequestHandler
        RequestHandler.handler = self.handlePushbackMessage

        self.server = Server((ip, port), RequestHandler)

        #初始化服务器线程
        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        self.client = Client(ip_other, port_other)

    # 延迟管控Handler
    def handlePushbackMessage(self, data):
        victim = data.strip()[len("Pushback attack to "):]
        print("Received pushback message for victim: %s" % victim)
        # Avoid race conditions for pushback messages
        self.lock.acquire()
        try:
            self.other_victims.add(victim)
        finally:
            self.lock.release()

    #流量监管模块

    # 用修饰器实现新的注册监听datapath Handler
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    # QUERY_INTERVAL线程监控
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(SimpleMonitor.QUERY_INTERVAL)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        domainHosts = ['0a:0a:00:00:00:01', '0a:0a:00:00:00:02', '0a:0b:00:00:00:01', '0a:0b:00:00:00:02']

        # 鉴定出的受害者集合
        victims = set()

        body = ev.msg.body
        dpid = int(ev.msg.datapath.id)
        switch = self.dpids[dpid]

        if SimpleMonitor.REPORT_STATS:
            print "-------------- Flow stats for switch", switch, "---------------"

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            in_port = stat.match['in_port']
            out_port = stat.instructions[0].actions[0].port
            eth_dst = stat.match['eth_dst']

            key = (dpid, in_port, eth_dst, out_port)
            rate = 0
            if key in self.flow_byte_counts:
                cnt = self.flow_byte_counts[key]
                rate = self.bitrate(stat.byte_count - cnt)
            self.flow_byte_counts[key] = stat.byte_count
            if SimpleMonitor.REPORT_STATS:
                print "In Port %8x Eth Dst %17s Out Port %8x Bitrate %f" % (in_port, eth_dst, out_port, rate)

            # 存储流计算结果
            self.rates[switch][in_port - 1][str(eth_dst)] = rate

            # 标记高带宽的主机
            if rate > SimpleMonitor.ATTACK_THRESHOLD:
                self.noAttackCounts[switch][in_port - 1] = 0
                victim = str(eth_dst)
                if victim in domainHosts:
                    victims.add(victim)

        for port in range(len(self.ingressApplied[switch])):
            if not self.ingressApplied[switch][port]:
                continue

            if all(x <= SimpleMonitor.PEACE_THRESHOLD for x in self.rates[switch][port].values()):
                self.noAttackCounts[switch][port] += 1
            else:
                self.noAttackCounts[switch][port] = 0

        victims = victims.intersection({'0a:0a:00:00:00:01', '0a:0a:00:00:00:02'})

        self.dealWithPushbackRequests()

        pushbacks = self.dealWithAttackers(victims)

        if pushbacks == self.pushbacks and len(pushbacks) > 0:  # Send pushback messages
            self.sustainedPushbackRequests += 1
            logging.debug("Sustained Pushback Count %s" % str(self.sustainedPushbackRequests))
            if self.sustainedPushbackRequests > SimpleMonitor.SUSTAINED_COUNT:
                for victim in pushbacks:
                    self.client.send("Pushback attack to " + victim)
                self.sustainedPushbackRequests = 0
        elif len(pushbacks) > 0:
            self.sustainedPushbackRequests = 0
            self.pushbacks = pushbacks

        self.checkForIngressRemoval(
            victims)

        if SimpleMonitor.REPORT_STATS:
            print "--------------------------------------------------------"

    # 处理另一个domain内controller的pushback请求
    def dealWithPushbackRequests(self):
        victims = set()
        self.lock.acquire()
        try:
            victims = self.other_victims
            self.other_victims = set()
        finally:
            self.lock.release()

        for victim in victims:
            victimAttackers = self.getAttackers(victim)
            print("Responding to pushback request, applying ingress on %s to relieve %s" % (victimAttackers, victim))
            for attacker in victimAttackers:
                self.applyIngress(attacker)

    # 标记受害者集合并处理域外攻击
    def dealWithAttackers(self, victims):
        pushbacks = set()
        attackers = set()
        for victim in victims:
            victimHost, victimSwitch, victimPort = self.getVictim(victim)
            print(
            "Identified victim: MAC %s Host %s Switch %s Port %s" % (victim, victimHost, victimSwitch, victimPort))
            victimAttackers = self.getAttackers(victim)
            print("Attackers for vicim %s: %s" % (victimAttackers, victimHost))
            if not victimAttackers:
                pushbacks.add(victim)
            else:
                attackers = attackers.union(victimAttackers)

        if attackers:
            self.sustainedAttacks += 1
            logging.debug("Sustained Attack Count %s" % (self.sustainedAttacks / 3))
        else:
            self.sustainedAttacks = 0

        if self.sustainedAttacks / 3 > SimpleMonitor.SUSTAINED_COUNT:
            for attacker in attackers:
                self.applyIngress(attacker)

        return pushbacks

    # 检查入栈流量策略是否需要移除
    def checkForIngressRemoval(self, victims):
        for switch in self.ingressApplied:
            for port in range(len(self.ingressApplied[switch])):
                if self.noAttackCounts[switch][port] >= self.SUSTAINED_COUNT and self.ingressApplied[switch][port]:
                    self.removeIngress(self.portMaps[switch][port])

    # 对标记出的攻击者实施策略
    def applyIngress(self, attacker, shouldApply=True):
        attackerSwitch, attackerPort = self.getSwitch(attacker)
        if self.ingressApplied[attackerSwitch][int(attackerPort) - 1] == shouldApply:
            return

        ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=0", "ingress_policing_rate=0"
        if shouldApply:
            self.noAttackCounts[attackerSwitch][int(attackerPort) - 1] = 0
            print("Applying ingress filters on %s, on switch %s at port %s" % (attacker, attackerSwitch, attackerPort))
            ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=100", "ingress_policing_rate=40"
        else:
            print("Removing ingress filters on %s, on switch %s at port %s" % (attacker, attackerSwitch, attackerPort))

        subprocess.call(
            ["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingBurst])
        subprocess.call(
            ["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingRate])
        self.ingressApplied[attackerSwitch][int(attackerPort) - 1] = shouldApply

    # 移除入栈策略
    def removeIngress(self, attacker):
        self.applyIngress(attacker, False)

    # 返回被攻击主机的连接信息
    def getVictim(self, victim):
        victimHost = victim[1].upper() + victim[4].upper() + "h" + victim[16]
        for switch in self.portMaps:
            for port in range(len(self.portMaps[switch])):
                if self.portMaps[switch][port] == victimHost:
                    return victimHost, switch, str(port + 1)

    # 返回攻击者信息
    def getAttackers(self, victim):
        attackers = set()
        for switch in self.rates:
            for port in range(len(self.rates[switch])):
                if victim not in self.rates[switch][port]:
                    continue
                if self.rates[switch][port][victim] > SimpleMonitor.ATTACKER_THRESHOLD:
                    attacker = self.portMaps[switch][port]
                    if not self.isSwitch(attacker):
                        attackers.add(attacker)
        return attackers

    @staticmethod
    def isSwitch(victim):
        return victim[0] == "s"

    def getSwitch(self, node):
        for switch in self.portMaps:
            if node in self.portMaps[switch]:
                return switch, str(self.portMaps[switch].index(node) + 1)

    @staticmethod
    def bitrate(bytes):
        return bytes * 8.0 / (SimpleMonitor.QUERY_INTERVAL * 1000)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            key = (ev.msg.datapath.id, stat.port_no)

            rx_bitrate, tx_bitrate = 0, 0
            if key in self.port_byte_counts:
                cnt1, cnt2 = self.port_byte_counts[key]
                rx_bitrate = self.bitrate(stat.rx_bytes - cnt1)
                tx_bitrate = self.bitrate(stat.tx_bytes - cnt2)
            self.port_byte_counts[key] = (stat.rx_bytes, stat.tx_bytes)

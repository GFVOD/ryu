from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp

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
                if(self.mac_to_ipv4[dpid][mac_src]==ip_src) :  #如果表中匹
#配，则发送openflow消息并下发流表
                    match = parser.OFPMatch(in_port=in_port,eth_dst=dst,eth_src=src,arp_spa=ip_src)
                    self.add_flow(datapath, 1, match, actions)
                    datapath.send_msg(out)
                else :    #判断是arp攻击数据包
                    return  #不发送openflow消息也不下发流表
        else :  #判断不是 Ethernet 数据包则不操作
            return

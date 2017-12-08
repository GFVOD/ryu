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
        self.mac_to_ipv4 = {}
        self.ipv4_to_mac = {}
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = [parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)]
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        in_port = msg.match['in_port']
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info ("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        data = None
        if msg.buffer_id == ofproto.OFPCML_NO_BUFFER:
            data = msg.data
        out = parser.OFPActionOutput(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port,actions=actions,data=data)
        if not eth :
            return
        if eth.ethertype == '0x0806':
            pkt_arp = pkt.get_protocol(arp.arp)
            ip_src = pkt_arp.src_ip
            mac_src = pkt_arp.src_mac
            if (self.mac_to_ipv4.has_key(self.mac_to_ipv4[dpid][mac_src])==False) :
                if(self.ipv4_to_mac.has_key(self.ipv4_to_mac[dpid][ip_src])==False) :
                    self.mac_to_ipv4.setdefault(dpid, {})
                    self.logger.info ("%s %s %s", dpid, mac_src, ip_src)
                    self.mac_to_ipv4[dpid][mac_src] = ip_src
                    self.ipv4_to_mac.setdefault(dpid, {})
                    self.logger.info ("%s %s %s", dpid, ip_src, mac_src)
                    self.ipv4_to_mac[dpid][ip_src] = mac_src
            if pkt_arp.opcode == arp.ARP_REQUEST :
                datapath.send_msg(out)
            elif pkt_arp.opcode == arp.ARP_REPLY :
                if(self.mac_to_ipv4[dpid][mac_src]==ip_src) :
                    match = parser.OFPMatch(in_port=in_port,eth_dst=dst,eth_src=src,arp_spa=ip_src)
                    self.add_flow(datapath, 1, match, actions)
                else :
                    return
        else :
            return

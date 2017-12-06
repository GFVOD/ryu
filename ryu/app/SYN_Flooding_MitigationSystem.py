from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
import socket
import struct
import time


class TcpSynFloodingDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

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
        if tcp.TCP_SYN == 0x002 and








'''def detectTCPSynFlooding(pcapRecords, thresholdPercentage, windowSize):
    instances = 0
    for index, record in enumerate(pcapRecords):
        if isTCPSynPacket(record.protocol, record.info):
            instances = instances + checkWindowFrame(index, pcapRecords, windowSize, thresholdPercentage)
    print '\nTCP SYN Flooding Instances = ' + str(instances)


# Check how many TCP SYN Packets are sent within the WindowSize.
def checkWindowFrame(index, pcapRecords, windowSize, thresholdPercentage):
    windowStart = index + 1
    countInWindow = 0
    while windowStart < index + windowSize and windowStart < len(pcapRecords):
        if isTCPSynPacket(pcapRecords[windowStart].protocol, pcapRecords[windowStart].info):
            countInWindow = countInWindow + 1
        windowStart = windowStart + 1
    if (countInWindow * 100 / windowSize) >= thresholdPercentage and index + windowSize < len(pcapRecords):
        print 'Detected TCP SYN Flooding between ' + str(pcapRecords[index].timestamp) + ' and ' + str(
            pcapRecords[index + windowSize].timestamp) + ': ' + str(countInWindow * 100 / windowSize) + '%'
        return 1
    return 0


# Check if the current packet contributes to the TCP SYN Flooding
def isTCPSynPacket(protocol, info):
    return protocol == 'TCP' and all(partialDetector in info for partialDetector in ['Len=0', 'Seq=0']) and any(
        partialDetector in info for partialDetector in ['[SYN]', '[SYN, ACK]'])'''

from ryu.lib.packet import tcp
from ryu.lib import stringify
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
import struct
import time
from ryu.lib.packet import packet

TCP_OPTION_KIND_TIMESTAMPS = 8            # Timestamps
TCP_OPTION_KIND_USER_TIMEOUT = 28         # User Timeout Option
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



















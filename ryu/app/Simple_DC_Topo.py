from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange, dumpNodeConnections
from mininet.log import setLogLevel


class CustomTopo(Topo):

    def __init__(self, linkopts1, linkopts2, linkopts3, fanout=2, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        # Add your logic here ...
        self.fanout = fanout
        core = self.addSwitch('c1')
        for i in irange(1, fanout):
            aggregation = self.addSwitch('a%s' % i)
            self.addLink(core, aggregation, **linkopts1)
            for j in irange(1, fanout):
                edge = self.addSwitch('e%s' % (fanout * (i - 1) + j))
                self.addLink(aggregation, edge, **linkopts2)
                for k in irange(1, fanout):
                    host = self.addHost('h%s' % ((fanout * (fanout * (i - 1) + j - 1)) + k))
                    self.addLink(edge, host, **linkopts3)


topos = {'custom': (lambda: CustomTopo())}




if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
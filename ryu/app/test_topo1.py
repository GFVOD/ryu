
from mininet.topo import Topo


class MyTopo(Topo):
    "Simple loop topology example."

    def __init__(self):
        "Create custom loop topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        #host4 = self.addHost('h4')
        switch1 = self.addSwitch("s1")
        switch2 = self.addSwitch("s2")
        switch3 = self.addSwitch("s3")
        switch4 = self.addSwitch("s4")

        # Add links
        self.addLink(switch1, host1, 1)
        self.addLink(switch1, switch2, 2, 1)
        self.addLink(switch1, switch3, 3, 1)
        self.addLink(switch2, switch4, 2, 1)
        self.addLink(switch3, switch4, 2, 2)
        self.addLink(switch4, host2, 3)
        self.addLink(switch4, host3, 4)
        #self.addLink(switch3, host4, 3)


topos = {'mytopo': (lambda: MyTopo())}
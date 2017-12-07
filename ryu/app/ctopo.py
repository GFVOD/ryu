from mininet.topo import Topo

class ctopo1( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1=self.addHost('h1')
        h2=self.addHost('h2')
        h3=self.addHost('h3')
        h4=self.addHost('h4')
        h5=self.addHost('h5')
        h6=self.addHost('h6')
        h7=self.addHost('h7')
        h8=self.addHost('h8')

        s1=self.addSwitch('s1')
        s2=self.addSwitch('s2')
        s3=self.addSwitch('s3')
        s4=self.addSwitch('s4')
        s5=self.addSwitch('s5')
        s6=self.addSwitch('s6')
        s7=self.addSwitch('s7')

        # Add links
        self.addLink(h1,s4)
        self.addLink(h2,s4)
        self.addLink(h3,s5)
        self.addLink(h4,s5)
        self.addLink(h5,s6)
        self.addLink(h6,s6)
        self.addLink(h7,s7)
        self.addLink(h8,s7)
        self.addLink(s4,s2)
        self.addLink(s5,s2)
        self.addLink(s6,s3)
        self.addLink(s7,s3)
        self.addLink(s2,s1)
        self.addLink(s3,s1)



topos = { 'ctopo1': ( lambda: ctopo1() ) }
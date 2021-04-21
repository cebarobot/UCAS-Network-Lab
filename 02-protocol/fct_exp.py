from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.node import OVSBridge

class MyTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        self.addLink(h1, h2, bw=1000, delay='100ms')

topo = MyTopo()
net = Mininet(topo = topo, switch = OVSBridge, link = TCLink, controller=None)

net.start()
h2 = net.get('h2')
h2.cmd('python2 -m SimpleHTTPServer 80 &')
CLI(net)
h2.cmd('kill %python')
net.stop()

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
import sys
sys.path.append('/home/p4/tutorials/utils')
from p4_mininet import P4Switch
from p4_mininet import P4Host
from p4runtime_switch import P4RuntimeSwitch

class MyTopo(Topo):
    def build(self):
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02') # controller
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03') 
        s1 = self.addSwitch(
        's1',
        cls=P4RuntimeSwitch,
        sw_path='simple_switch_grpc',
        json_path='codiceP4.json',
        p4info='sabre.p4info.txt',
        thrift_port=9090,
        grpc_port=50051
        )

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        

net = Mininet(topo=MyTopo(), controller=None)
# h2 = net.get('h2')
# h2.cmd('/home/p4/src/p4dev-python-venv/bin/python3 -u controller.py &')
net.start()
CLI(net)
net.stop()

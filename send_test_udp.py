from scapy.all import *

class Sabre(Packet):
    fields_desc = [
        ByteField("msg_type", 0),
        IntField("segment_id", 0),
        StrFixedLenField("block_hash", b"\x02"*32, 32),
        IntField("checksum", 0),
        StrFixedLenField("segment_data", b"\x00"*64, 64),
        IntField("secret", 0),
        IntField("segments_num", 0)
    ]
bind_layers(UDP, Sabre, dport=3333)
pkt = Ether(dst="00:00:00:00:00:02") / \
      IP(dst="10.0.0.2") / \
      UDP(dport=3333) / \
      Sabre(	msg_type=2,
		segment_id=3,
		block_hash=b"\x02"*32,
		checksum=0,
		segment_data=b"\x05"*64,
		secret= 0x456e9287,
		segments_num=5
	)
	
pkt.show()
sendp(pkt, iface="h1-eth0")

import sys
import time
import socket
import requests
import threading
import struct
import hashlib
import zlib

# librerie P4Runtime (dagli esempi ufficiali)
sys.path.append('/home/p4/tutorials/utils')

from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.bmv2 as bmv2
import p4runtime_lib.helper as helper


############################
# CONFIG
############################

class SabreHeader:
    def __init__(self, msg_type, segment_id, block_hash,
                 checksum, segment_data, secret, segments_num):

        assert len(block_hash) == 32
        assert len(segment_data) == 64

        self.msg_type = msg_type
        self.segment_id = segment_id
        self.block_hash = block_hash
        self.checksum = checksum
        self.segment_data = segment_data
        self.secret = secret
        self.segments_num = segments_num

    def to_bytes(self):
        return struct.pack(
            ">B I 32s I 64s I I",
            self.msg_type,
            self.segment_id,
            self.block_hash,
            self.checksum,
            self.segment_data,
            self.secret,
            self.segments_num
        )


P4INFO_FILE = 'sabre.p4info.txt'
JSON_FILE = 'codiceP4.json'

SWITCH_ADDR = '10.0.2.15:50051'                 # utilizzato da P4Runtime per controllare il processo switch da remoto mediante server gRPC sulla macchina dello switch 
DEVICE_ID = 0

CONTROLLER_IP = "10.0.0.2"
SABRE_PORT = 3333

SEGMENT_SIZE = 64 

peer_list = set()
RPC_URL = "http://user:password@127.0.0.1:8332" # indirizzo dell'interfaccia di bitcoind in esecuzione in locale
                                                # si comunica mediante interfaccia di loopback

############################
# CONNECT
############################

def connect_to_switch(p4info_helper):
    sw = bmv2.Bmv2SwitchConnection(
        name='s1',
        address=SWITCH_ADDR,
        device_id=DEVICE_ID,
        proto_dump_file='logs/s1-p4runtime-requests.txt'
    )

    sw.MasterArbitrationUpdate()

    sw.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info,
        bmv2_json_file_path=JSON_FILE
    )

    print("[+] Connected to switch")
    return sw


############################
# WHITELIST
############################

def add_whitelist(sw, p4info_helper, ip, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.whitelist",
        match_fields={
            "hdr.ipv4.srcAddr": ip,
            "hdr.udp.srcPort": port
        },
        action_name="MyIngress.allow",
        action_params={}
    )

    sw.WriteTableEntry(table_entry)
    print(f"[+] Whitelisted {ip}:{port}")


def add_blacklist(sw, p4info_helper, ip):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.blacklist",
        match_fields={
            "hdr.ipv4.srcAddr": ip
        },
        action_name="MyIngress.drop",
        action_params={}
    )

    sw.WriteTableEntry(table_entry)
    print(f"[+] Blacklisted {ip}")


############################
# NCONN handler
############################

def handle_nconn(ip, port):
    peer_list.add((ip,port))
    print(f"[+] New peer: {ip}:{port}")



############################
# CTR 
############################

def send_ctr(ip, port, sock):
    
    ctr = SabreHeader(
        msg_type = 8,
        segment_id = 0,
        block_hash = b'\x00'*32,
        checksum = 0,
        segment_data = b'\x00'*64,
        secret = 0,
        segments_num = 0
    ) 
    sock.sendto(ctr.to_bytes(), (ip, port))

    print(f"[+] Sent CTR to {ip}:{port}")


############################
# DIGEST HANDLER
############################

def handle_digest(sw, p4info_helper, digest, sock):
   
    for data in digest.data:

        peer_ip = data.struct.members[0].bitstring
        peer_port = data.struct.members[1].bitstring

        # conversione
        ip = socket.inet_ntoa(peer_ip.to_bytes(4, byteorder='big'))
        port = int(peer_port)

        print(f"[+] New peer whitelisted: {ip}:{port}")

        add_whitelist(sw, p4info_helper, ip, port)
        send_ctr(ip, port, sock)


############################
# BLOCK VALIDATION
############################

def handle_validation(block):
    payload = {
        "jsonrpc": "1.0",
        "id": "sabre",
        "method": "submitblock",
        "params": [block]
    }

    try:
        r = requests.post(RPC_URL, json=payload)
        result = r.json()

        if result["error"] is None:
            return True
        else:
            print("[!] Bitcoin error:", result["error"])
            return False

    except Exception as e:
        print("[!] RPC exception:", e)
        return False



def handle_connection(conn, addr, sock_udp):
    print(f"[+] Peer connected: {addr[0]}:{addr[1]}")

    try:
        # ricezione dati 
        data = conn.recv(1000000)  # 1MB 

        if not data:
            print("[!] Empty data")
            conn.close()
            return

        # bytes → string
        block = data.decode().strip()

        # validazione via bitcoind
        is_valid = handle_validation(block)

        # risposta al peer
        if is_valid:
            conn.send(b"VALID")
            print("[+] VALID BLOCK")
            send_upd(CONTROLLER_IP, SABRE_PORT, data, sock_udp)

        else:
            conn.send(b"INVALID")
            print("[-] INVALID BLOCK")

    except Exception as e:
        print("[!] Error handling connection:", e)

    finally:
        conn.close()


############################
# handler tcp
############################

def tcp_connection(sock_udp):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 5000))
    sock.listen()

    print("[*] Controller TCP listening on port 5000")

    while True:
        result = sock.accept()
        conn = result[0]
        addr = result[1]
        print("[*] Controller recieved data : {conn}:{addr}")
        threading.Thread(
        target=handle_connection,
        args=(conn, addr, sock_udp),
        daemon=True
        ).start()



############################
# send block
############################

def send_upd(ip, port, block_bytes, sock):
    
    # conversione in hash
    tmp = hashlib.sha256(block_bytes).digest()
    blk_hash = hashlib.sha256(tmp).digest()
    segments = segmentation(block_bytes)
    upd = SabreHeader(
        msg_type = 6,
        segment_id = 0,
        block_hash = blk_hash,
        checksum = 0,
        segment_data = b'\x00'*64,
        secret = 0,
        segments_num = len(segments)
    )

    sock.sendto(upd.to_bytes(), (ip, port))

    print(f"[+] Sent UPD to {ip}:{port}")
    send_block(ip, port, segments, len(segments), blk_hash, sock)


def segmentation(block_bytes):
    segments = []

    for i in range(0, len(block_bytes), SEGMENT_SIZE):
        chunk = block_bytes[i:i + SEGMENT_SIZE]

        # padding
        if len(chunk) < SEGMENT_SIZE:
            chunk = chunk.ljust(SEGMENT_SIZE, b'\x00')

        segments.append(chunk)

    return segments



def send_block(ip, port, segments, num_segments, blk_hash, sock):
    
    i = 0
    for segment in segments:
        
        checksum = zlib.crc32(segment)  # calcolo checksum con integer a 32 bit
        blk = SabreHeader(
            msg_type = 5,
            segment_id = i,
            block_hash = blk_hash,
            checksum = checksum,
            segment_data = segment,
            secret = 0,
            segments_num = num_segments
        )
        sock.sendto(blk.to_bytes(), (ip, port))
        print(f"[+] Sent segment {i} to {ip}:{port}")
        i+=1
        time.sleep(0.001)


def nconn_listener(sock):
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock1.bind(("0.0.0.0", 3333))

    print("[*] Listening SABRE...")

    while True:
        data, addr = sock1.recvfrom(2048)
        print(f"Ricevuti {len(data)} byte da {addr}", flush=True)
        if(data and data[0] == 7):
            handle_nconn(addr[0], addr[1])


############################
# MAIN LOOP
############################

def main():
    #p4info_helper = helper.P4InfoHelper(P4INFO_FILE)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.  setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #sw = connect_to_switch(p4info_helper)

    tcp_thread = threading.Thread(target=tcp_connection, args=(sock,))
    tcp_thread.daemon = True
    tcp_thread.start()

    tcp_thread = threading.Thread(target=nconn_listener, args=(sock,))
    tcp_thread.daemon = True
    tcp_thread.start()
    
    
    while True:
        time.sleep(1)
        """
        try:
            while True:
                # gestione polling digest ADV nuovi blocchi
                digest_list = sw.ReadDigestList()

                for digest in digest_list:
                    handle_digest(sw, p4info_helper, digest, sock)

                time.sleep(0.1)

        except KeyboardInterrupt:
            print("Shutting down...")

        finally:
            ShutdownAllSwitchConnections()
        """

############################

if __name__ == '__main__':
    main()

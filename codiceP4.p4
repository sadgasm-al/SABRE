#include <core.p4>
#include <v1model.p4>

///////////////////////////////////////////////////////////
// HEADERS
///////////////////////////////////////////////////////////

const bit<16> SABRE_PORT = 3333;
const bit<16> TCP_VALIDATION_PORT = 5000;
const bit<9> CONTROLLER_PORT = 2;
const bit<9> PEERS_PORT = 1;
const bit<32> SECRET_KEY = 0xFFFFFFFF;
const bit<32> CONTROLLER_IP = 0x0A000002; // es. 10.0.0.2
const bit<8> ESTABILISHED = 1;
const bit<32> MAX = 0xFFFFFFFF;
const bit<32> ZERO = 0;

const bit<8> SYN     = 0;
const bit<8> SYN_ACK = 1;
const bit<8> ACK     = 2;
const bit<8> ADV     = 3;
const bit<8> GET_SEQ = 4;
const bit<8> BLK     = 5;
const bit<8> UPD     = 6;
const bit<8> NCONN   = 7;



struct digest_t {
    bit<32> peer_ip;
    bit<16> peer_port;
}


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

///////////////////////////////////////////////////////////
// SABRE HEADER
///////////////////////////////////////////////////////////

header sabre_t {
    bit<8>  msg_type;
    bit<32> segment_id;
    bit<256> block_hash;
    bit<32> checksum;
    bit<512> segment_data;
    bit<32> secret;
    bit<32> segments_num;
}

///////////////////////////////////////////////////////////
// HEADER STRUCT
///////////////////////////////////////////////////////////

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
    sabre_t    sabre;
}



///////////////////////////////////////////////////////////
// METADATA
///////////////////////////////////////////////////////////

struct metadata {
    bit<1> udp_conn;
    bit<1> tcp_conn;
}

///////////////////////////////////////////////////////////
// REGISTERS
///////////////////////////////////////////////////////////

// HashMem
register<bit<256>>(1024) hash_mem;

// BlockMem (semplificata)
register<bit<32>>(1024) segment_id_reg;
register<bit<32>>(1024) segment_checksum_reg;
register<bit<512>>(1024) segment_data_reg;

// Current block
register<bit<256>>(1) current_block_hash;
register<bit<32>>(1) block_total_segments;

// PeerList
register<bit<32>>(65536) peer_ip_reg;
register<bit<16>>(65536) peer_port_reg;
register<bit<8>>(65536) peer_state;
register<bit<32>>(65536) last_activity;
register<bit<32>>(65536) request_counter;


///////////////////////////////////////////////////////////
// PARSER
///////////////////////////////////////////////////////////

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp; // UDP
	    6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
    	hdr.udp.setInvalid();		// SICUREZZA PER LA FASE DI DEPARSING
    	hdr.sabre.setInvalid();	
    	packet.extract(hdr.tcp);
    	transition accept;
    }

    state parse_udp {
    	hdr.tcp.setInvalid();
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
	    SABRE_PORT: parse_sabre;
	    default: accept;
	}
    }

    state parse_sabre {
        packet.extract(hdr.sabre);
        transition accept;
    }
}



///////////////////////////////////////////////////////////
// INGRESS (CORE LOGIC)
///////////////////////////////////////////////////////////

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

///////////////////////////////////////////////////////////
// ACTIONS (HANDLER)
///////////////////////////////////////////////////////////

action drop() {
    mark_to_drop(standard_metadata);
}

action allow() { }

action handle_syn() {
    // GENERAZIONE SEGRETO
    bit<32> secret_conn;
    hash(secret_conn, HashAlgorithm.crc32, SECRET_KEY, {hdr.ipv4.srcAddr, hdr.udp.srcPort}, MAX);
    hdr.sabre.msg_type = SYN_ACK;	
    hdr.sabre.secret = secret_conn;
   
   
    // RIDIREZIONE VERSO IL CLIENT
    bit<32> tmp_ip = hdr.ipv4.srcAddr;
    bit<16> tmp_port = hdr.udp.srcPort;
    hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
    hdr.ipv4.dstAddr = tmp_ip;
    hdr.udp.srcPort = hdr.udp.dstPort;
    hdr.udp.dstPort = tmp_port;
    bit <48> tmp_mac = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = tmp_mac;
    hdr.udp.checksum = 0;
	
    // RIDIREZIONE VERSO PORTA FISICA DI USCITA
    standard_metadata.egress_spec = PEERS_PORT;
}

action handle_ack() {
   
    // CONTROLLO SEGRETO 
    bit<32> secret_conn;
    bit<32> secret_client = hdr.sabre.secret;
    hash(secret_conn, HashAlgorithm.crc32, SECRET_KEY, {hdr.ipv4.srcAddr, hdr.udp.srcPort}, MAX);
    if (secret_client != secret_conn){			
	mark_to_drop(standard_metadata);
	return;	
    }
    
    // 	CALCOLO INDICE E AGGIUNTA CLIENT NELLA PEERLIST
    bit<32> index;
    hash(index, HashAlgorithm.crc32, ZERO, {hdr.ipv4.srcAddr, hdr.udp.srcPort}, MAX);
    index = index % 65536;
    peer_ip_reg.write(index, hdr.ipv4.srcAddr);	
    peer_port_reg.write(index, hdr.udp.srcPort);	
    peer_state.write(index, ESTABILISHED);		
    last_activity.write(index, 1);			
    request_counter.write(index, 0);		

    // NOTIFICA NUOVO CLIENT AL CONTROLLER
    hdr.sabre.msg_type = NCONN;
    hdr.udp.checksum = 0;
    hdr.ipv4.dstAddr = CONTROLLER_IP;
    hdr.udp.dstPort = SABRE_PORT;

    // RIDIREZIONE VERSO PORTA FISICA DI USCITA
    standard_metadata.egress_spec = CONTROLLER_PORT;

}

action handle_adv() {
    
    // CALCOLO INDICE HASHMEM
    bit<32> index;
    hash(index, HashAlgorithm.crc32, ZERO, {hdr.sabre.block_hash}, MAX);
    index = index % 1024;
    
    // CONTROLLO PRESENZA BLOCCO IN HASHMEM
    bit<256> tmp_hash;
    hash_mem.read(tmp_hash, index);
    if (hdr.sabre.block_hash == tmp_hash) {
        mark_to_drop(standard_metadata);
        return;
    }

    // INSERIMENTO IN HASHMEM DEL BLOCCO E IN WHITELIST DEL CLIENT
    hash_mem.write(index, hdr.sabre.block_hash);
    digest_t d;

    d.peer_ip   = hdr.ipv4.srcAddr;	// ALTERNATIVA:
    d.peer_port = hdr.udp.srcPort;	// configurare whitelist come registro
    digest<digest_t>(1, d);

}

action handle_get_seq() {
     
    // CONTROLLI HASH E INDICE SEGMENTO
    bit<256> curr;
    current_block_hash.read(curr, 0);
	
    if (hdr.sabre.block_hash != curr) {
	mark_to_drop(standard_metadata);
	return;
    }	
   	
    bit<32> segm_total;
    block_total_segments.read(segm_total, 0);
	
    if (hdr.sabre.segment_id >= segm_total) {
	mark_to_drop(standard_metadata);
	return;
    } 	


    // RECUPERO SEGMENTO
    bit<512> tmp;
    segment_data_reg.read(tmp, hdr.sabre.segment_id);

    // CREAZIONE E INVIO RISPOSTA AL CLIENT
    hdr.sabre.msg_type = BLK;
    hdr.udp.checksum = 0;
    hdr.sabre.segment_data = tmp;
    hdr.sabre.segments_num = segm_total;	
 
    bit<32> tmp_ip = hdr.ipv4.srcAddr;
    bit<16> tmp_port = hdr.udp.srcPort;
    hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
    hdr.ipv4.dstAddr = tmp_ip;
    hdr.udp.srcPort = hdr.udp.dstPort;
    hdr.udp.dstPort = tmp_port;
    bit <48> tmp_mac = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = tmp_mac;
   
    standard_metadata.egress_spec = PEERS_PORT;

}


action handle_upd() {
    
    // AGGIORNAMENTO
    block_total_segments.write(0, hdr.sabre.segments_num);
    current_block_hash.write(0, hdr.sabre.block_hash);
    hdr.ethernet.dstAddr = 48w0xffffffffffff;		// BROADCAST
    hdr.udp.checksum = 0;
    standard_metadata.egress_spec = PEERS_PORT;
}


action handle_blk() {
    
    // CONTROLLO CHECKSUM E HASH DEL BLOCCO
    bit<32> index = hdr.sabre.segment_id % 1024;
    bit<32> checksum_val;
    bit<256> curr;
    current_block_hash.read(curr, 0);


    if (hdr.sabre.block_hash != curr) {
	mark_to_drop(standard_metadata);
	return;
    }    

  	/*
    hash(checksum_val, HashAlgorithm.crc32, ZERO, { hdr.sabre.segment_data }, MAX);
    if (checksum_val != hdr.sabre.checksum) {
  	mark_to_drop(standard_metadata);
	return;
    }
	*/

    // INSERIMENTO IN BLOCKMEM
    bit<512> existing;
    segment_data_reg.read(existing, index);

    if (existing == hdr.sabre.segment_data) {
    	mark_to_drop(standard_metadata);
    	return;
    }

    segment_id_reg.write(index, hdr.sabre.segment_id);
    segment_checksum_reg.write(index, hdr.sabre.checksum);
    segment_data_reg.write(index, hdr.sabre.segment_data);
    
}

///////////////////////////////////////////////////////////
// TABLES
///////////////////////////////////////////////////////////

		table blacklist {
    			key = {
        			hdr.ipv4.srcAddr: exact;
    			}
    			actions = {
        			drop;
        			NoAction;
    			}
    			size = 1000000;
		}

		table whitelist {
   			key = {
        			hdr.ipv4.srcAddr: exact;
				hdr.udp.srcPort: exact;
    			}
    			actions = {
				allow;
				NoAction;
    			}
    			size = 100;
    			default_action = NoAction();
		}
		

    apply {
	
        //////////////////////////////
        // VALIDAZIONE
        //////////////////////////////

        blacklist.apply();


        //////////////////////////////
        // DISPATCH COMUNICAZIONE
        //////////////////////////////

	meta.udp_conn = 0;
	meta.tcp_conn = 0;

	if (!hdr.ipv4.isValid()) {
    	   mark_to_drop(standard_metadata);
    	   return;
	}

	if (hdr.ipv4.protocol == 6) {
    	    meta.tcp_conn = 1;
	}
	else if (hdr.ipv4.protocol == 17) {
    	   meta.udp_conn = 1;
	}
	
	if (meta.tcp_conn != 1 && meta.udp_conn != 1) {
    	   mark_to_drop(standard_metadata);
	   return;
	}
	
	if (meta.tcp_conn == 1) {	// traffico BITCOIN verifica blocco
	   // Client -> Controller
	  if (hdr.tcp.dstPort == TCP_VALIDATION_PORT  && !whitelist.apply().hit) {
			standard_metadata.egress_spec = CONTROLLER_PORT;
		  	return;
		 } 
	  
	  // Controller -> Client (handshake)
    	  else if (hdr.tcp.srcPort == TCP_VALIDATION_PORT) {
      	 		standard_metadata.egress_spec = PEERS_PORT;
        		return;
    		} else {
	   mark_to_drop(standard_metadata);
	   return;
	   }
	} 


	if (meta.udp_conn == 1) {	// traffico UDP SABRE

	bit<8> msg;
	bit<32> index;
	bit<32> ip_list;
	bit<16> port_list; 

            	if (!hdr.sabre.isValid()) {
		    mark_to_drop(standard_metadata);
		    return;
		}

		msg = hdr.sabre.msg_type;
		hash(index, HashAlgorithm.crc32, ZERO, {hdr.ipv4.srcAddr, hdr.udp.srcPort}, MAX);
		index = index % 65536;


	//////////////////////////////
	// LOOKUP PEERLIST
	//////////////////////////////
		
		if (msg != SYN && msg != ACK){
		    peer_ip_reg.read(ip_list, index);		
		    peer_port_reg.read(port_list, index);	

		    if (ip_list != hdr.ipv4.srcAddr || port_list != hdr.udp.srcPort) {
				mark_to_drop(standard_metadata);
		    		return;
			}
		}

	//////////////////////////////
	// CONTROLLO MESSAGGI INVALIDI
	//////////////////////////////

		if (msg == SYN_ACK || msg == NCONN) {
		    mark_to_drop(standard_metadata);
		    return;
		}

		if (msg == UPD && standard_metadata.ingress_port != CONTROLLER_PORT) {
		    mark_to_drop(standard_metadata);
		    return;
		}
		
		if (msg == BLK && standard_metadata.ingress_port != CONTROLLER_PORT) {
		    mark_to_drop(standard_metadata);
		    return;
		}

		
	//////////////////////////////
        // DISPATCH MESSAGGIO
        //////////////////////////////


            	if (msg == SYN) {
   			 handle_syn();
		} else if (msg == ACK) {
    			handle_ack();
		} else if (msg == ADV) {
    			handle_adv();
		} else if (msg == GET_SEQ) {	
    			handle_get_seq();
		} else if (msg == BLK) {
    			handle_blk();
		} else if (msg == UPD) {
    			handle_upd();
		}

           
	}

        
    }
}

///////////////////////////////////////////////////////////
// EGRESS
///////////////////////////////////////////////////////////

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

///////////////////////////////////////////////////////////
// CHECKSUM (stub)
///////////////////////////////////////////////////////////

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

///////////////////////////////////////////////////////////
// DEPARSER
///////////////////////////////////////////////////////////

control MyDeparser(packet_out packet,
                   in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
	packet.emit(hdr.udp);
        packet.emit(hdr.sabre);
    }
}

///////////////////////////////////////////////////////////
// MAIN
///////////////////////////////////////////////////////////

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;



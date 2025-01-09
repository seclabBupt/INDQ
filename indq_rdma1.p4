#include <core.p4>
#include <tna.p4>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ROCE 0x8915

#define IPv4_PROTO_UDP 0x11

// UDP 端口号, 用于区分自定义协议
#define UDP_PORT_INDQ 50002

#define RDMA_WRITE_ONLY 10
#define RDMA_READ_REQUEST 12
#define RDMA_READ_RESPONSE 16

#ifndef MAX_SUPPORTED_QPS
	#define MAX_SUPPORTED_QPS 256 // Maximum number of supported QPs. Specifies table and register sizes
	// #define MAX_SUPPORTED_QPS 65536 // Used when benchmarking tons of QPs
#endif

typedef bit<32> ipv4_address_t;

typedef bit<32> iCRC_t;
typedef bit<32> remote_key_t;
typedef bit<24> queue_pair_t;
typedef bit<24> psn_t;              // RoCEv2 中的数据包序列号 (Packet sequence number)

typedef bit<16> qp_reg_index_t;     // 用于为每个 QP 存放其 PSN. 该字段是充当那个寄存器的索引号

typedef bit<32> slot_nums_t;
typedef bit<32> memory_slot_t;      // 内存插槽(空隙). 由 Key-Write 和 Append 原语所共享, 出于某些原因, 它们都被限制在最大 32 bits
typedef bit<64> memory_address_t;   // 物理内存地址(共 2^64)

// 定义不同的数据包类型 (Normal 和 Mirror), 用于桥接报头中
typedef bit<8>  pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

// 定义不同的镜像数据包类型 (I2E 和 E2E)
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

// 14 Bytes
header ethernet_h{
	bit<48> dstAddr;
	bit<48> srcAddr;
	bit<16> etherType;
}

// 20 Bytes
header ipv4_h{
	bit<4> version;
	bit<4> ihl;
	bit<6> dscp;
	bit<2> ecn;
	bit<16> totalLen;
	bit<16> identification;
	bit<3> flags;
	bit<13> fragOffset;
	bit<8> ttl;
	bit<8> protocol;
	bit<16> hdrChecksum;
	ipv4_address_t srcAddr;
	ipv4_address_t dstAddr;
}

// 8 Bytes
header udp_h{
	bit<16> srcPort;
	bit<16> dstPort;
	bit<16> totalLen;
	bit<16> checksum;
}

// 自定义协议的报头部分
header indq_base_h{
	bit<8> opcode;
}

// 自定义协议的载荷部分
header indq_payload_h{
	bit<32> key;
	bit<32> value;
}

// Global Route Header (GRH) (40 Bytes)
header infiniband_grh_h{
    bit<4>   version;
    bit<8>   class;
    bit<20>  flow_lab;
    bit<16>  pay_len;
    bit<8>   next_hdr;
    bit<8>   hop_lim;
    bit<128> src_gid;
    bit<128> dst_gid;
}

// Base Transport Header (BTH) (12 Bytes)
header infiniband_bth_h{
	bit<8> opcode;
	bit<1> solicitedEvent;
	bit<1> migReq;
	bit<2> padCount;
	bit<4> transportHeaderVersion;
	bit<16> partitionKey;
	bit<1> fRes;
	bit<1> bRes;
	bit<6> reserved1;
	bit<24> destinationQP;
	bit<1> ackRequest;
	bit<7> reserved2;
	psn_t packetSequenceNumber;
}

// RDMA Extended Transport Header (RETH) (16 bytes)
header infiniband_reth_h{
    memory_address_t virtualAddress;
    bit<32> rKey;
    bit<32> dmaLength;
}

// RDMA ACK Extended Transport Header (ACKETH) (4 bytes)
header infiniband_acketh_h{
	bit<8> syndrome;
	bit<24> MessageSequenceNumber;
}

// RDMA Payload (8 bytes)
// Payload size is determined by the Custom Protocol
header rdma_payload_h{
	bit<32> value;
	bit<32> checksum;
}

// iCRC 字段 (4 Bytes)
header infiniband_icrc_h{
	bit<32> iCRC;
}

header mirror_h{
	pkt_type_t pkt_type;
}

header mirror_bridged_metadata_h{
	pkt_type_t pkt_type;
}

struct headers{
	mirror_bridged_metadata_h bridged_md;
	ethernet_h ethernet;
	ipv4_h ipv4;
	udp_h udp;

	/* Custom Header */
	indq_base_h indq_base;
	indq_payload_h indq_payload;
 
	/* RoCEv2 Header */
	infiniband_grh_h grh;
	infiniband_bth_h bth;
	infiniband_reth_h reth;
	infiniband_acketh_h ack_eth;
	rdma_payload_h rdma_payload;
	infiniband_icrc_h icrc;
}

struct ingress_metadata_t{
	pkt_type_t pkt_type;
	MirrorId_t mirror_session;
}


struct egress_metadata_t{
	/* RDMA Metadata */
	psn_t rdma_psn;
	remote_key_t remote_key;
	queue_pair_t queue_pair;

	/* Used to locate where to store in the rdma memory */
	memory_address_t memory_address_start;
	memory_address_t memory_address_offset;

	/* Slot is used as an intermediary for calculating rdma memory address */
	memory_slot_t num_slots;
	memory_slot_t dst_slot;
	
	qp_reg_index_t qp_reg_index;

	bit<8> redundancy_entry_num;
	bit<32> indq_key_checksum;
}


/* 入口解析器部分校对完毕, 没有问题 */
parser TofinoIngressParser(packet_in pkt,
						   /* User */
						   inout ingress_metadata_t ig_md,
						   /* Intrinsic */
						   out ingress_intrinsic_metadata_t ig_intr_md)
{
	state start{
		pkt.extract(ig_intr_md);
		transition select(ig_intr_md.resubmit_flag){
			1 : parse_resubmit;
			0 : parse_port_metadata;
		}
	}

	state parse_resubmit{
		transition reject;
	}

	state parse_port_metadata{
		pkt.advance(64);    // Tofino 1
		transition accept;
	}
}

parser SwitchIngressParser(packet_in pkt,
						   /* User */
						   out headers hdr,
						   out ingress_metadata_t ig_md,
						   /* Intrinsic */ 
						   out ingress_intrinsic_metadata_t ig_intr_md)
{
	TofinoIngressParser() tofino_parser;
	
	state start{
		tofino_parser.apply(pkt, ig_md, ig_intr_md);
		transition parse_ethernet;
	}
	
	state parse_ethernet{
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType){
			ETHERTYPE_IPV4: parse_ipv4;
			ETHERTYPE_ROCE: parse_grh;
			default: accept;
		}
	}
	
	state parse_ipv4{
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
			IPv4_PROTO_UDP: parse_udp;
			default: accept;
		}
	}

	state parse_udp{
		pkt.extract(hdr.udp);
		// 根据自定义协议的端口号来判断该解析哪个报头
		transition select(hdr.udp.dstPort){
			UDP_PORT_INDQ: parse_indq_base;
			default: accept;
		}
	}

	state parse_indq_base{
		pkt.extract(hdr.indq_base);
		transition parse_indq_payload;
	}

	state parse_indq_payload{
		pkt.extract(hdr.indq_payload);
		transition accept;
	}

	state parse_grh{
		pkt.extract(hdr.grh);
		transition parse_bth;
	}

	state parse_bth{
		pkt.extract(hdr.bth);
		transition select(hdr.bth.opcode){
			RDMA_READ_RESPONSE: parse_acketh;
			default: accept;
		}
	}

	state parse_acketh{
		pkt.extract(hdr.ack_eth);
		transition parse_rdma_payload;
	}

	state parse_rdma_payload{
		pkt.extract(hdr.rdma_payload);
		transition accept;
	}
	
}

/* 入口控制块部分校对完毕, 没有问题 */
control SwitchIngress(inout headers hdr,
					  /* User */
					  inout ingress_metadata_t ig_md,
					  /* Intrinsic */
					  in ingress_intrinsic_metadata_t ig_intr_md,
					  in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
					  inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
					  inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md)
{
	/* 根据目的以太网地址来设置多播组 ID, 从而对数据包执行多播操作 */
	action prep_multiwrite(bit<16> mcast_grp)
	{
		ig_intr_tm_md.mcast_grp_a = mcast_grp;
	}
	table tbl_prep_multicast
	{
		key = {
			hdr.ethernet.dstAddr: exact;
		}
		actions = {
			prep_multiwrite;
			@defaultonly NoAction;
		}
		default_action = NoAction;
		size = 1024;
	}

	/* 根据目的以太网地址决定数据包执行转发到对应的目的端口, 或者是丢弃该数据包 */
	action forward(PortId_t port)
	{
		ig_intr_tm_md.ucast_egress_port = port;
	}
	action to_cpu()
	{
		ig_intr_tm_md.ucast_egress_port = 66;
	}
	action drop()
	{
		ig_intr_dprsr_md.drop_ctl = 1;
	}
	table tbl_forward
	{
		key = {
			hdr.ethernet.dstAddr: exact;
		}
		actions = {
			forward;
			to_cpu;
			drop;
		}
		default_action = to_cpu;
		size = 1024;
	}
	
	apply
	{
		tbl_forward.apply();

		tbl_prep_multicast.apply();

		// 为 Egress Control 准备桥接元数据
		hdr.bridged_md.setValid();
		hdr.bridged_md.pkt_type = PKT_TYPE_NORMAL;
	}
}


/* 入口逆解析器部分校对完毕, 没有问题 */
control SwitchIngressDeparser(packet_out pkt, 
							  inout headers hdr,
							  in ingress_metadata_t ig_md,
							  in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md)
{
	Mirror() mirror;
	
	apply{
		// 如果时 Ingress-to-Egress 镜像操作
		if (ig_intr_dprsr_md.mirror_type == MIRROR_TYPE_I2E){
			// Emit Mirror，并附加上 mirror_h 报头
			mirror.emit<mirror_h>(ig_md.mirror_session, {ig_md.pkt_type});
		}
		pkt.emit(hdr);
	}
}

parser TofinoEgressParser(packet_in pkt,
						  out egress_intrinsic_metadata_t eg_intr_md)
{
	state start
	{
		pkt.extract(eg_intr_md);
		transition accept;
	}
}

/* 出口解析器部分校对完毕, 没有问题 */
parser SwitchEgressParser(packet_in pkt,
						  /* User */
						  out headers hdr,
						  out egress_metadata_t eg_md,
						  /* Intrinsic */
						  out egress_intrinsic_metadata_t eg_intr_md)
{
	TofinoEgressParser() tofino_parser;

	state start{
		tofino_parser.apply(pkt, eg_intr_md);
		transition parse_metadata;
	}
	
	state parse_metadata{
		mirror_h mirror_md = pkt.lookahead<mirror_h>();
		// 根据镜像元数据中的 pkt_type 字段决定下一步要执行的解析状态
		transition select(mirror_md.pkt_type){
			PKT_TYPE_MIRROR: parse_mirror_md;
			PKT_TYPE_NORMAL: parse_bridged_md;
			default: accept;
		}
	}
	
	// 提取桥接元数据
	state parse_bridged_md{
		pkt.extract(hdr.bridged_md);
		transition parse_ethernet;
	}
	
	// 如果是镜像数据包, 在本方案中表示是遥测报告数据包, 提取其镜像元数据
	state parse_mirror_md{
		mirror_h mirror_md;
		pkt.extract(mirror_md);
		transition parse_ethernet;
	}
	
	state parse_ethernet{
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType){
			ETHERTYPE_IPV4: parse_ipv4;
			ETHERTYPE_ROCE: parse_grh;
			default: accept;
		}
	}
	
	state parse_ipv4{
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
			IPv4_PROTO_UDP: parse_udp;
			default: accept;
		}
	}
	
	state parse_udp{
		pkt.extract(hdr.udp);
		transition select(hdr.udp.dstPort){
			UDP_PORT_INDQ: parse_indq_base;
			default: accept;
		}
	}

	state parse_indq_base{
		pkt.extract(hdr.indq_base);
		transition parse_indq_payload;
	}

	state parse_indq_payload{
		pkt.extract(hdr.indq_payload);
		transition accept;
	}

	state parse_grh{
		pkt.extract(hdr.grh);
		transition accept;
	}

	// state parse_bth{
	// 	pkt.extract(hdr.bth);
	// 	transition accept;
	// }

	// state parse_acketh{
	// 	pkt.extract(hdr.ack_eth);
	// 	transition parse_rdma_payload;
	// }

	// state parse_rdma_payload{
	// 	pkt.extract(hdr.rdma_payload);
	// 	transition accept;
	// }
	
}

// control ControlRDMARatelimit(inout headers hdr, inout egress_metadata_t eg_md)
// {
// 	// 该寄存器中存放着每个出口端口对应的还可丢弃的数据包数量
// 	Register<drop_counter_t, PortId_t>(1024,0) reg_rdma_drop_counter;

// 	// 用于对某个出口端口当前的计数值进行递减操作
// 	RegisterAction<drop_counter_t, PortId_t, drop_counter_t>(reg_rdma_drop_counter) get_drop_counter = {
// 		void apply(inout drop_counter_t counter, out drop_counter_t output)
// 		{
// 			// 对 counter 的值进行递减(每次只减 1)
// 			if(counter > 0){
// 				counter = counter - 1;
// 			}
// 			output = counter;
// 		}
// 	};
// 	// 用于重置某个出口端口的计数值
// 	RegisterAction<drop_counter_t, PortId_t, drop_counter_t>(reg_rdma_drop_counter) initiate_drop_counting = {
// 		void apply(inout drop_counter_t counter, out drop_counter_t output)
// 		{
// 			counter = QP_RESYNC_PACKET_DROP_NUM;
// 			output = counter;
// 		}
// 	};
	
// 	// 用于设置某个队列对 (QP) 的索引号
// 	action set_qp_reg_num(qp_reg_index_t qp_reg_index)
// 	{
// 		eg_md.qp_reg_index = qp_reg_index;
// 	}
// 	table tbl_get_qp_reg_num
// 	{
// 		key = {
// 			eg_md.queue_pair: exact;
// 		}
// 		actions = {
// 			set_qp_reg_num;
// 			NoAction;
// 		}
// 		default_action = NoAction;
// 		size = 1024;
// 	}
	
// 	apply
// 	{
// 		if(eg_md.is_congestion_ack == 1){
// 			// 开始强制丢弃该出口端口的数据包 (即先初始化丢包计数值)
// 			initiate_drop_counting.execute(eg_md.egress_port);
// 			// 重新同步 PSN 计数器时需要执行这步操作
// 			tbl_get_qp_reg_num.apply();
// 		}
// 		// 如果是自定义协议的数据包
// 		else if(hdr.indq_base.isValid()) {
//         	// 获取该出口端口当前还可丢弃的数据包数量
// 			eg_md.drop_counter = get_drop_counter.execute(eg_md.egress_port);
			
// 			// 如果 drop_counter 大于 0 则应丢弃该数据包（忽略 RDMA 生成）
// 			if(eg_md.drop_counter > 0){
// 				// 这将绕过 PSN 增量器，并在 Deparser 中直接丢弃
// 				eg_md.prevent_rdma_generation = 1;
// 			}
// 		}
		
// 	}
// }


/* PrepareMemoryAddress 用于根据数据包中的负载计算出最终要写入的内存地址偏移量 */
control ControlPrepareMemoryAddress(inout headers hdr,
							   inout egress_metadata_t eg_md,
							   in egress_intrinsic_metadata_t eg_intr_md)
{
	Hash<slot_nums_t>(HashAlgorithm_t.CRC32) hash_slot;
	Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_checksum;

	// 用于区分多播中产生的多个数据包 (因为每来一个数据包都要递增寄存器中的值, 并且还是循环)
	Register<bit<8>, bit<1>>(MAX_SUPPORTED_QPS) get_redundancy_number;
	RegisterAction<bit<8>, bit<1>, bit<8>>(get_redundancy_number) get_pkt_number = {
		void apply(inout bit<8> stored, out bit<8> output)
		{
			// 首先将内部存储的 stored 输出给 output
			output = stored;
			// 如果当前存储的值大于 hash_nums - 1, 则需要将 stored 置 0
			if(stored >= 3){
				stored = 0;
			}
			// 否则, 对 stored 进行递增
			else{
				stored = stored + 1;
			}			
		}
	};

	// 根据目的以太网地址, 获取对应 Collector 的 RDMA 元数据信息
	action set_server_info(remote_key_t remote_key, queue_pair_t queue_pair, memory_address_t memory_address_start, memory_slot_t num_slots, qp_reg_index_t qp_reg_index)
	{
		eg_md.remote_key = remote_key;
		eg_md.queue_pair = queue_pair;
		eg_md.memory_address_start = memory_address_start;
		eg_md.num_slots = num_slots;
		eg_md.qp_reg_index = qp_reg_index;
	}
	table tbl_getRDMAMetadata
	{
		key = {
			hdr.ethernet.dstAddr: exact;
		}
		actions = {
			set_server_info;
		}
		// 单个 Translator 不可能负责比这更多的工作
		size = MAX_SUPPORTED_QPS;
	}

	// 通过哈希函数计算出目标插槽 (计算结果为 bit<32> 类型)
	action cal_dst_slot()
	{
		eg_md.dst_slot = hash_slot.get({hdr.indq_payload.key, eg_md.redundancy_entry_num});
	}
	table tbl_cal_dst_slot
	{
		key = {}
		actions = {
			cal_dst_slot;
		}
		size = 1;
		default_action = cal_dst_slot();
	}


	// 根据实际可用的插槽数量, 对这个计算出的目标插槽进行更正 (通过与 mask 进行按位与运算)
	action bound_memory_slot(memory_slot_t mask)
	{
		eg_md.dst_slot = eg_md.dst_slot & mask;
	}
	table tbl_bound_memory_slot
	{
		key = {
			eg_md.num_slots: exact;
		}
		actions = {
			bound_memory_slot;
		}
		const entries = {
			2: 				bound_memory_slot(0x00000001);
			4: 				bound_memory_slot(0x00000003);
			8: 				bound_memory_slot(0x00000007);
			16: 			bound_memory_slot(0x0000000f);
			32: 			bound_memory_slot(0x0000001f);
			64: 			bound_memory_slot(0x0000003f);
			128: 			bound_memory_slot(0x0000007f);
			256: 			bound_memory_slot(0x000000ff);
			512: 			bound_memory_slot(0x000001ff);
			1024: 			bound_memory_slot(0x000003ff);
			2048: 			bound_memory_slot(0x000007ff);
			4096: 			bound_memory_slot(0x00000fff);
			8192: 			bound_memory_slot(0x00001fff);
			16384: 			bound_memory_slot(0x00003fff);
			32768: 			bound_memory_slot(0x00007fff);
			65536: 			bound_memory_slot(0x0000ffff);
			131072: 		bound_memory_slot(0x0001ffff);
			262144: 		bound_memory_slot(0x0003ffff);
			524288: 		bound_memory_slot(0x0007ffff);
			1048576: 		bound_memory_slot(0x000fffff);
			2097152: 		bound_memory_slot(0x001fffff);
			4194304: 		bound_memory_slot(0x003fffff);
			8388608: 		bound_memory_slot(0x007fffff);
			16777216: 		bound_memory_slot(0x00ffffff);
			33554432: 		bound_memory_slot(0x01ffffff);
			67108864: 		bound_memory_slot(0x03ffffff);
			134217728: 		bound_memory_slot(0x07ffffff);
			268435456: 		bound_memory_slot(0x0fffffff);
			536870912: 		bound_memory_slot(0x1fffffff);
			1073741824: 	bound_memory_slot(0x3fffffff);
			2147483648: 	bound_memory_slot(0x7fffffff);
			//4294967296: 	bound_memory_slot(0xffffffff); //does not fit in 32-bit
		}
		size = 64;
	}

	

	apply
	{
		// 如果为 INDQ 写入数据包, 则需要计算多个 RDMA 写入地址
		if (hdr.indq_base.opcode == 1){
			eg_md.redundancy_entry_num = get_pkt_number.execute(0);
		}
		// 如果为 INDQ 读请求数据包, 则只需计算第一个 RDMA 写入地址进行读取即可
		else if (hdr.indq_base.opcode == 2){
			eg_md.redundancy_entry_num = 0;
		}

		// 获取 RDMA 元数据信息
		tbl_getRDMAMetadata.apply();

		@stage(1)
		{
			if(hdr.indq_payload.isValid()){
				// 计算校验和 checksum
			
				// 计算起始插槽位置和插槽偏移量, 然后联合起来计算出目标插槽位置
				tbl_cal_dst_slot.apply();
				tbl_bound_memory_slot.apply();

				// 将计算出的目标插槽转换为实际在内存地址中的偏移量
				// 即需要乘以有效载荷的字节数 (此处为 8，即向左位移 3)
				eg_md.memory_address_offset = (memory_address_t)(eg_md.dst_slot);
				eg_md.memory_address_offset = eg_md.memory_address_offset * 8;
			}
		}
		
	}
}


/* CraftRDMA 用于将原始数据包转换为 RDMA 数据包 */
control ControlCraftRDMA(inout headers hdr,
						 inout egress_metadata_t eg_md)
{
	Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_checksum;
	// 该寄存器用于保存 RDMA 的 PSN, 并对其进行更新和同步
	Register<bit<32>, qp_reg_index_t>(MAX_SUPPORTED_QPS) reg_rdma_sequence_number;
	RegisterAction<psn_t, qp_reg_index_t, psn_t>(reg_rdma_sequence_number) get_psn = {
		void apply(inout psn_t stored_psn, out psn_t output)
		{
			// 首先输出尚未递增的 PSN
			output = stored_psn;
			// 然后对 PSN 进行递增并覆盖原有的值
			stored_psn = stored_psn + 1;
		}
	};
	RegisterAction<psn_t, qp_reg_index_t, psn_t>(reg_rdma_sequence_number) set_psn = {
		void apply(inout psn_t stored_psn, out psn_t output)
		{
			// 将 PSN 重新同步为 ACK 获取的值
			stored_psn = eg_md.rdma_psn; 
			output = stored_psn;
		}
	};

	action setEthernet()
	{
		hdr.ethernet.setValid();
		hdr.ethernet.srcAddr = 0x08c0eb24686b;
		hdr.ethernet.dstAddr = 0x08c0eb247b8b;
		hdr.ethernet.etherType = ETHERTYPE_ROCE;
	}

	action setInfiniband_GRH()
	{
		hdr.grh.setValid();
		hdr.grh.version = 6;
		hdr.grh.class = 2;
		hdr.grh.flow_lab = 0;
		hdr.grh.pay_len = 44;
		hdr.grh.next_hdr = 27;
		hdr.grh.hop_lim = 1;
		hdr.grh.src_gid = 0xfe800000000000000ac0ebfffe24686b;
		hdr.grh.dst_gid = 0xfe800000000000000ac0ebfffe247b8b;
	}

	action setInfiniband_BTH()
	{
		hdr.bth.setValid();		                  
		hdr.bth.solicitedEvent = 0;
		hdr.bth.migReq = 1; 
		hdr.bth.padCount = 0;
		hdr.bth.transportHeaderVersion = 0;
		hdr.bth.partitionKey = 0xffff;
		hdr.bth.fRes = 0;
		hdr.bth.bRes = 0;
		hdr.bth.reserved1 = 0;
		hdr.bth.destinationQP = eg_md.queue_pair;
		hdr.bth.ackRequest = 0;
		hdr.bth.reserved2 = 0;
	}
	
	action setInfiniband_RETH()
	{
		hdr.reth.setValid();
		hdr.reth.virtualAddress = eg_md.memory_address_start + eg_md.memory_address_offset;
		hdr.reth.rKey = eg_md.remote_key;
		// (根据自定义协议的需求进行设置) DMA 长度, 这个决定了 RDMA Payload 的长度
		hdr.reth.dmaLength = 8;
	}

	action setWriteOnlyPayload()
	{
		hdr.rdma_payload.setValid();
		// 计算 key 的校验和 checksum (转换字节序计算)
		eg_md.indq_key_checksum = hash_checksum.get({hdr.indq_payload.key[7:0] ++ hdr.indq_payload.key[15:8] ++ hdr.indq_payload.key[23:16] ++ hdr.indq_payload.key[31:24]}); 
		hdr.rdma_payload.checksum = eg_md.indq_key_checksum[7:0] ++
									eg_md.indq_key_checksum[15:8] ++
									eg_md.indq_key_checksum[23:16] ++
									eg_md.indq_key_checksum[31:24];
		// 转换原始 INDQ 数据包中的 value 字段的字节序
		hdr.rdma_payload.value = hdr.indq_payload.value[7:0] ++
							hdr.indq_payload.value[15:8] ++
							hdr.indq_payload.value[23:16] ++
							hdr.indq_payload.value[31:24];
	}

	apply{
		setEthernet();
		@stage(2){
			// 如果为 INDQ 数据包, 则转换为 RDMA 数据包
			if(hdr.indq_base.isValid()){
				// GRH Header
				setInfiniband_GRH();
				// BTH Header
				setInfiniband_BTH();

				// 读取并更新该 RDMA 连接的 PSN
				hdr.bth.packetSequenceNumber = get_psn.execute(eg_md.qp_reg_index); 
				
				// RETH Header
				setInfiniband_RETH();

				// Write-Only
				if (hdr.indq_base.opcode == 1){
					hdr.bth.opcode = RDMA_WRITE_ONLY;
					setWriteOnlyPayload();
				}
				// Read Request
				else if(hdr.indq_base.opcode == 2){
					hdr.bth.opcode = RDMA_READ_REQUEST;
				}

				// iCRC Header
				hdr.icrc.setValid();
			}
		}
		// 使原始数据包的相关报头失效
		hdr.ipv4.setInvalid();
		hdr.udp.setInvalid();
		hdr.indq_base.setInvalid();
		hdr.indq_payload.setInvalid();
	}
}

/* 出口控制块部分校对完毕, 没有问题 */
control SwitchEgress(inout headers hdr,
					 inout egress_metadata_t eg_md,
					 in egress_intrinsic_metadata_t eg_intr_md,
					 in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
					 inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
					 inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport)
{
	ControlPrepareMemoryAddress() PrepareMemoryAddress;
	ControlCraftRDMA() CraftRDMA;

	action setIP(){
		hdr.ipv4.setValid();
		hdr.ipv4.ihl = 5;
		hdr.ipv4.identification = 11111;
		hdr.ipv4.ecn = 0b00;
		hdr.ipv4.flags = 0b010;
		hdr.ipv4.fragOffset = 0;
		hdr.ipv4.protocol = 0x11;
		hdr.ipv4.srcAddr = 0xC0A80303;
		hdr.ipv4.dstAddr = 0xC0A80403;
		hdr.ipv4.totalLen = 20 + 8 + 1 + 8;
	}

	action setUDP(){
		hdr.udp.setValid();
		hdr.udp.srcPort = 11111;
		hdr.udp.dstPort = UDP_PORT_INDQ;
		hdr.udp.totalLen = 8 + 1 + 8;
		hdr.udp.checksum = 0;
	}

	action setINDQReadResponse(){
		hdr.indq_base.setValid();
		// 设置 opcode 为 3, 表示为读响应数据包
		hdr.indq_base.opcode = 3;

		// 将 RDMA Read Response 的数据赋值给 INDQ Read Response 的相应字段
		hdr.indq_payload.setValid();
		hdr.indq_payload.key = hdr.rdma_payload.checksum;
		hdr.indq_payload.value = hdr.rdma_payload.value;
	}

	apply{
		// 如果为 INDQ 数据包, 则转换为 RDMA 数据包
		if(hdr.indq_base.isValid()){
			PrepareMemoryAddress.apply(hdr, eg_md, eg_intr_md);
			CraftRDMA.apply(hdr, eg_md);
		}
		// 如果该数据包为 RDMA Read Response 数据包, 则转换为 INDQ 数据包
		else if(hdr.bth.opcode == RDMA_READ_RESPONSE && hdr.ack_eth.isValid() && hdr.ack_eth.syndrome == 0){
			setIP();
			setUDP();
			setINDQReadResponse();

            // 使原始 RDMA 数据包的相关报头失效
            hdr.grh.setInvalid();
            hdr.bth.setInvalid();
            hdr.ack_eth.setInvalid();
            hdr.rdma_payload.setInvalid();
		}
	}
} 


/* 出口逆解析器部分校对完毕, 没有问题 */
control SwitchEgressDeparser(packet_out pkt, inout headers hdr, in egress_metadata_t eg_md, in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
	Checksum() ipv4_checksum;
	apply{
		// Update IPv4 checksum
		hdr.ipv4.hdrChecksum = ipv4_checksum.update(
			{hdr.ipv4.version,
			 hdr.ipv4.ihl,
			 hdr.ipv4.dscp,
			 hdr.ipv4.ecn,
			 hdr.ipv4.totalLen,
			 hdr.ipv4.identification,
			 hdr.ipv4.flags,
			 hdr.ipv4.fragOffset,
			 hdr.ipv4.ttl,
			 hdr.ipv4.protocol,
			 hdr.ipv4.srcAddr,
			 hdr.ipv4.dstAddr});
			 
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.udp);
		pkt.emit(hdr.indq_base);
		pkt.emit(hdr.indq_payload);
		pkt.emit(hdr.grh);
		pkt.emit(hdr.bth);
		pkt.emit(hdr.reth);
		pkt.emit(hdr.ack_eth);
		pkt.emit(hdr.rdma_payload);
		pkt.emit(hdr.icrc);
	}
}


Pipeline(SwitchIngressParser(),
	SwitchIngress(),
	SwitchIngressDeparser(),
	SwitchEgressParser(),
	SwitchEgress(),
	SwitchEgressDeparser()
) pipe;

Switch(pipe) main;

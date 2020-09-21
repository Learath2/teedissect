#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/conversation.h>

#include "huffman.h"

#define TW_PORT 8303

/*

CURRENT:
	packet header: 3 bytes
		unsigned char flags_ack; // 6bit flags, 2bit ack
			0.6:   ORNCaaAA
			0.6.5: ORNCTUAA
			0.7:   --NORCAA

		unsigned char ack; // 8 bit ack
		unsigned char num_chunks; // 8 bit chunks

		(unsigned char padding[3])	// 24 bit extra in case it's a connection less packet
									// this is to make sure that it's compatible with the
									// old protocol

	chunk header: 2-3 bytes
		unsigned char flags_size; // 2bit flags, 6 bit size
		unsigned char size_seq; // 4bit size, 4bit seq
		(unsigned char seq;) // 8bit seq, if vital flag is set
*/
enum {
	NET_PACKETFLAG_UNUSED=1<<0,
	NET_PACKETFLAG_TOKEN=1<<1,
	NET_PACKETFLAG_CONTROL=1<<2,
	NET_PACKETFLAG_CONNLESS=1<<3,
	NET_PACKETFLAG_RESEND=1<<4,
	NET_PACKETFLAG_COMPRESSION=1<<5,
	// NOT SENT VIA THE NETWORK DIRECTLY:
	NET_PACKETFLAG_EXTENDED=1<<6,

	NET_CTRLMSG_KEEPALIVE=0,
	NET_CTRLMSG_CONNECT=1,
	NET_CTRLMSG_CONNECTACCEPT=2,
	NET_CTRLMSG_ACCEPT=3,
	NET_CTRLMSG_CLOSE=4,

	NET_CHUNKFLAG_VITAL=1,
	NET_CHUNKFLAG_RESEND=2,
};

struct CNetPacketConstruct
{
	int m_Flags;
	int m_Ack;
	int m_NumChunks;
	int m_DataSize;
	unsigned char m_aExtraData[4];
};

struct CNetChunkHeader
{
	int m_Flags;
	int m_Size;
	int m_Sequence;
};

static const guint16 NET_HEADER_EXTENDED = 0x7865u;
static const unsigned char SECURITY_TOKEN_MAGIC[] = {'T', 'K', 'E', 'N'};

enum conv_version {
	PROTOCOL_UNK,
	PROTOCOL_06,
	PROTOCOL_DDNET,
	PROTOCOL_065,
	PROTOCOL_07,
};

static const value_string protocolvstring[] = {
	{PROTOCOL_UNK, "Protocol Unknown"},
	{PROTOCOL_06, "Protocol 0.6"},
	{PROTOCOL_DDNET, "Protocol DDNet"},
	{PROTOCOL_065, "Protocol 0.6.5"},
	{PROTOCOL_07, "Protocol 0.7"},
	{0, NULL}
};

struct context {
	int id;
	enum conv_version version;
};

static int proto_teeworlds = -1;
static int hf_teeworlds_flags = -1;
static int hf_teeworlds_flags_c = -1;
static int hf_teeworlds_flags_n = -1;
static int hf_teeworlds_flags_r = -1;
static int hf_teeworlds_flags_o = -1;
static int hf_teeworlds_ack = -1;
static int hf_teeworlds_nchunks = -1;
static int hf_teeworlds_exsi = -1;
static int hf_teeworlds_exsi_token = -1;
static int hf_teeworlds_ctrlmsg = -1;
static int hf_teeworlds_ddnet_token = -1;
static int hf_teeworlds_protocol_version = -1;
static int hf_teeworlds_chunk_flags = -1;
static int hf_teeworlds_chunk_flags_v = -1;
static int hf_teeworlds_chunk_flags_r = -1;
static int hf_teeworlds_chunk_seq = -1;
static int hf_teeworlds_chunk_data = -1;
static gint ett_teeworlds = -1;
static gint ett_teeworlds_flags = -1;
static gint ett_teeworlds_chunk = -1;
static gint ett_teeworlds_chunk_flags = -1;
static expert_field ei_teeworlds_compressionfail = EI_INIT;

static struct huff_ctx gs_huffctx;

static struct context *
tw_new_conn(packet_info *pinfo)
{
	conversation_t *c = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst,
		conversation_pt_to_endpoint_type(pinfo->ptype), pinfo->srcport, pinfo->destport, 0);

	struct context *ctx = wmem_alloc(wmem_file_scope(), sizeof *ctx);
	ctx->id = pinfo->num;
	ctx->version = PROTOCOL_06;

	conversation_add_proto_data(c, proto_teeworlds, ctx);
	return ctx;
}

static int
dissect_chunk(tvbuff_t *tvb, proto_tree *tree)
{
	struct CNetChunkHeader Header;
	Header.m_Flags = tvb_get_bits8(tvb, 0, 2);
	Header.m_Size = (tvb_get_guint8(tvb, 0) & 0x3f) << 4 | (tvb_get_guint8(tvb, 1) & 0xf);
	if(Header.m_Flags&NET_CHUNKFLAG_VITAL)
		Header.m_Sequence = (tvb_get_guint8(tvb, 1) & 0xf0) << 4 | tvb_get_guint8(tvb, 2);
	else
		Header.m_Sequence = -1;

	int header_size = Header.m_Sequence >= 0 ? 3 : 2;
	proto_tree *chunk_tree _U_ = proto_tree_add_subtree_format(tree, tvb, 0,
		header_size + Header.m_Size, ett_teeworlds_chunk, NULL,
		"Chunk Flags=%d Size=%d Seq=%d", Header.m_Flags, Header.m_Size, Header.m_Sequence);

	static int * const chunk_flags[] = {
		&hf_teeworlds_chunk_flags_v,
		&hf_teeworlds_chunk_flags_r,
		NULL
	};
	proto_tree_add_bitmask_value(chunk_tree, tvb, 0, hf_teeworlds_chunk_flags, ett_teeworlds_chunk_flags, chunk_flags, Header.m_Flags);

	if(Header.m_Sequence >= 0)
		proto_tree_add_uint(chunk_tree, hf_teeworlds_chunk_seq, tvb, 1, 2, Header.m_Sequence);

	proto_tree_add_item(chunk_tree, hf_teeworlds_chunk_data, tvb, header_size, Header.m_Size, ENC_NA);

	return header_size + Header.m_Size;
}

static int
dissect_teeworlds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_item *ti;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TW");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *root_item = proto_tree_add_item(tree, proto_teeworlds, tvb, 0, -1, ENC_NA);
	proto_tree *tw_tree = proto_item_add_subtree(root_item, ett_teeworlds);

	struct CNetPacketConstruct Packet;
	Packet.m_Flags = tvb_get_bits8(tvb, 0, 6);
	Packet.m_Ack = tvb_get_bits16(tvb, 7, 10, ENC_BIG_ENDIAN);
	Packet.m_NumChunks = tvb_get_guint8(tvb, 2);

	static int * const tw_flags[] = {
		&hf_teeworlds_flags_c,
		&hf_teeworlds_flags_n,
		&hf_teeworlds_flags_r,
		&hf_teeworlds_flags_o,
		NULL
	};
	proto_tree_add_bitmask_value(tw_tree, tvb, 0, hf_teeworlds_flags, ett_teeworlds_flags, tw_flags, Packet.m_Flags);
	proto_tree_add_uint(tw_tree, hf_teeworlds_ack, tvb, 0, 2, Packet.m_Ack);

	if(Packet.m_Flags&NET_PACKETFLAG_CONNLESS) {
		if(tvb_get_gint16(tvb, 0, ENC_BIG_ENDIAN) == NET_HEADER_EXTENDED)
		{
			ti = proto_tree_add_boolean_format_value(tw_tree, hf_teeworlds_exsi, tvb, 0, 0, TRUE, "Req");
			proto_item_set_generated(ti);

			guint32 token;
			proto_tree_add_item_ret_uint(tw_tree, hf_teeworlds_exsi_token, tvb, 3, 2, ENC_BIG_ENDIAN, &token);
		}

		return tvb_captured_length(tvb);
	}

	proto_tree_add_item(tw_tree, hf_teeworlds_nchunks, tvb, 2, 1, ENC_BIG_ENDIAN);

	if(Packet.m_Flags&NET_PACKETFLAG_CONTROL) {
		guint8 ctrl_msg = tvb_get_guint8(tvb, 3);
		proto_tree_add_uint(tw_tree, hf_teeworlds_ctrlmsg, tvb, 3, 1, ctrl_msg);

		if(ctrl_msg == NET_CTRLMSG_CONNECT || ctrl_msg == NET_CTRLMSG_CONNECTACCEPT)
		{
			struct context *ctx;
			if(ctrl_msg == NET_CTRLMSG_CONNECT && !PINFO_FD_VISITED(pinfo))
				ctx = tw_new_conn(pinfo);
			else {
				conversation_t *c = find_conversation_pinfo(pinfo, 0);
				ctx = conversation_get_proto_data(c, proto_teeworlds);
			}

			unsigned char magic[4];
			tvb_memcpy(tvb, magic, 4, 4);
			if(!memcmp(magic, SECURITY_TOKEN_MAGIC, sizeof(SECURITY_TOKEN_MAGIC)))
			{
				if(!PINFO_FD_VISITED(pinfo))
					ctx->version = PROTOCOL_DDNET;

				proto_tree_add_item(tw_tree, hf_teeworlds_ddnet_token, tvb, 8, 4, ENC_BIG_ENDIAN);
			}
		}
	}

	conversation_t *c = find_conversation_pinfo(pinfo, 0);
	struct context *ctx = conversation_get_proto_data(c, proto_teeworlds);
	ti = proto_tree_add_int(tw_tree, hf_teeworlds_protocol_version, tvb, 0, 0, ctx->version);
	proto_item_set_generated(ti);

	tvbuff_t *next_tvb;
	if(Packet.m_Flags&NET_PACKETFLAG_COMPRESSION) {
		unsigned char *buf = wmem_alloc(pinfo->pool, 1400);
		int Size = huffman_decompress(&gs_huffctx, tvb_get_ptr(tvb, 3, -1), tvb_captured_length_remaining(tvb, 3), buf, 1400);
		if(Size < 0) {
			expert_add_info(pinfo, NULL, &ei_teeworlds_compressionfail);
			return 0;
		}

		next_tvb = tvb_new_child_real_data(tvb, buf, Size, Size);
		add_new_data_source(pinfo, next_tvb, "Decompressed Data");
	}
	else
		next_tvb = tvb_new_subset_remaining(tvb, 3);

	for(int i = 0; i < Packet.m_NumChunks; i++)
	{
		int processed = dissect_chunk(next_tvb, tw_tree);
		next_tvb = tvb_new_subset_remaining(next_tvb, processed);
	}

	if(tvb_captured_length(next_tvb) == 4)
		proto_tree_add_item(tw_tree, hf_teeworlds_ddnet_token, next_tvb, 0, 4, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

void
proto_register_teeworlds(void)
{
	expert_module_t *expert_teeworlds;

	static hf_register_info hf[] = {
		{ &hf_teeworlds_flags,
            {
				"Flags", "tw.flags",
            	FT_UINT8, BASE_DEC, NULL,
				0x0/*FC*/, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_flags_c,
			{
				"Control Flag", "tw.flags.c",
				FT_BOOLEAN, 6, TFS(&tfs_set_notset),
				NET_PACKETFLAG_CONTROL, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_flags_n,
			{
				"Connless Flag", "tw.flags.n",
				FT_BOOLEAN, 6, TFS(&tfs_set_notset),
				NET_PACKETFLAG_CONNLESS, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_flags_r,
			{
				"Resend Flag", "tw.flags.r",
				FT_BOOLEAN, 6, TFS(&tfs_set_notset),
				NET_PACKETFLAG_RESEND, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_flags_o,
			{
				"Compression Flag", "tw.flags.o",
				FT_BOOLEAN, 6, TFS(&tfs_set_notset),
				NET_PACKETFLAG_COMPRESSION, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_ack,
			{
				"Ack", "tw.ack",
				FT_UINT16, BASE_DEC, NULL,
				0x0/*3FF*/, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_nchunks,
			{
				"Num Chunks", "tw.nchunks",
				FT_UINT8, BASE_DEC, NULL,
				0x0, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_exsi,
			{
				"Extended Serverinfo Packet", "tw.exsvinfo",
				FT_BOOLEAN, BASE_NONE, NULL,
				0x0, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_exsi_token,
			{
				"Extended Serverinfo Token", "tw.exsvinfo.token",
				FT_UINT16, BASE_HEX, NULL,
				0x0, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_ctrlmsg,
			{
				"Control Msg", "tw.ctrl",
				FT_UINT8, BASE_DEC, NULL, // Add a table here
				0x0, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_ddnet_token,
			{
				"DDNet Token", "tw.ddnet.token",
				FT_UINT32, BASE_HEX, NULL,
				0x0, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_protocol_version,
			{
				"Version", "tw.version",
				FT_INT32, BASE_NONE, VALS(protocolvstring),
				0x0, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_chunk_flags,
			{
				"Flags", "tw.chunk.flags",
				FT_UINT8, BASE_DEC, NULL,
				0x0, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_chunk_flags_v,
			{
				"Vital Flag", "tw.chunk.flags.v",
				FT_BOOLEAN, 2, TFS(&tfs_true_false),
				NET_CHUNKFLAG_VITAL, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_chunk_flags_r,
			{
				"Resend Flag", "tw.chunk.flags.r",
				FT_BOOLEAN, 2, TFS(&tfs_true_false),
				NET_CHUNKFLAG_RESEND, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_chunk_seq,
			{
				"Sequence No", "tw.chunk.seq",
				FT_UINT16, BASE_DEC, NULL,
				0x0, NULL,
				HFILL
			}
		},
		{ &hf_teeworlds_chunk_data,
			{
				"Data", "tw.chunk.data",
				FT_BYTES, BASE_NONE, NULL,
				0x0, NULL,
				HFILL
			}
		},
	};

	static gint *ett[] = {
        &ett_teeworlds,
		&ett_teeworlds_flags,
		&ett_teeworlds_chunk,
		&ett_teeworlds_chunk_flags,
    };

	static ei_register_info ei[] = {
		{&ei_teeworlds_compressionfail, {"tw.compressionfail", PI_MALFORMED, PI_ERROR, "Decompression failed", EXPFILL}},
	};

    proto_teeworlds = proto_register_protocol("Teeworlds", "TW", "tw");
    proto_register_field_array(proto_teeworlds, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

	expert_teeworlds = expert_register_protocol(proto_teeworlds);
	expert_register_field_array(expert_teeworlds, ei, array_length(ei));

	huffman_init(&gs_huffctx);
}

void
proto_reg_handoff_teeworlds(void)
{
    static dissector_handle_t teeworlds_handle;

    teeworlds_handle = create_dissector_handle(dissect_teeworlds, proto_teeworlds);
    dissector_add_uint("udp.port", TW_PORT, teeworlds_handle);
}


/***************************************************************************
 *            nf_record_t.h
 *
 *  
 *  Copyright  mirko casadei 2011  mc
 *  
 ****************************************************************************/
#include <stdio.h>
#include <inttypes.h>

#define NF_RECORD_T_H


// single IP addr for next hop and bgp next hop
typedef struct ip_addr_s2 {
    union {
        struct {
#ifdef WORDS_BIGENDIAN
            uint32_t fill[3];
            uint32_t _v4;
#else
            uint32_t fill1[2];
            uint32_t _v4;
            uint32_t fill2;
#endif
        };
        uint64_t _v6[2];
    } ip_union;
} ip_addr_t2;

typedef struct nf_record_s {
// Common netflow record,formatted
    int netflow_n;              //netflow block counter
    uint16_t type;              // index 0  0xffff 0000 0000 0000
    uint16_t size;              // index 0  0x0000'ffff'0000 0000
    uint8_t flags;              // index 0  0x0000'0000'ff00'0000
    char sampled[11];
    uint8_t exporter_ref;       // index 0  0x0000'0000'00ff'0000
    uint16_t ext_map;           // index 0  0x0000'0000'0000'ffff
    uint16_t msec_first;        // index 1  0xffff'0000'0000'0000
    uint16_t msec_last;         // index 1  0x0000'ffff'0000'0000
    uint32_t first;             // index 1  0x0000'0000'ffff'ffff
    uint32_t last;              // index 2  0xffff'ffff'0000'0000
    char datestr1[64];
    char datestr2[64];
    uint8_t fwd_status;         // index 2  0x0000'0000'ff00'0000
    uint8_t tcp_flags;          // index 2  0x0000'0000'00ff'0000
    uint8_t prot;               // index 2  0x0000'0000'0000'ff00
    uint8_t tos;                // index 2  0x0000'0000'0000'00ff
    char src_addr_str[40];
    char dst_addr_str[40];
    char tcp_flags_str[16];
    // extension 8
    uint16_t srcport;           // index 3  0xffff'0000'0000'0000
    uint16_t dstport;           // index 3  0x0000'ffff'0000'0000
    union {
        struct {
            uint8_t dst_tos;    // index 3  0x0000'0000'ff00'0000
            uint8_t dir;        // index 3  0x0000'0000'00ff'0000
            uint8_t src_mask;   // index 3  0x0000'0000'0000'ff00
            uint8_t dst_mask;   // index 3  0x0000'0000'0000'00ff
        };
        uint32_t any;
    };
    char s_snet[40];
    char s_dnet[40];
    // extension 4 / 5
    uint32_t input;             // index 4  0xffff'ffff'0000'0000
    uint32_t output;            // index 4  0x0000'0000'ffff'ffff
    // extension 6 / 7
    uint32_t srcas;             // index 5  0xffff'ffff'0000'0000
    uint32_t dstas;             // index 5  0x0000'0000'ffff'ffff
    // IP address block 
    union {
        struct _ipv4_s2 {
#ifdef WORDS_BIGENDIAN
            uint32_t fill1[3];  // <empty>      index 6 0xffff'ffff'ffff'ffff
            // <empty>      index 7 0xffff'ffff'0000'0000
            uint32_t srcaddr;   // srcaddr      index 7 0x0000'0000'ffff'ffff
            uint32_t fill2[3];  // <empty>      index 8 0xffff'ffff'ffff'ffff
            // <empty>      index 9 0xffff'ffff'0000'0000
            uint32_t dstaddr;   // dstaddr      index 9 0x0000'0000'ffff'ffff
#else
            uint32_t fill1[2];  // <empty>      index 6 0xffff'ffff'ffff'ffff
            uint32_t srcaddr;   // srcaddr      index 7 0xffff'ffff'0000'0000
            uint32_t fill2;     // <empty>      index 7 0x0000'0000'ffff'ffff
            uint32_t fill3[2];  // <empty>      index 8 0xffff'ffff'ffff'ffff
            uint32_t dstaddr;   // dstaddr      index 9 0xffff'ffff'0000'0000
            uint32_t fill4;     // <empty>      index 9 0xffff'ffff'0000'0000
#endif
        } _v4_2;
        struct _ipv6_s2 {
            uint64_t srcaddr[2];    // srcaddr[0-1] index 6 0xffff'ffff'ffff'ffff
            // srcaddr[2-3] index 7 0xffff'ffff'ffff'ffff
            uint64_t dstaddr[2];    // dstaddr[0-1] index 8 0xffff'ffff'ffff'ffff
            // dstaddr[2-3] index 9 0xffff'ffff'ffff'ffff
        } _v6_2;
    } ip_union;
    // counter block - expanded to 8 bytes
    uint64_t dPkts;             // index 10 0xffff'ffff'ffff'ffff
    uint64_t dOctets;           // index 11 0xffff'ffff'ffff'ffff
    // extension 9 / 10
    ip_addr_t2 ip_nexthop;      // ipv4   index 13 0x0000'0000'ffff'ffff
    // ipv6   index 12 0xffff'ffff'ffff'ffff
    // ipv6   index 13 0xffff'ffff'ffff'ffff
    char ip_nexthop_str[40];
    // extension 11 / 12
    ip_addr_t2 bgp_nexthop;     // ipv4   index 15 0x0000'0000'ffff'ffff
    // ipv6   index 14 0xffff'ffff'ffff'ffff
    // ipv6   index 15 0xffff'ffff'ffff'ffff
    char bgp_nexthop_str[40];
    // extension 13
    uint16_t src_vlan;          // index 16 0xffff'0000'0000'0000
    uint16_t dst_vlan;          // index 16 0x0000'ffff'0000'0000
    uint32_t fill1;             // align 64bit word
    // extension 14 / 15
    uint64_t out_pkts;          // index 17 0xffff'ffff'ffff'ffff
#	define OffsetOutPackets 	17
// MaskPackets and ShiftPackets already defined

    // extension 16 / 17
    uint64_t out_bytes;         // index 18 0xffff'ffff'ffff'ffff
#	define OffsetOutBytes 		18

    // extension 18 / 19
    uint64_t aggr_flows;        // index 19 0xffff'ffff'ffff'ffff
#	define OffsetAggrFlows 		19
#	define MaskFlows 	 		0xffffffffffffffffLL

    // extension 20
    uint64_t in_src_mac;        // index 20 0xffff'ffff'ffff'ffff
#	define OffsetInSrcMAC 		20
#	define MaskMac 	 			0xffffffffffffffffLL

    // extension 20
    uint64_t out_dst_mac;       // index 21 0xffff'ffff'ffff'ffff
#	define OffsetOutDstMAC 		21

    // extension 21
    uint64_t in_dst_mac;        // index 22 0xffff'ffff'ffff'ffff
#	define OffsetInDstMAC 		22

    // extension 21
    uint64_t out_src_mac;       // index 23 0xffff'ffff'ffff'ffff
#	define OffsetOutSrcMAC 		23

    // extension 22
    uint32_t mpls_label[10];
#	define OffsetMPLS12 		24
#	define OffsetMPLS34 		25
#	define OffsetMPLS56 		26
#	define OffsetMPLS78 		27
#	define OffsetMPLS910 		28
    // extension 23 / 24
    ip_addr_t2 ip_router;       // ipv4   index 30 0x0000'0000'ffff'ffff
    // ipv6   index 29 0xffff'ffff'ffff'ffff
    // ipv6   index 30 0xffff'ffff'ffff'ffff
    char ip_router_str[40];
    // extension 25
    uint16_t fill;              // fill index 31 0xffff'0000'0000'0000
    uint8_t engine_type;        // type index 31 0x0000'ff00'0000'0000
    uint8_t engine_id;          // ID   index 31 0x0000'00ff'0000'0000


    struct nf_record_s *next;

} nf_record_t;

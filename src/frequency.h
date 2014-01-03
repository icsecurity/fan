#include <stdio.h>
#include "uthash.h"
#include "nf_record_t.h"

// Base block dimension of data to collect
#define BLOCK_DIMENSION (10000)
#define MAX_ITERATIONS (3) 
#define RENYI_ALPHA (5)
#define MAX_SYN_ITERATIONS (1) 
#define DELAY_SYN_FLOODING (100)
#define MAX_LOGDIR_LENGTH (60)

#define KULL_LEIB (0)
#define RENYI (1)

// Complex data structures about entropy, or any metric that is based on one probability distribution
struct entropy_data
{
	// ip source array about current data
	struct ip_src_frequency* ips;
	// ip dest array about current data
	struct ip_dst_frequency* ipd;
	// srcport array about current data
	struct freq_srcport* isp;
	// ip src - src port array about current data
	struct ip_src_srcport_frequency* ipsp;
	// ip dst - dst port array about current data
	struct ip_dst_dstport_frequency* ipdp;
	// packets number - bytes number array about current data
	struct npackets_nbytes* pb;
	// ip src - src port - ip dst - dst port array about current data
	struct ipsrcdst_srcdstport* ipsdp;
	// protocol array
	struct protocol_frequency* iprotocol;
	// number of unique ip src
	int unique_src;
	// number of unique ip dst
	int unique_dst;
	// number of unique src port
	int unique_srcport;
	// number of unique ip src - src port
	int unique_ipsrc_srcport;
	// number of unique ip dst - dst port
	int unique_ipdst_dstport;
	// number of unique packets number - bytes number
	int unique_npack_nbytes;
	// number of ip src - src port - ip dst - dst port
	int unique_ipsrcdstport;
	// number of protocol
	int unique_protocol;
};

// Complex data structures for any metric that is based on two probability distributions
struct twodist_data
{
	// frequencies ip source array of last timeslot
	struct ip_src_frequency *ipsrc_past;
	// frequencies ip source array of current timeslot
	struct ip_src_frequency *ipsrc_current;
	// frequencies ip dest array of last timeslot
	struct ip_dst_frequency *ipdst_past;
	// frequencies ip dest array of current timeslot
	struct ip_dst_frequency *ipdst_current;
	// frequencies ip src - src port array of last timeslot
	struct ip_src_srcport_frequency *ipsrcport_past;
	// frequencies ip src - src port array of current timeslot
	struct ip_src_srcport_frequency *ipsrcport_current;
	// frequencies ip dst - dst port array of last timeslot
	struct ip_dst_dstport_frequency *ipdstport_past;
	// frequencies ip dst - dst port array of current timeslot
	struct ip_dst_dstport_frequency *ipdstport_current;
	// frequencies packets number - bytes number array of last timeslot
	struct npackets_nbytes *pb_past;
	// frequencies packets number - bytes number array of current timeslot
	struct npackets_nbytes *pb_current;
	// frequencies ip src - src port - ip dst - dst port array of last timeslot
	struct ipsrcdst_srcdstport *ipsrcdstport_past;
	// frequencies ip src - src port - ip dst - dst port array of current timeslot
	struct ipsrcdst_srcdstport *ipsrcdstport_current;
	// number of unique ip src current
	int unique_src_current;
	// number of unique ip dst current
	int unique_dst_current;
	// number of unique ip src - src port current
	int unique_ipsrc_srcport_current;
	// number of unique ip dst - dst port current
	int unique_ipdst_dstport_current;
	// number of unique packets number - bytes number current
	int unique_npack_nbytes_current;
	// number of ip src - src port - ip dst - dst port current
	int unique_ipsrcdstport_current;
	// number of unique ip src past
	int unique_src_past;
	// number of unique ip dst past
	int unique_dst_past;
	// number of unique ip src - src port past
	int unique_ipsrc_srcport_past;
	// number of unique ip dst - dst port past
	int unique_ipdst_dstport_past;
	// number of unique packets number - bytes number past
	int unique_npack_nbytes_past;
	// number of ip src - src port - ip dst - dst port past
	int unique_ipsrcdstport_past;
};

// flags informations in flows
struct flags_info
{
	uint32_t ip_src;
	uint32_t ip_dst;
	char str_flag[16];
    	uint32_t first; 	
};

// IP source frequency data structure
struct ip_src_frequency
{
	uint32_t ip_src;
	int frequency;
	UT_hash_handle hh;
};

// IP destination frequency data structure
struct ip_dst_frequency
{
	uint32_t ip_dst;
	int frequency;
	UT_hash_handle hh;
};

struct key_protocol_frequency
{
	uint8_t protocol;	
};
// IP destination frequency data structure
struct protocol_frequency
{
	struct key_protocol_frequency key;
	uint8_t protocol;
	int frequency;
	UT_hash_handle hh;
};

// Key for hash purpose
struct key_ipsrcport_frequency
{
	uint32_t ip_src;
	uint16_t srcport;	
};
// IP source - source port frequency data structure
struct ip_src_srcport_frequency
{
	struct key_ipsrcport_frequency key;
	uint32_t ip_src;
	uint16_t srcport;
	int frequency;
	UT_hash_handle hh;
};

// Key for hash purpose
struct key_ipdstport_frequency
{
	uint32_t ip_dst;
	uint16_t dstport;	
};
// IP destination - destination port frequency data structure
struct ip_dst_dstport_frequency
{
	struct key_ipdstport_frequency key;
	uint32_t ip_dst;
	uint16_t dstport;
	int frequency;
	UT_hash_handle hh;
};

// Key for hash purpose
struct key_npackets_nbytes
{
	uint64_t dOctets;
	uint64_t dPkts;		
};
// Packets number - bytes number frequency data structure
struct npackets_nbytes
{
	struct key_npackets_nbytes key;
	uint64_t dOctets;
	uint64_t dPkts;	
	int frequency;
	UT_hash_handle hh;
};

// Key for hash purpose
struct key_ipsrcdst_srcdstport
{
	uint32_t ip_src;
	uint16_t srcport;
	uint32_t ip_dst;
	uint16_t dstport;
};
// IP source - source port - IP destination - destination port frequency data structure
struct ipsrcdst_srcdstport
{
	struct key_ipsrcdst_srcdstport key;
	uint32_t ip_src;
	uint16_t srcport;
	uint32_t ip_dst;
	uint16_t dstport;
	int frequency;	
	UT_hash_handle hh;
};

struct key_prot_port
{
	uint8_t protocol;
	uint16_t port;	
};

struct freq_kmeans_anomaly
{
	struct key_prot_port key;
	uint8_t protocol;
	uint16_t port;
	uint64_t sum_dOctets;
	uint64_t sum_dPkts;	
	uint32_t ip_src;
	int different_pairs;
	UT_hash_handle hh;	
};

struct key_freq_srcport
{
	uint16_t srcport;
};

struct freq_srcport
{
	struct key_freq_srcport key;
	uint16_t srcport;
	int frequency;
	UT_hash_handle hh;
};

struct key_connections
{
	uint32_t ip_src;
	uint32_t ip_dst;	
};

struct freq_connections
{
	struct key_connections key;
	uint32_t ip_src;
	uint32_t ip_dst;
	char** str_flag;	
    	uint32_t first;
	int num;
	UT_hash_handle hh;
};

// Struct to save the frequency of common elements in the computation of divergence between two time slot
struct KL_frequency
{
	int frequency_current;
	int frequency_last;
};

// Compute the entropy using the frequency of data
// data --> frequency array of the symbols
// cnt_unique --> number of unique symbols
// cnt --> total number of symbols
float compute_entropy(int* data, int cnt_unique, int cnt);

// Compare two IP Addresses: return 1 if equal and 0 else
int is_equal_ip(uint32_t n1, uint32_t n2);

// Compare two couple of IP Address and ports: return 1 if equal and 0 else
int is_equal_couple(uint32_t s1, uint32_t s2, uint16_t p1, uint16_t p2);

// Compare two couple of packets number and bytes number: return 1 if equal and 0 else
int is_equal_couple_64(uint64_t s1, uint64_t s2, uint64_t p1, uint64_t p2);

// Compare two quadruple of source and destination address, source and destination ports: return 1 if equal and 0 else
int is_equal_quadruple(uint32_t s1, uint32_t s2,uint32_t d1, uint32_t d2, uint16_t ps1, uint16_t ps2, uint16_t pd1, uint16_t pd2);


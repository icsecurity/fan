#define MAX_SYN_ITERATIONS 1 
#define DELAY_SYN_FLOODING 100

struct flags_info
{
	uint32_t ip_src;
	uint32_t ip_dst;
	char str_flag[16];
    	uint32_t first; 	
};

int count_unusual_handshakes_syn (struct flags_info* data, int count, int delay);
int count_unusual_handshakes_un_syn_rst_sc (struct flags_info* data, int count);
int count_unusual_handshakes_un_syn_synack (struct flags_info* data, int count, int delay);
int count_unusual_handshakes_un_syn_synack_rst_cs (struct flags_info* data, int count);

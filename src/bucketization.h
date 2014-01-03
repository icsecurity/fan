// Bucketization management

// The struct to maintain the the hash table and the array of flows associated with a date
struct metric_struct
{
	char metric[64];
	char** dep;
	int dep_elements;
	UT_hash_handle hh;
};

// The struct to maintain the the hash table and the array of flows associated with a date
struct bucket_struct
{
	char date[64];
	nf_record_t* vett;
	int elements;
	UT_hash_handle hh;
};

// struct generator
struct data_block
{
	char mode[64];
	char date[64];
	int elements_num;
    	char src_addr_str[40];
    	char dst_addr_str[40];
	uint32_t source_ip;
	int source_ip_up;
	int source_ip_down;
	uint32_t destination_ip;
	int dst_ip_up;
	int dst_ip_down;
	int pkts_up;
	int bytes_up;
	int pkts_down;
	int bytes_down;
 	uint16_t srcport;
	int srcport_up;
	int srcport_down;
    	uint16_t dstport;
	int dstport_up;
	int dstport_down;
	uint8_t prot;
	int prot_up;
	int prot_down;
    	char flags_str[16]; 
	int tos_up;
	int tos_down;
};

// Compare two dates and return the difference in seconds
int compare_date(char* date_start,char* date_end,int timeslot);
// Timeslot sensibility 
int ret_timeslot_sens (float timeslot);
// Sort two dates
int date_sort(struct bucket_struct *a, struct bucket_struct *b);

// Compare Date
// date_start -> Date of first flows of the timeslot
// date_end -> Date of current flows of the timeslot
// timeslot -> Timeslot dimension
// Return 0 if timeslot is not elapsed, and 1 otherwise
int compare_date(char* date_start,char* date_end,int timeslot)
{
	char year_start[5];
	char year_end[5];
	char month_start[3];
	char month_end[3];
	char day_start[3];
	char day_end[3];
	char seconds_start[3];
	char seconds_end[3];
	char minutes_start[3];
	char minutes_end[3];
	char hours_start[3];
	char hours_end[3];
	memcpy(year_start,&date_start[0],4);
	year_start[4] = '\0';
	memcpy(year_end,&date_end[0],4);
	year_end[4] = '\0';
	memcpy(month_start,&date_start[5],2);
	month_start[2] = '\0';
	memcpy(month_end,&date_end[5],2);
	month_end[2] = '\0';
	memcpy(day_start,&date_start[8],2);
	day_start[2] = '\0';
	memcpy(day_end,&date_end[8],2);
	day_end[2] = '\0';
	memcpy(seconds_start,&date_start[17],2);
	seconds_start[2] = '\0';
	memcpy(seconds_end,&date_end[17],2);
	seconds_end[2] = '\0';
	memcpy(minutes_start,&date_start[14],2);
	minutes_start[2] = '\0';
	memcpy(minutes_end,&date_end[14],2);
	minutes_end[2] = '\0';
	memcpy(hours_start,&date_start[11],2);
	hours_start[2] = '\0';
	memcpy(hours_end,&date_end[11],2);
	hours_end[2] = '\0';
	int sec_start = atoi(seconds_start);
	int sec_end = atoi(seconds_end);
	int min_start = atoi(minutes_start);
	int min_end = atoi(minutes_end);
	int h_start = atoi(hours_start);
	int h_end = atoi(hours_end);
	int y_start = atoi(year_start);
	int y_end = atoi(year_end);
	int mon_start = atoi(month_start);
	int mon_end = atoi(month_end);
	int d_start = atoi(day_start);
	int d_end = atoi(day_end);
	long total_sec_end = 0;
	long total_sec_start = 0;
	total_sec_end = y_end * 31104000 + mon_end * 2592000 + d_end * 86400 + h_end * 3600 + min_end * 60 + sec_end;
	total_sec_start = y_start * 31104000 + mon_start * 2592000 + d_start * 86400 + h_start * 3600 + min_start * 60 + sec_start;
	if (total_sec_end - total_sec_start == timeslot) return 1;
	else return 0;
}

// Timeslot sensibility 
int ret_timeslot_sens (float timeslot)
{
	if (timeslot > 0 && timeslot < 10) return 19;
	if (timeslot >= 10 && timeslot < 60) return 18;
	if (timeslot >= 60 && timeslot < 3600) return 16;
}

// Sort two dates
int date_sort(struct bucket_struct *a, struct bucket_struct *b)
{
	return strcmp(a->date,b->date);
}


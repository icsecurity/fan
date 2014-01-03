#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include "frequency.h"
#include "log.h"
#include "uthash.h"
#include "ezxml.h"

// Max lenght of a shared librarie name
#define MET_MAX_LENGTH (64)
#define MAX_METRICSET_LENGTH (600)
#define LIBDIR "../lib/"

// Typedef for the functions of the .so module (Metrics)
typedef double (*init)(int);
typedef double (*process)(nf_record_t*,int,char*);
typedef double (*close)(void);
typedef double (*log)(char*);

// Data structure to pass to the thread
struct arg_thread {
char metric[64];
char** dep;
int dep_elements;
init so_init;
process so_process;
close so_close;
log so_log;
nf_record_t* vett_curr;
int curr_flows;
char* logdirectory;
char* bucket_id;
int can_start;
int ended;
};

// The struct to maintain the hash table and the array of flows associated with a date
struct metric_struct
{
	char metric[64];
	char** dep;
	int dep_elements;
	UT_hash_handle hh;
};

// gestione_metriche is a Method Manager. In this function we receive the current timeslot flows, the number of this flows
// and the metrics we have to compute. For every metric we make the computation.
int gestione_metriche(nf_record_t* vett_curr, int past_flows, char* met, char* logdir,  char* bucket_id);

// gestione_metriche is a Method Manager. In this function we receive the current timeslot flows, the number of this flows
// and the metrics we have to compute. For every metric we make the computation.
int gestione_metriche_xml(nf_record_t* vett_curr, int curr_flows, struct metric_struct* metric_list, char* logdir, char* bucket_id,char* xml_path,int max_thread);

// In this function we receive the current timeslot flows, the number of this flows
// and the metrics we have to compute. For every metric we make the computation in multithreading way
int gestione_metriche_multith(nf_record_t* vett_curr, int curr_flows, struct metric_struct* metric_list, char* logdir, char* bucket_id,char* xml_path,int max_thread);

// This function count the number of metric in the metric set. Similar to ret_metrics
int num_metrics (char* metric_set);

// Launch the module thread
void* thread_launcher(void* arguments);

// Verify the correctness of the dependencies
int check_one_nodep(struct metric_struct* metric_list);

// Order the modules by dependencies
int dependencies_sort(struct metric_struct *a, struct metric_struct* b);

// Verify if all module have finished their computation in case of multithreading 
int end_all(struct arg_thread arguments[],int num);


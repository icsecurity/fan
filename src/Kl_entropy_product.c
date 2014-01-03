#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <dlfcn.h>
#include "frequency.h"
#include "log.h"

// Global variables
// Struct entropy_data is in frequency.h
struct entropy_data data;
int iterations = 0;
// File for logging purpose
char filename[FILENAME_MAX];
// File for logging purpose
char resultname[FILENAME_MAX];
// Sum of analyzed flows
int sum_flows = 0;
// Logdir specified
char *spec_logdir = NULL;
// bytes global
float product = 0.0;
float ent_src = 0.0;
float kl_src = 0.0;
float mul = 0.0;

// Function prototypes
// init operation
double so_init (int numflows);
// Process data
double so_process (nf_record_t * r_current, int current_flows,
		   char *bucket_id);
// Close operations: free resources
double so_close (void);
// Specified the log directory
double so_log (char *logdir);
// With this function other modules can access the results of this one and use them in their computation
void **so_getResult (void);

// Initialize the data struct entropy_data and its field
double init_all (int numflows);
// Process data from ip source point of view
int process (nf_record_t * r_current, int current_flows);

// so_init initializes the field of the entropy_data data structure
// numflows --> number of current timeslot flows
double
so_init (int numflows)
{
  iterations++;
  if (iterations == 1)
    {
      strncpy (filename, setFileName (MUL, spec_logdir), FILENAME_MAX);
      strncpy (resultname, setFileNameResults (MUL), FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Kl_entropy_product.so module", -1);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  return STATUS_OK;
}

// Process Data
// r_current --> current timeslot flows
// current_flows --> number of current timeslot flows
double
so_process (nf_record_t * r_current, int current_flows, char *bucket_id)
{
   typedef void** (*get_result)(void);
	
   char* error;
	void* module;
	// Open the .so
	get_result so_getResult;
	module = dlopen("../lib/entropy.so", RTLD_LAZY);
	if (!module) 
	{
		fprintf(stderr, "Couldn't open %s : %s\n",
		"Entropy_modded.so",dlerror());
		return ERR_OPEN_SO;
	}
	/* Get symbol */
	dlerror();
	// Function so_init
	so_getResult= dlsym(module, "so_getResult");
	if ((error = dlerror())) 
	{
		fprintf(stderr, "Couldn't find so_init: %s\n", error);
		return ERR_OPEN_SO;
	}
	void** pro = NULL;
	pro = (*so_getResult)();
	ent_src = *(float*)pro[0];
	module = dlopen("../lib/Kullback-leibler.so", RTLD_LAZY);
	if (!module) 
	{
		fprintf(stderr, "Couldn't open %s : %s\n",
		"Kl_modded.so",dlerror());
		return ERR_OPEN_SO;
	}
	/* Get symbol */
	dlerror();
	// Function so_init
	so_getResult= dlsym(module, "so_getResult");
	if ((error = dlerror())) 
	{
		fprintf(stderr, "Couldn't find so_init: %s\n", error);
		return ERR_OPEN_SO;
	}
	pro = (*so_getResult)();
	kl_src = *(float*)pro[0];
	if (kl_src != 0.0 || ent_src != 0.0) mul = (float) kl_src * ent_src;
	else mul = 0.0;
  writeLogFile (filename, BUCKET, bucket_id, -1);
  printf("[Info] Entropy src * Kl src: %.6f \n", mul);
  // Analyze data by different entropy base
  // IP source
  FILE *fs;
  fs = fopen (resultname, "a");
  if (fs == NULL)
    {
      printf ("Couldn't open file\n");
      return ERR_OPEN_FILE;
    }
  if (iterations == 1)
    {
      fprintf (fs, "Timeslot Bucket,Product \n");
    }
  fprintf (fs, "%s,%.6f \n", bucket_id, mul);
  fclose (fs);
  return STATUS_OK;
}

// Close operations
// Free resources
double
so_close (void)
{
  return STATUS_OK;
}

// Change default log directory
double
so_log (char *logdir)
{
  if (logdir == NULL)
    return STATUS_OK;
  else
    {
      spec_logdir = (char *) malloc (MAX_LOGDIR_LENGTH * sizeof (char));
      if (spec_logdir == NULL)
	{
	  return MEMORY_ERROR;
	}
      strncpy (spec_logdir, logdir, MAX_LOGDIR_LENGTH);
    }
  return STATUS_OK;
}

// With this function other modules can access the results of this one and use them in their computation
void **
so_getResult (void)
{
  void **pt = NULL;
  pt = (void **) malloc (1 * sizeof (void *));
  pt[0] = malloc (sizeof (void *));
  *(float *) pt[0] = mul;
  return pt;
}

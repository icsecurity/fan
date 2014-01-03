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
float num_bytes = 0.0;

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
      strncpy (filename, setFileName (CONTA, spec_logdir), FILENAME_MAX);
      strncpy (resultname, setFileNameResults (CONTA), FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Contabytes.so module", -1);
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
  writeLogFile (filename, BUCKET, bucket_id, -1);
  // Analyze data by different entropy base
  // IP source
  int z = 0;
  float bytes_tot = 0.0;
  for (z = 1; z <= current_flows; z++)
    {
      bytes_tot += (float) r_current[z].dOctets;
    }
  num_bytes = bytes_tot;
  FILE *fs;
  fs = fopen (resultname, "a");
  if (fs == NULL)
    {
      printf ("Couldn't open file\n");
      return ERR_OPEN_FILE;
    }
  if (iterations == 1)
    {
      fprintf (fs, "Timeslot Bucket,Total bytes \n");
    }
  fprintf (fs, "%s,%.6f \n", bucket_id, bytes_tot);
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
  *(float *) pt[0] = num_bytes;
  return pt;
}

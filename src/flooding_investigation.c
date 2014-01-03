#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include "frequency.h"
#include "log.h"

// Threshold
#define LIM_IPDST (8.85)
#define LIM_SRCPORT (8.45)
#define LIM_PKTS (2000000)
#define LIM_PKTSPERSEC (38000.00)
#define TIMESLOT (60)

// Global Variable for passing results to other modules if needed
int alarm_res = 0;

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

float compute_entropy_ipd (int cnt_unique, int cnt);
float compute_entropy_isp (int cnt_unique, int cnt);
int count_pkts (nf_record_t * r_current, int current_flows);

// Initialize the data struct entropy_data and its field
double init_all (int numflows);
// Process data from ip source point of view
int process (nf_record_t * r_current, int current_flows);

// so_init initializes the field of the entropy_data data structure
// numflows --> number of current timeslot flows
double
so_init (int numflows)
{
  int ret_func = 0;
  iterations++;

  if (iterations == 1)
    {
      strncpy (filename, setFileName (FLOODINGINVESTIGATION, spec_logdir),
	       FILENAME_MAX);
      strncpy (resultname, setFileNameResults (FLOODINGINVESTIGATION),
	       FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Flooding_investigation.so module", -1);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  sum_flows += numflows;
  writeLogFile (filename, INFO, "Timeslot flows", numflows);
  printf ("[Info] Start Flooding Investigation Metric \n");
  // We initializes the field of entropy_data structure
  ret_func = init_all (numflows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  return STATUS_OK;
}

// Process Data
// r_current --> current timeslot flows
// current_flows --> number of current timeslot flows
double
so_process (nf_record_t * r_current, int current_flows, char *bucket_id)
{
  // Prepare the output variable
  writeLogFile (filename, BUCKET, bucket_id, -1);
  float entropy_dst = 0.0;
  float entropy_srcport = 0.0;
  int num_pkts = 0;
  float pkts_sec = 0.0;
  int ret_func = 0;
  int alarm_level = 0;
  // Analyze data by different entropy base
  // IP source
  ret_func = process (r_current, current_flows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  //Compute the entropy of IP Destination
  entropy_dst = compute_entropy_ipd (data.unique_dst, current_flows);
  //Output results
  printf ("[Info] Unique IP Destination %d \n", data.unique_dst);
  printf ("[Info] Entropy of IP Destination Addresses is %f \n", entropy_dst);
  writeLogFile (filename, INFO, "Unique IP Destination", data.unique_dst);
  //Compute the entropy of IP Destination
  entropy_srcport = compute_entropy_isp (data.unique_srcport, current_flows);
  //Output results
  printf ("[Info] Unique Source Port %d \n", data.unique_srcport);
  printf ("[Info] Entropy of Source Port is %f \n", entropy_srcport);
  writeLogFile (filename, INFO, "Unique Source Port", data.unique_srcport);
  num_pkts = count_pkts (r_current, current_flows);
  printf ("[Info] Total Packets %d \n", num_pkts);
  pkts_sec = (float) num_pkts / TIMESLOT;
  printf ("[Info] Packets for second %f \n", pkts_sec);
  // Every value is evaluated by comparing it with the threshold
  // Danger levels are 4. If we arrive to the 4th level, then we are in a DDoS state
  if (num_pkts >= LIM_PKTS)
    {
      printf
	("[Alarm] Danger Level 1 exceeded: Packets Volume is over threshold %d \n",
	 LIM_PKTS);
      writeLogFile (filename, ALARM,
		    "Danger Level 1 exceeded: Packets Volume is over the threshold\n\n",
		    -1);
      alarm_level = 1;
      if (entropy_dst <= LIM_IPDST)
	{
	  printf
	    ("[Alarm] Danger Level 2 exceeded: Entropy of IP Destination is under threshold %f \n",
	     LIM_IPDST);
	  writeLogFile (filename, ALARM,
			"Danger Level 2 exceeded: Entropy of IP Destination is under the threshold\n\n",
			-1);
	  alarm_level = 2;
	  if (entropy_srcport <= LIM_SRCPORT)
	    {
	      printf
		("[Alarm] Danger Level 3 exceeded: Entropy of Source Port is under threshold %f \n",
		 LIM_SRCPORT);
	      writeLogFile (filename, ALARM,
			    "Danger Level 3 exceeded: Entropy of Source Port is under the threshold\n\n",
			    -1);
	      alarm_level = 3;
	      if (pkts_sec >= LIM_PKTSPERSEC)
		{
		  printf
		    ("[Alarm] Danger Level 4 exceeded: Packets for second is over threshold %f \n",
		     LIM_PKTSPERSEC);
		  printf ("[!!!Alarm!!!] DDos detected: Danger Level 4! \n");
		  writeLogFile (filename, ALARM,
				"Danger Level 4 exceeded: Packets for second is over the threshold\n\n",
				-1);
		  writeLogFile (filename, ALARM,
				"DDos detected: Danger Level 4!", -1);
		  alarm_level = 4;
		  alarm_res = 1;
		}
	    }

	}
    }
  FILE *fs;
  fs = fopen (resultname, "a");
  if (fs == NULL)
    {
      printf ("Couldn't open file\n");
      return ERR_OPEN_FILE;
    }
  if (iterations == 1)
    {
      fprintf (fs,
	       "Timeslot Bucket,Ip dst entropy,src port entropy, Packets number, Packets number per sec, alarm level \n");
    }
  fprintf (fs, "%s,%.6f,%.6f,%d,%.6f,%d \n", bucket_id, entropy_dst,
	   entropy_srcport, num_pkts, pkts_sec, alarm_level);
  fclose (fs);
  return STATUS_OK;
}

// Close operations
// Free resources
double
so_close (void)
{
  // free resources
  struct ip_dst_frequency *ip_dst, *tmp2;
  HASH_ITER (hh, data.ipd, ip_dst, tmp2)
  {
    HASH_DEL (data.ipd, ip_dst);
    free (ip_dst);
  }
  struct freq_srcport *ip_srcport, *tmp3;
  HASH_ITER (hh, data.isp, ip_srcport, tmp3)
  {
    HASH_DEL (data.isp, ip_srcport);
    free (ip_srcport);
  }
  free (data.ipd);
  free (data.isp);
  data.ipd = NULL;
  data.isp = NULL;
  printf ("[Info] End Flooding Investigation Metric \n");
  writeLogFile (filename, INFO, "Total analyzed flows", sum_flows);
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
  *(int *) pt[0] = alarm_res;
  return pt;
}

// Init all provide to initialize the data field of the entropy_data struct
// INPUT: numflows, the flows of the current timeslot
// data.ips -> ip source
// data.ipd -> ip destination
// data.ipsp -> ip source - source port
// data.ipdp -> ip destination - destination port
// data.pb -> packets number - bytes number
// data.ipsdp -> ip source - source port - ip destination - destination port
double
init_all (int numflows)
{
  //writeLogFile (filename,STATUS_OK,"Starting Method",-1);
  //Allocate the space for block dimension data ip source 
  data.ipd = NULL;
  return STATUS_OK;
}

// Process the flows with ip source point of view
// r_current --> flows of the current timeslot
// current_flows --> number of the flows of the current timeslot
int
process (nf_record_t * r_current, int current_flows)
{
  // Default block dimension
  int z = 0;
  for (z = 1; z <= current_flows; z++)
    {
      // Collect ip dst
      struct ip_dst_frequency *d;
      HASH_FIND_INT (data.ipd, &r_current[z].ip_union._v4_2.dstaddr, d);
      if (d == NULL)
	{
	  d =
	    (struct ip_dst_frequency *)
	    malloc (sizeof (struct ip_dst_frequency));
	  if (d == NULL)
	    {
	      printf ("[Info] Problem in memory allocation in process \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in process",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (d, 0, sizeof (struct ip_dst_frequency));
	  d->ip_dst = r_current[z].ip_union._v4_2.dstaddr;
	  d->frequency = 1;
	  HASH_ADD_INT (data.ipd, ip_dst, d);
	}
      else
	d->frequency += 1;


      // Collect ip dst - dst port
      struct freq_srcport l, *t, *srcport;
      memset (&l, 0, sizeof (struct freq_srcport));
      l.key.srcport = r_current[z].srcport;
      HASH_FIND (hh, data.isp, &l.key, sizeof (struct key_freq_srcport), t);
      if (t == NULL)
	{
	  srcport =
	    (struct freq_srcport *) malloc (sizeof (struct freq_srcport));
	  if (srcport == NULL)
	    {
	      printf ("[Info] Problem in memory allocation in process \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in process",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (srcport, 0, sizeof (struct freq_srcport));
	  srcport->key.srcport = r_current[z].srcport;
	  srcport->srcport = r_current[z].srcport;
	  srcport->frequency = 1;
	  HASH_ADD (hh, data.isp, key, sizeof (struct key_freq_srcport),
		    srcport);
	}
      else
	t->frequency += 1;

    }
  unsigned int num_ip_dst;
  num_ip_dst = HASH_COUNT (data.ipd);
  data.unique_dst = num_ip_dst;
  unsigned int num_srcport;
  num_srcport = HASH_COUNT (data.isp);
  data.unique_srcport = num_srcport;
  return STATUS_OK;
}

// Count packets
int
count_pkts (nf_record_t * r_current, int current_flows)
{
  int z = 0;
  int num_packets = 0;
  for (z = 1; z <= current_flows; z++)
    {
      num_packets += r_current[z].dPkts;
    }
  return num_packets;
}

// Entropy ip dst computing function
float
compute_entropy_ipd (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct ip_dst_frequency *s;
  for (s = data.ipd; s != NULL; s = s->hh.next)
    {
      probability = (float) s->frequency / cnt;
      if (probability > 0.0)
	{
	  entropy_normal -=
	    probability * (float) (log ((double) probability) / log (2.0));
	}
    }
  return entropy_normal;
}

// Entropy ip dst computing function
float
compute_entropy_isp (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct freq_srcport *s;
  for (s = data.isp; s != NULL; s = s->hh.next)
    {
      probability = (float) s->frequency / cnt;
      if (probability > 0.0)
	{
	  entropy_normal -=
	    probability * (float) (log ((double) probability) / log (2.0));
	}
    }
  return entropy_normal;
}

 /*************************************************************************
 *  entropy.c
 *
 *  Compute Source Address IP Entropy   
 *  Compute Destination Address IP Entropy 
 *  Compute Source Addresses IP - Source Port Entropy 
 *  Compute Dest Addresses IP - Dest Port Entropy
 *  Compute Packets Number - Bytes Number Entropy
 *  Compute Source Addresses IP - Source Port - Destination Addresses IP - Destination Port Entropy
 *
 *  This module get in input a collection of flow from a timeslot and compute the entropy on six different
 *  configurations. The informations are returned by stdout and logged into a file named with 
 *  metricname_datehourminutessecondsmilliseconds in the log folder. The entropy_pro structure is complex:
 *  each field is a pointer to specific pro structures, one for each configuration. In the init phase, these pro
 *  structures are initialized, in the process phase are filled with pro and then these pro are used to compute entropy,
 *  in the close phase the pro structures are freed and a new timeslot flows block is ready to be analyzed.
 *
 *
 *  Copyright (C) Andrea Cosentino 2012
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <dlfcn.h>
#include "frequency.h"
#include "log.h"

#define LIM_IPSRC (0.30)
#define LIM_IPDST (0.30)
#define LIM_IPSRCPORT (0.30)
#define LIM_IPDSTPORT (0.30)
#define LIM_PACKBYTES (0.30)
#define LIM_IPSRCDSTPORT (0.30)

// Global Variable for passing results to other modules if needed
float entropy_res_src = 0.0;
float entropy_res_dst = 0.0;
float entropy_res_srcport = 0.0;
float entropy_res_dstport = 0.0;
float entropy_res_npackbytes = 0.0;
float entropy_res_ipsrcdstport = 0.0;

// Global variables
// Struct entropy_pro is in frequency.h
struct entropy_data *pro = NULL;
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
// Process pro
double so_process (nf_record_t * r_current, int current_flows,
		   char *bucket_id);
// Close operations: free resources
double so_close (void);
// Specified the log directory
double so_log (char *logdir);
// With this function other modules can access the results of this one and use them in their computation
void **so_getResult (void);

// Entropy function
float compute_entropy_ips (int cnt_unique, int cnt);
float compute_entropy_ipd (int cnt_unique, int cnt);
float compute_entropy_ipsrcport (int cnt_unique, int cnt);
float compute_entropy_ipdstport (int cnt_unique, int cnt);
float compute_entropy_npackets_nbytes (int cnt_unique, int cnt);
float compute_entropy_ipsrcdstport (int cnt_unique, int cnt);

// Initialize the pro struct entropy_pro and its field
double init_all (int numflows);
// Process pro from ip source point of view
int process (nf_record_t * r_current, int current_flows);

// so_init initializes the field of the entropy_pro pro structure
// numflows --> number of current timeslot flows
double
so_init (int numflows)
{
  iterations++;

  if (iterations == 1)
    {
      strncpy (filename, setFileName (ENTROPYDEP, spec_logdir), FILENAME_MAX);
      strncpy (resultname, setFileNameResults (ENTROPYDEP), FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Entropy_modded.so module", -1);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  sum_flows += numflows;
  writeLogFile (filename, INFO, "Timeslot flows", numflows);
  printf
    ("[Info] Start Computing Entropy for different data: IP source / IP Destination / IP source - source port / IP destination - destination port / Packets number - Bytes Number / IP source - source port - IP destination - Destination port \n");
  // We initializes the field of entropy_pro structure
  return STATUS_OK;
}

// Process pro
// r_current --> current timeslot flows
// current_flows --> number of current timeslot flows
double
so_process (nf_record_t * r_current, int current_flows, char *bucket_id)
{
  writeLogFile (filename, BUCKET, bucket_id, -1);
  // Prepare the output variable
  float entropy_src = 0.0;
  float entropy_dst = 0.0;
  float entropy_ipsrcport = 0.0;
  float entropy_ipdstport = 0.0;
  float entropy_npack_nbytes = 0.0;
  float entropy_ipsrcdstport = 0.0;
  int alarm_src = 0;
  int alarm_dst = 0;
  int alarm_ipsrcport = 0;
  int alarm_ipdstport = 0;
  int alarm_npack_nbytes = 0;
  int alarm_ipsrcdstport = 0;
  typedef struct entropy_data *(*get_result) (void);

  char *error;
  void *module;
  // Open the .so
  get_result so_getResult;
  module = dlopen ("../lib/Frequency_mod.so", RTLD_LAZY);
  if (!module)
    {
      fprintf (stderr, "Couldn't open %s : %s\n", "Frequency_mod.so",
	       dlerror ());
      return ERR_OPEN_SO;
    }
  /* Get symbol */
  dlerror ();
  // Function so_init
  so_getResult = dlsym (module, "so_getResult");
  if ((error = dlerror ()))
    {
      fprintf (stderr, "Couldn't find so_init: %s\n", error);
      return ERR_OPEN_SO;
    }
  pro = (*so_getResult) ();
  // Analyze pro by different entropy base
  // IP source
  //Compute the entropy of IP Source
  entropy_src = compute_entropy_ips (pro->unique_src, current_flows);
  entropy_res_src = entropy_src;
  //Output results
  printf ("[Info] Unique IP Source %d \n", pro->unique_src);
  printf ("[Info] Entropy of IP Source Addresses is %f \n", entropy_src);
  writeLogFile (filename, INFO, "Unique IP Source", pro->unique_src);
  //Compute the entropy of IP Destination
  entropy_dst = compute_entropy_ipd (pro->unique_dst, current_flows);
  entropy_res_dst = entropy_dst;
  //Output results
  printf ("[Info] Unique IP Destination %d \n", pro->unique_dst);
  printf ("[Info] Entropy of IP Destination Addresses is %f \n", entropy_dst);
  writeLogFile (filename, INFO, "Unique IP Destination", pro->unique_dst);
  //Compute the entropy of IP Source - Source Port
  entropy_ipsrcport =
    compute_entropy_ipsrcport (pro->unique_ipsrc_srcport, current_flows);
  entropy_res_srcport = entropy_ipsrcport;
  //Output results
  printf ("[Info] Unique IP Source - Source Port %d \n",
	  pro->unique_ipsrc_srcport);
  printf ("[Info] Entropy of IP Source - Source Port is %f \n",
	  entropy_ipsrcport);
  writeLogFile (filename, INFO, "Unique IP Source - Source Port",
		pro->unique_ipsrc_srcport);
  //Compute the entropy of IP Destination - Destination Port
  entropy_ipdstport =
    compute_entropy_ipdstport (pro->unique_ipdst_dstport, current_flows);
  entropy_res_dstport = entropy_ipdstport;
  //Output results
  printf ("[Info] Unique IP Destination - Destination Port %d \n",
	  pro->unique_ipdst_dstport);
  printf ("[Info] Entropy of IP Destination - Destination Port is %f \n",
	  entropy_ipdstport);
  writeLogFile (filename, INFO, "Unique IP Destination - Destination Port",
		pro->unique_ipdst_dstport);
  //Compute the entropy of Packets Number - Bytes Number
  entropy_npack_nbytes =
    compute_entropy_npackets_nbytes (pro->unique_npack_nbytes, current_flows);
  entropy_res_npackbytes = entropy_npack_nbytes;
  //Output results
  printf ("[Info] Unique Packets Number - Bytes Number %d \n",
	  pro->unique_npack_nbytes);
  printf ("[Info] Entropy of Packets Number - Bytes Number is %f \n",
	  entropy_npack_nbytes);
  writeLogFile (filename, INFO, "Unique Packets Number - Bytes Number",
		pro->unique_npack_nbytes);
  //Compute the entropy of IP source - source port - IP destination - destination port
  entropy_ipsrcdstport =
    compute_entropy_ipsrcdstport (pro->unique_ipsrcdstport, current_flows);
  entropy_res_ipsrcdstport = entropy_ipsrcdstport;
  //Output results
  printf
    ("[Info] Unique IP Source - Source Port - IP Destination - Destination Port %d \n",
     pro->unique_ipsrcdstport);
  printf
    ("[Info] Entropy of IP Source - Source Port - IP Destination - Destination Port is %f \n",
     entropy_ipsrcdstport);
  writeLogFile (filename, INFO,
		"Unique IP Source Addresses - IP Destination Addresses - Source Port - Destination Port",
		pro->unique_ipsrcdstport);
  if (entropy_src <= LIM_IPSRC)
    {
      printf ("[!!!Alarm!!!] Entropy of IP Source is under the limit\n");
      writeLogFile (filename, ALARM,
		    "Entropy of IP Source is under the limit \n\n", -1);
      alarm_src = 1;
    }
  if (entropy_dst <= LIM_IPDST)
    {
      printf ("[!!!Alarm!!!] Entropy of IP Destination is under the limit\n");
      writeLogFile (filename, ALARM,
		    "Entropy of IP Destination is under the limit\n\n", -1);
      alarm_dst = 1;
    }
  if (entropy_ipsrcport <= LIM_IPSRCPORT)
    {
      printf
	("[!!!Alarm!!!] Entropy of IP Source - Source Port is under the limit\n");
      writeLogFile (filename, ALARM,
		    "Entropy of IP Source - Source Port is under the limit\n\n",
		    -1);
      alarm_ipsrcport = 1;
    }
  if (entropy_ipdstport <= LIM_IPDSTPORT)
    {
      printf
	("[!!!Alarm!!!] Entropy of IP Destination - Destination Port is under the limit\n");
      writeLogFile (filename, ALARM,
		    "Entropy of IP Destination - Destination Port is under the limit\n\n",
		    -1);
      alarm_ipdstport = 1;
    }
  if (entropy_npack_nbytes <= LIM_PACKBYTES)
    {
      printf
	("[!!!Alarm!!!] Entropy of Packets Number - Bytes Number is under the limit\n");
      writeLogFile (filename, ALARM,
		    "Entropy of Packets Number - Bytes Number is under the limit\n\n",
		    -1);
      alarm_npack_nbytes = 1;
    }
  if (entropy_ipsrcdstport <= LIM_IPSRCDSTPORT)
    {
      printf
	("[!!!Alarm!!!] Entropy of IP source - source port - IP destination - destination port is under the limit\n");
      writeLogFile (filename, ALARM,
		    "Entropy of IP source - source port - IP destination - destination port is under the limit\n\n",
		    -1);
      alarm_ipsrcdstport = 1;
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
	       "Timeslot Bucket,Ip src entropy, Ip dst entropy, Ip src - src port entropy, Ip dst - dst port entropy, packets number - bytes number entropy, Ip src - src port - Ip dst - dst port entropy, alarm src, alarm dst, alarm src - src port, alarm dst - dst port, alarm packets number - bytes number, alarm Ip src - src port - Ip dst - dst port \n");
    }
  fprintf (fs, "%s,%3.6f,%3.6f,%3.6f,%3.6f,%3.6f,%3.6f,%d,%d,%d,%d,%d,%d \n",
	   bucket_id, entropy_src, entropy_dst, entropy_ipsrcport,
	   entropy_ipdstport, entropy_npack_nbytes, entropy_ipsrcdstport,
	   alarm_src, alarm_dst, alarm_ipsrcport, alarm_ipdstport,
	   alarm_npack_nbytes, alarm_ipsrcdstport);
  fclose (fs);
  return STATUS_OK;
}

// Close operations
// Free resources
double
so_close (void)
{
  printf
    ("[Info] End Computing Entropy for different data: IP source / IP Destination / IP source - source port / IP destination - destination port / Packets number - Bytes Number / IP source - source port - IP destination - Destination port \n");
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
  pt = (void **) malloc (6 * sizeof (void *));
  pt[0] = malloc (sizeof (void *));
  pt[1] = malloc (sizeof (void *));
  pt[2] = malloc (sizeof (void *));
  pt[3] = malloc (sizeof (void *));
  pt[4] = malloc (sizeof (void *));
  pt[5] = malloc (sizeof (void *));
  *(float *) pt[0] = entropy_res_src;
  *(float *) pt[1] = entropy_res_dst;
  *(float *) pt[2] = entropy_res_srcport;
  *(float *) pt[3] = entropy_res_dstport;
  *(float *) pt[4] = entropy_res_npackbytes;
  *(float *) pt[5] = entropy_res_ipsrcdstport;
  return pt;
}

// Entropy ip src computing function
float
compute_entropy_ips (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct ip_src_frequency *s;
  for (s = pro->ips; s != NULL; s = s->hh.next)
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
compute_entropy_ipd (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct ip_dst_frequency *s;
  for (s = pro->ipd; s != NULL; s = s->hh.next)
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

// Entropy ip src - src port computing function
float
compute_entropy_ipsrcport (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct ip_src_srcport_frequency *s;
  for (s = pro->ipsp; s != NULL; s = s->hh.next)
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

// Entropy ip dst - dst port computing function
float
compute_entropy_ipdstport (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct ip_dst_dstport_frequency *s;
  for (s = pro->ipdp; s != NULL; s = s->hh.next)
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

// Entropy packets number - bytes number computing function
float
compute_entropy_npackets_nbytes (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct npackets_nbytes *s;
  for (s = pro->pb; s != NULL; s = s->hh.next)
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

// Entropy ip src - ip dst - src port - dst port computing function
float
compute_entropy_ipsrcdstport (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct ipsrcdst_srcdstport *s;
  for (s = pro->ipsdp; s != NULL; s = s->hh.next)
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

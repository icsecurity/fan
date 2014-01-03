 /*************************************************************************
 *  Kullback-leibler.c
 *
 *  Compute Source Address IP Kullback Leibler divergence   
 *  Compute Destination Address IP Kullback Leibler divergence
 *  Compute Source Addresses IP - Source Port Kullback Leibler divergence
 *  Compute Dest Addresses IP - Dest Port Kullback Leibler divergence
 *  Compute Packets Number - Bytes Number Kullback Leibler divergence
 *  Compute Source Addresses IP - Source Port - Destination Addresses IP - Destination Port Kullback Leibler divergence
 *
 *  This module get in input a collection of flow from a timeslot and the last timeslot, and compute the Kullback Leibler
 *  divergence on six different configurations. The informations are returned by stdout and logged into a file named with 
 *  metricname_datehourminutessecondsmilliseconds in the log folder. The twodist_data structure is complex:
 *  each field is a pointer to specific data structures, one for each configuration. In the init phase, these data
 *  structures are initialized, in the process phase are filled with data and then these data are used to compute Kullback-leibler divergence,
 *  in the close phase the data structures are freed and a new timeslot flows block is ready to be analyzed with the last timeslot.
 *
 *
 *  Copyright (C) Andrea Cosentino 2012
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <dlfcn.h>
#include "frequency.h"
#include "log.h"

#define LIM_IPSRC (1.80)
#define LIM_IPDST (1.80)
#define LIM_IPSRCPORT (1.80)
#define LIM_IPDSTPORT (1.80)
#define LIM_PACKBYTES (1.80)
#define LIM_IPSRCDSTPORT (1.80)

// Global Variable for passing results to other modules if needed
float kl_res_src = 0.0;
float kl_res_dst = 0.0;
float kl_res_srcport = 0.0;
float kl_res_dstport = 0.0;
float kl_res_npackbytes = 0.0;
float kl_res_ipsrcdstport = 0.0;

// Global variables
// twodist_data data structure is defined in frequency.h
struct twodist_data *pro;
// iterations number
int iterations = 0;
// filename to log into
char filename[FILENAME_MAX];
// File for logging purpose
char resultname[FILENAME_MAX];
// Total analyzed flows
int sum_flows = 0;
// Logdir specified
char *spec_logdir = NULL;
// Variable for information purpose
int last_numflows;
int current_numflows;

// Function prototypes
// init operation
double so_init (int numflows);
// process data
double so_process (nf_record_t * r_current, int current_flows,
		   char *bucket_id);
// close operations: free resources
double so_close (void);
// Specified the log directory
double so_log (char *logdir);
// With this function other modules can access the results of this one and use them in their computation
void **so_getResult (void);

// Process data from ip source point of view
int process (nf_record_t * r_current, int current_flows);
// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int copy_current_src (void);
// Copy the current timeslot flows with ip dest point of view in the past timeslot flows
int copy_current_dst (void);
// Copy the current timeslot flows with ip source - source port point of view in the past timeslot flows
int copy_current_srcport (void);
// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int copy_current_dstport (void);
// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int copy_current_npackbyt (void);
// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int copy_current_ipsrcdstport (void);

// Compute Kullback-Leibler on hash tables by IP Source
float compute_src_div (void);
// Compute Kullback-Leibler on hash tables by IP Destination
float compute_dst_div (void);
// Compute Kullback-Leibler on hash tables by IP Source - Source Port
float compute_srcport_div (void);
// Compute Kullback-Leibler on hash tables by IP Destination - Destination Port
float compute_dstport_div (void);
// Compute Kullback-Leibler on hash tables by IP Destination - Destination Port
float compute_npackbyt_div (void);
// Compute Kullback-Leibler on hash tables by IP Source - Source Port - IP Destination - Destination Port
float compute_ipsrcdstport_div (void);

// so_init initializes the field of the twodist_data data structure
// numflows --> number of current timeslot flows
double
so_init (int numflows)
{
  iterations++;
  sum_flows += numflows;
  if (iterations == 1)
    {
      strncpy (filename, setFileName (KULLBACKLOGNAMEDEP, spec_logdir),
	       FILENAME_MAX);
      strncpy (resultname, setFileNameResults (KULLBACKLOGNAMEDEP),
	       FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Kl_modded.so module", -1);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  if (iterations == 1)
    {
      current_numflows = numflows;
    }
  else
    {
      last_numflows = current_numflows;
      current_numflows = numflows;
    }
  if (iterations >= 2)
    {
      writeLogFile (filename, INFO, "Last Timeslot Flows Number",
		    last_numflows);
      writeLogFile (filename, INFO, "Current Timeslot Flows Number",
		    current_numflows);
      printf
	("[Info] Start Computing Kullback-Leibler Divergence on the last two Timeslots \n");
      printf ("[Info] Last Timeslot Flows Number %d \n", last_numflows);
      printf ("[Info] Current Timeslot Flows Number %d \n", current_numflows);
    }
  return STATUS_OK;
}

// Process Data
// r_current --> current timeslot flows
// current_flows --> number of current timeslot flows
double
so_process (nf_record_t * r_current, int current_flows, char *bucket_id)
{
  writeLogFile (filename, BUCKET, bucket_id, -1);
  float kl_divergence_src = 0.0;
  float kl_divergence_dst = 0.0;
  float kl_divergence_ipsrcport = 0.0;
  float kl_divergence_ipdstport = 0.0;
  float kl_divergence_npackbytes = 0.0;
  float kl_divergence_ipsrcdstport = 0.0;
  int alarm_src = 0;
  int alarm_dst = 0;
  int alarm_ipsrcport = 0;
  int alarm_ipdstport = 0;
  int alarm_npack_nbytes = 0;
  int alarm_ipsrcdstport = 0;
  int ret_func = 0;
  ret_func = process (r_current, current_flows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  if (iterations >= 2)
    {
      kl_divergence_src = compute_src_div ();
      kl_res_src = kl_divergence_src;
      kl_divergence_dst = compute_dst_div ();
      kl_res_dst = kl_divergence_dst;
      kl_divergence_ipsrcport = compute_srcport_div ();
      kl_res_srcport = kl_divergence_ipsrcport;
      kl_divergence_ipdstport = compute_dstport_div ();
      kl_res_dstport = kl_divergence_ipdstport;
      kl_divergence_npackbytes = compute_npackbyt_div ();
      kl_res_npackbytes = kl_divergence_npackbytes;
      kl_divergence_ipsrcdstport = compute_ipsrcdstport_div ();
      kl_res_ipsrcdstport = kl_divergence_ipsrcdstport;
      printf ("[Info] IP Source Kullback Leibler Divergence is: %f \n",
	      kl_divergence_src);
      printf ("[Info] IP Destination Kullback Leibler Divergence is: %f \n",
	      kl_divergence_dst);
      printf
	("[Info] IP Source - Source Port Kullback Leibler Divergence is: %f \n",
	 kl_divergence_ipsrcport);
      printf
	("[Info] IP Destination - Destination Port Kullback Leibler Divergence is: %f \n",
	 kl_divergence_ipdstport);
      printf
	("[Info] Packets Number - Bytes Number Kullback Leibler Divergence is: %f \n",
	 kl_divergence_npackbytes);
      printf
	("[Info] IP Source - Source Port - IP Destination - Destination Port Kullback Leibler Divergence is: %f \n",
	 kl_divergence_ipsrcdstport);
      if (kl_divergence_src >= LIM_IPSRC)
	{
	  printf
	    ("[!!!Alarm!!!] Kullback-Leibler Divergence of IP Source is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Kullback-Leibler Divergence of IP Source is over the limit\n\n",
			-1);
	  alarm_src = 1;
	}
      if (kl_divergence_dst >= LIM_IPDST)
	{
	  printf
	    ("[!!!Alarm!!!] Kullback-Leibler Divergence of IP Destination is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Kullback-Leibler Divergence of IP Destination is over the limit\n\n",
			-1);
	  alarm_dst = 1;
	}
      if (kl_divergence_ipsrcport >= LIM_IPSRCPORT)
	{
	  printf
	    ("[!!!Alarm!!!] Kullback-Leibler Divergence of IP Source - Source Port is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Kullback-Leibler Divergence of IP Source - Source Port is over the limit\n\n",
			-1);
	  alarm_ipsrcport = 1;
	}
      if (kl_divergence_ipdstport >= LIM_IPDSTPORT)
	{
	  printf
	    ("[!!!Alarm!!!] Kullback-Leibler Divergence of IP Destination - Destination Port is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Kullback-Leibler Divergence of IP Destination - Destination Port is over the limit\n\n",
			-1);
	  alarm_ipdstport = 1;
	}
      if (kl_divergence_npackbytes >= LIM_PACKBYTES)
	{
	  printf
	    ("[!!!Alarm!!!] Kullback-Leibler Divergence of Packets Number - Bytes Number is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Kullback-Leibler Divergence of Packets Number - Bytes Number is over the limit\n\n",
			-1);
	  alarm_npack_nbytes = 1;
	}
      if (kl_divergence_ipsrcdstport >= LIM_IPSRCDSTPORT)
	{
	  printf
	    ("[!!!Alarm!!!] Kullback-Leibler Divergence of IP source - source port - IP destination - destination port is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Kullback-Leibler Divergence of IP source - source port - IP destination - destination port is over the limit\n\n",
			-1);
	  alarm_ipsrcdstport = 1;
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
	       "Timeslot Bucket,Ip src KL divergence, Ip dst KL divergence, Ip src - src port KL divergence, Ip dst - dst port KL divergence, packets number - bytes number KL divergence, Ip src - src port - Ip dst - dst port KL divergence, alarm src, alarm dst, alarm src - src port, alarm dst - dst port, alarm packets number - bytes number, alarm Ip src - src port - Ip dst - dst port \n");
    }
  fprintf (fs, "%s,%3.6f,%3.6f,%3.6f,%3.6f,%3.6f,%3.6f,%d,%d,%d,%d,%d,%d \n",
	   bucket_id, kl_divergence_src, kl_divergence_dst,
	   kl_divergence_ipsrcport, kl_divergence_ipdstport,
	   kl_divergence_npackbytes, kl_divergence_ipsrcdstport, alarm_src,
	   alarm_dst, alarm_ipsrcport, alarm_ipdstport, alarm_npack_nbytes,
	   alarm_ipsrcdstport);
  fclose (fs);
  return STATUS_OK;
}

// Close operations
// Free resources and copy current timeslot flows data in the last timeslot flows data
double
so_close (void)
{
  int ret_func = 0;
  ret_func = copy_current_src ();
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  ret_func = copy_current_dst ();
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  ret_func = copy_current_srcport ();
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  ret_func = copy_current_dstport ();
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  ret_func = copy_current_npackbyt ();
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  ret_func = copy_current_ipsrcdstport ();
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  if (iterations >= 2)
    {
      writeLogFile (filename, INFO, "Total analyzed flows", sum_flows);
      printf
	("[Info] End Computing Kullback-Leibler Divergence on the last two Timeslots \n");
    }
  return STATUS_OK;
}

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
  *(float *) pt[0] = kl_res_src;
  *(float *) pt[1] = kl_res_dst;
  *(float *) pt[2] = kl_res_srcport;
  *(float *) pt[3] = kl_res_dstport;
  *(float *) pt[4] = kl_res_npackbytes;
  *(float *) pt[5] = kl_res_ipsrcdstport;
  return pt;
}

// Process the flows with ip source point of view
// r_current --> flows of the current timeslot
// current_flows --> number of the flows of the current timeslot
int
process (nf_record_t * r_current, int current_flows)
{
  typedef struct twodist_data *(*get_result) (void);

  char *error;
  void *module;
  // Open the .so
  get_result so_getResulttwodist;
  module = dlopen ("../lib/Frequency_mod.so", RTLD_LAZY);
  if (!module)
    {
      fprintf (stderr, "Couldn't open %s : %s\n", "entropy.so", dlerror ());
      return ERR_OPEN_SO;
    }
  /* Get symbol */
  dlerror ();
  // Function so_init
  so_getResulttwodist = dlsym (module, "so_getResulttwodist");
  if ((error = dlerror ()))
    {
      fprintf (stderr, "Couldn't find so_init: %s\n", error);
      return ERR_OPEN_SO;
    }
  pro = (*so_getResulttwodist) ();
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_src (void)
{
  pro->ipsrc_past = NULL;
  struct ip_src_frequency *ip_src, *tmp;
  HASH_ITER (hh, pro->ipsrc_current, ip_src, tmp)
  {
    struct ip_src_frequency *s;
    s = (struct ip_src_frequency *) malloc (sizeof (struct ip_src_frequency));
    if (s == NULL)
      {
	printf ("[Info] Problem in memory allocation in process \n");
	writeLogFileAnalyzer (filename, MEMORY_ERROR,
			      "Problem in memory allocation in process", -1,
			      NULL);
	return MEMORY_ERROR;
      }
    memset (s, 0, sizeof (struct ip_src_frequency));
    s->ip_src = ip_src->ip_src;
    s->frequency = ip_src->frequency;
    HASH_ADD_INT (pro->ipsrc_past, ip_src, s);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_dst (void)
{
  pro->ipdst_past = NULL;
  struct ip_dst_frequency *ip_dst, *tmp;
  HASH_ITER (hh, pro->ipdst_current, ip_dst, tmp)
  {
    struct ip_dst_frequency *s;
    s = (struct ip_dst_frequency *) malloc (sizeof (struct ip_dst_frequency));
    if (s == NULL)
      {
	printf ("[Info] Problem in memory allocation in process \n");
	writeLogFileAnalyzer (filename, MEMORY_ERROR,
			      "Problem in memory allocation in process", -1,
			      NULL);
	return MEMORY_ERROR;
      }
    memset (s, 0, sizeof (struct ip_dst_frequency));
    s->ip_dst = ip_dst->ip_dst;
    s->frequency = ip_dst->frequency;
    HASH_ADD_INT (pro->ipdst_past, ip_dst, s);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_srcport (void)
{
  pro->ipsrcport_past = NULL;
  struct ip_src_srcport_frequency *ip_src, *tmp;
  HASH_ITER (hh, pro->ipsrcport_current, ip_src, tmp)
  {
    struct ip_src_srcport_frequency *ipsrcport;
    ipsrcport =
      (struct ip_src_srcport_frequency *)
      malloc (sizeof (struct ip_src_srcport_frequency));
    if (ipsrcport == NULL)
      {
	printf ("[Info] Problem in memory allocation in process \n");
	writeLogFileAnalyzer (filename, MEMORY_ERROR,
			      "Problem in memory allocation in process", -1,
			      NULL);
	return MEMORY_ERROR;
      }
    memset (ipsrcport, 0, sizeof (struct ip_src_srcport_frequency));
    ipsrcport->key.ip_src = ip_src->key.ip_src;
    ipsrcport->key.srcport = ip_src->key.srcport;
    ipsrcport->ip_src = ip_src->ip_src;
    ipsrcport->srcport = ip_src->srcport;
    ipsrcport->frequency = ip_src->frequency;
    HASH_ADD (hh, pro->ipsrcport_past, key,
	      sizeof (struct key_ipsrcport_frequency), ipsrcport);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_dstport (void)
{
  pro->ipdstport_past = NULL;
  struct ip_dst_dstport_frequency *ip_dst, *tmp;
  HASH_ITER (hh, pro->ipdstport_current, ip_dst, tmp)
  {
    struct ip_dst_dstport_frequency *ipdstport;
    ipdstport =
      (struct ip_dst_dstport_frequency *)
      malloc (sizeof (struct ip_dst_dstport_frequency));
    if (ipdstport == NULL)
      {
	printf ("[Info] Problem in memory allocation in process \n");
	writeLogFileAnalyzer (filename, MEMORY_ERROR,
			      "Problem in memory allocation in process", -1,
			      NULL);
	return MEMORY_ERROR;
      }
    memset (ipdstport, 0, sizeof (struct ip_dst_dstport_frequency));
    ipdstport->key.ip_dst = ip_dst->key.ip_dst;
    ipdstport->key.dstport = ip_dst->key.dstport;
    ipdstport->ip_dst = ip_dst->ip_dst;
    ipdstport->dstport = ip_dst->dstport;
    ipdstport->frequency = ip_dst->frequency;
    HASH_ADD (hh, pro->ipdstport_past, key,
	      sizeof (struct key_ipdstport_frequency), ipdstport);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_npackbyt (void)
{
  pro->pb_past = NULL;
  struct npackets_nbytes *pb, *tmp;
  HASH_ITER (hh, pro->pb_current, pb, tmp)
  {
    struct npackets_nbytes *npackbyt;
    npackbyt =
      (struct npackets_nbytes *) malloc (sizeof (struct npackets_nbytes));
    if (npackbyt == NULL)
      {
	printf ("[Info] Problem in memory allocation in process \n");
	writeLogFileAnalyzer (filename, MEMORY_ERROR,
			      "Problem in memory allocation in process", -1,
			      NULL);
	return MEMORY_ERROR;
      }
    memset (npackbyt, 0, sizeof (struct npackets_nbytes));
    npackbyt->key.dOctets = pb->key.dOctets;
    npackbyt->key.dPkts = pb->key.dPkts;
    npackbyt->dOctets = pb->dOctets;
    npackbyt->dPkts = pb->dPkts;
    npackbyt->frequency = pb->frequency;
    HASH_ADD (hh, pro->pb_past, key, sizeof (struct key_npackets_nbytes),
	      npackbyt);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_ipsrcdstport (void)
{
  pro->ipsrcdstport_past = NULL;
  struct ipsrcdst_srcdstport *spdp, *tmp;
  HASH_ITER (hh, pro->ipsrcdstport_current, spdp, tmp)
  {
    struct ipsrcdst_srcdstport *ipsrcdstport;
    ipsrcdstport =
      (struct ipsrcdst_srcdstport *)
      malloc (sizeof (struct ipsrcdst_srcdstport));
    if (ipsrcdstport == NULL)
      {
	printf ("[Info] Problem in memory allocation in process \n");
	writeLogFileAnalyzer (filename, MEMORY_ERROR,
			      "Problem in memory allocation in process", -1,
			      NULL);
	return MEMORY_ERROR;
      }
    memset (ipsrcdstport, 0, sizeof (struct ipsrcdst_srcdstport));
    ipsrcdstport->key.ip_src = spdp->key.ip_src;
    ipsrcdstport->key.srcport = spdp->key.srcport;
    ipsrcdstport->key.ip_dst = spdp->key.ip_dst;
    ipsrcdstport->key.dstport = spdp->key.dstport;
    ipsrcdstport->ip_src = spdp->ip_src;
    ipsrcdstport->srcport = spdp->srcport;
    ipsrcdstport->ip_dst = spdp->ip_dst;
    ipsrcdstport->dstport = spdp->dstport;
    ipsrcdstport->frequency = spdp->frequency;
    HASH_ADD (hh, pro->ipsrcdstport_past, key,
	      sizeof (struct key_ipsrcdst_srcdstport), ipsrcdstport);
  }
  return STATUS_OK;
}

// Compute Kullback-Leibler on hash tables by IP Source
float
compute_src_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float KL_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  int cnt = 0;
  struct ip_src_frequency *ip_src_current, *tmp_current;
  HASH_ITER (hh, pro->ipsrc_current, ip_src_current, tmp_current)
  {
    struct ip_src_frequency *s;
    HASH_FIND_INT (pro->ipsrc_past, &ip_src_current->ip_src, s);
    if (s != NULL)
      {
	sum_frequency_current += ip_src_current->frequency;
	sum_frequency_past += s->frequency;
      }
  }
  HASH_ITER (hh, pro->ipsrc_current, ip_src_current, tmp_current)
  {
    struct ip_src_frequency *s;
    HASH_FIND_INT (pro->ipsrc_past, &ip_src_current->ip_src, s);
    if (s != NULL)
      {
	cnt++;
	//printf("passo -1 %f \n", KL_divergence);
	// Probability of i-th elements in current time-slot
	p_current =
	  (float) ip_src_current->frequency / (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) s->frequency / (float) sum_frequency_past;
	// Compute KL
	if (p_current > 0.0 && p_last > 0.0)
	  KL_divergence += p_current * log (p_current / p_last);
	//printf("p_Current %.10f p_Last %.10f Log %f KL %f \n", p_current,p_last,log (p_current/p_last), KL_divergence);
      }
  }
  struct ip_src_frequency *ip_src, *tmp;
  HASH_ITER (hh, pro->ipsrc_past, ip_src, tmp)
  {
    HASH_DEL (pro->ipsrc_past, ip_src);
    free (ip_src);
  }
  pro->ipsrc_past = NULL;
  printf ("[Info] Common Unique IP Source Addresses: %d \n", cnt);
  writeLogFile (filename, INFO, "Common Unique IP Source Addresses", cnt);
  return KL_divergence;
}

// Compute Kullback-Leibler on hash tables by IP Destination
float
compute_dst_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float KL_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  int cnt = 0;
  struct ip_dst_frequency *ip_dst_current, *tmp_current;
  HASH_ITER (hh, pro->ipdst_current, ip_dst_current, tmp_current)
  {
    struct ip_dst_frequency *s;
    HASH_FIND_INT (pro->ipdst_past, &ip_dst_current->ip_dst, s);
    if (s != NULL)
      {
	sum_frequency_current += ip_dst_current->frequency;
	sum_frequency_past += s->frequency;
      }
  }
  HASH_ITER (hh, pro->ipdst_current, ip_dst_current, tmp_current)
  {
    struct ip_dst_frequency *s;
    HASH_FIND_INT (pro->ipdst_past, &ip_dst_current->ip_dst, s);
    if (s != NULL)
      {
	cnt++;
	//printf("passo -1 %f \n", KL_divergence);
	// Probability of i-th elements in current time-slot
	p_current =
	  (float) ip_dst_current->frequency / (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) s->frequency / (float) sum_frequency_past;
	// Compute KL
	if (p_current > 0.0 && p_last > 0.0)
	  KL_divergence += p_current * log (p_current / p_last);
	//printf("p_Current %.10f p_Last %.10f Log %f KL %f \n", p_current,p_last,log (p_current/p_last), KL_divergence);
      }
  }
  struct ip_dst_frequency *ip_dst, *tmp;
  HASH_ITER (hh, pro->ipdst_past, ip_dst, tmp)
  {
    HASH_DEL (pro->ipdst_past, ip_dst);
    free (ip_dst);
  }
  pro->ipdst_past = NULL;
  printf ("[Info] Common Unique IP Destination Addresses: %d \n", cnt);
  writeLogFile (filename, INFO, "Common Unique IP Destination Addresses",
		cnt);
  return KL_divergence;
}

// Compute Kullback-Leibler on hash tables by IP Destination
float
compute_srcport_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float KL_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  int cnt = 0;
  struct ip_src_srcport_frequency *ip_srcport_current, *tmp_current;
  HASH_ITER (hh, pro->ipsrcport_current, ip_srcport_current, tmp_current)
  {
    struct ip_src_srcport_frequency *rs;
    HASH_FIND (hh, pro->ipsrcport_past, &ip_srcport_current->key,
	       sizeof (struct key_ipsrcport_frequency), rs);
    if (rs != NULL)
      {
	sum_frequency_current += ip_srcport_current->frequency;
	sum_frequency_past += rs->frequency;
      }
  }
  HASH_ITER (hh, pro->ipsrcport_current, ip_srcport_current, tmp_current)
  {
    struct ip_src_srcport_frequency *rs;
    HASH_FIND (hh, pro->ipsrcport_past, &ip_srcport_current->key,
	       sizeof (struct key_ipsrcport_frequency), rs);
    if (rs != NULL)
      {
	cnt++;
	//printf("passo -1 %f \n", KL_divergence);
	// Probability of i-th elements in current time-slot
	p_current =
	  (float) ip_srcport_current->frequency /
	  (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) rs->frequency / (float) sum_frequency_past;
	// Compute KL
	if (p_current > 0.0 && p_last > 0.0)
	  KL_divergence += p_current * log (p_current / p_last);
	//printf("p_Current %.10f p_Last %.10f Log %f KL %f \n", p_current,p_last,log (p_current/p_last), KL_divergence);
      }
  }
  struct ip_src_srcport_frequency *current_user_p, *tmp1;
  HASH_ITER (hh, pro->ipsrcport_past, current_user_p, tmp1)
  {
    HASH_DEL (pro->ipsrcport_past, current_user_p);
    free (current_user_p);
  }
  printf ("[Info] Common Unique IP Source Addresses - Source Port: %d \n",
	  cnt);
  writeLogFile (filename, INFO,
		"Common Unique IP Source Addresses - Source Port", cnt);
  pro->ipsrcport_past = NULL;
  return KL_divergence;
}

// Compute Kullback-Leibler on hash tables by IP Destination - Destination Port
float
compute_dstport_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float KL_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  int cnt = 0;
  struct ip_dst_dstport_frequency *ip_dstport_current, *tmp_current;
  HASH_ITER (hh, pro->ipdstport_current, ip_dstport_current, tmp_current)
  {
    struct ip_dst_dstport_frequency *rs;
    HASH_FIND (hh, pro->ipdstport_past, &ip_dstport_current->key,
	       sizeof (struct key_ipdstport_frequency), rs);
    if (rs != NULL)
      {
	sum_frequency_current += ip_dstport_current->frequency;
	sum_frequency_past += rs->frequency;
      }
  }
  HASH_ITER (hh, pro->ipdstport_current, ip_dstport_current, tmp_current)
  {
    struct ip_dst_dstport_frequency *rs;
    HASH_FIND (hh, pro->ipdstport_past, &ip_dstport_current->key,
	       sizeof (struct key_ipdstport_frequency), rs);
    if (rs != NULL)
      {
	cnt++;
	//printf("passo -1 %f \n", KL_divergence);
	// Probability of i-th elements in current time-slot
	p_current =
	  (float) ip_dstport_current->frequency /
	  (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) rs->frequency / (float) sum_frequency_past;
	// Compute KL
	if (p_current > 0.0 && p_last > 0.0)
	  KL_divergence += p_current * log (p_current / p_last);
	//printf("p_Current %.10f p_Last %.10f Log %f KL %f \n", p_current,p_last,log (p_current/p_last), KL_divergence);
      }
  }
  struct ip_dst_dstport_frequency *current_user_p, *tmp1;
  HASH_ITER (hh, pro->ipdstport_past, current_user_p, tmp1)
  {
    HASH_DEL (pro->ipdstport_past, current_user_p);
    free (current_user_p);
  }
  printf
    ("[Info] Common Unique IP Destination Addresses - Destination Port: %d \n",
     cnt);
  writeLogFile (filename, INFO,
		"Common Unique IP Destination Addresses - Destination Port",
		cnt);
  pro->ipdstport_past = NULL;
  return KL_divergence;
}

// Compute Kullback-Leibler on hash tables by Packets Number - Bytes Number 
float
compute_npackbyt_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float KL_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  int cnt = 0;
  struct npackets_nbytes *m, *tmp_current;
  HASH_ITER (hh, pro->pb_current, m, tmp_current)
  {
    struct npackets_nbytes *rs;
    HASH_FIND (hh, pro->pb_past, &m->key, sizeof (struct key_npackets_nbytes),
	       rs);
    if (rs != NULL)
      {
	sum_frequency_current += m->frequency;
	sum_frequency_past += rs->frequency;
      }
  }
  HASH_ITER (hh, pro->pb_current, m, tmp_current)
  {
    struct npackets_nbytes *rs;
    HASH_FIND (hh, pro->pb_past, &m->key, sizeof (struct key_npackets_nbytes),
	       rs);
    if (rs != NULL)
      {
	cnt++;
	//printf("passo -1 %f \n", KL_divergence);
	// Probability of i-th elements in current time-slot
	p_current = (float) m->frequency / (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) rs->frequency / (float) sum_frequency_past;
	// Compute KL
	if (p_current > 0.0 && p_last > 0.0)
	  KL_divergence += p_current * log (p_current / p_last);
	//printf("p_Current %.10f p_Last %.10f Log %f KL %f \n", p_current,p_last,log (p_current/p_last), KL_divergence);
      }
  }
  struct npackets_nbytes *current_user_p, *tmp1;
  HASH_ITER (hh, pro->pb_past, current_user_p, tmp1)
  {
    HASH_DEL (pro->pb_past, current_user_p);
    free (current_user_p);
  }
  printf ("[Info] Common Unique Packets Number - Bytes Number: %d \n", cnt);
  writeLogFile (filename, INFO, "Common Unique Packets Number - Bytes Number",
		cnt);
  pro->pb_past = NULL;
  return KL_divergence;
}

// Compute Kullback-Leibler on hash tables by IP Source - Source Port - IP Destination - Destination Port
float
compute_ipsrcdstport_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float KL_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  int cnt = 0;
  struct ipsrcdst_srcdstport *m, *tmp_current;
  HASH_ITER (hh, pro->ipsrcdstport_current, m, tmp_current)
  {
    struct ipsrcdst_srcdstport *rs;
    HASH_FIND (hh, pro->ipsrcdstport_past, &m->key,
	       sizeof (struct key_ipsrcdst_srcdstport), rs);
    if (rs != NULL)
      {
	sum_frequency_current += m->frequency;
	sum_frequency_past += rs->frequency;
      }
  }
  HASH_ITER (hh, pro->ipsrcdstport_current, m, tmp_current)
  {
    struct ipsrcdst_srcdstport *rs;
    HASH_FIND (hh, pro->ipsrcdstport_past, &m->key,
	       sizeof (struct key_ipsrcdst_srcdstport), rs);
    if (rs != NULL)
      {
	cnt++;
	//printf("passo -1 %f \n", KL_divergence);
	// Probability of i-th elements in current time-slot
	p_current = (float) m->frequency / (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) rs->frequency / (float) sum_frequency_past;
	// Compute KL
	if (p_current > 0.0 && p_last > 0.0)
	  KL_divergence += p_current * log (p_current / p_last);
	//printf("p_Current %.10f p_Last %.10f Log %f KL %f \n", p_current,p_last,log (p_current/p_last), KL_divergence);
      }
  }
  struct ipsrcdst_srcdstport *current_user_p, *tmp1;
  HASH_ITER (hh, pro->ipsrcdstport_past, current_user_p, tmp1)
  {
    HASH_DEL (pro->ipsrcdstport_past, current_user_p);
    free (current_user_p);
  }
  printf
    ("[Info] Common Unique IP Source - IP Destination - Source Port - Destination Port: %d \n",
     cnt);
  writeLogFile (filename, INFO,
		"Common Unique IP Source - IP Destination - Source Port - Destination Port",
		cnt);
  pro->ipsrcdstport_past = NULL;
  return KL_divergence;
}

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
 *  metricname_datehourminutessecondsmilliseconds in the log folder. The entropy_data structure is complex:
 *  each field is a pointer to specific data structures, one for each configuration. In the init phase, these data
 *  structures are initialized, in the process phase are filled with data and then these data are used to compute entropy,
 *  in the close phase the data structures are freed and a new timeslot flows block is ready to be analyzed.
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

float compute_entropy_ips (int cnt_unique, int cnt);
float compute_entropy_ipd (int cnt_unique, int cnt);
float compute_entropy_ipsrcport (int cnt_unique, int cnt);
float compute_entropy_ipdstport (int cnt_unique, int cnt);
float compute_entropy_npackets_nbytes (int cnt_unique, int cnt);
float compute_entropy_ipsrcdstport (int cnt_unique, int cnt);

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
      strncpy (filename, setFileName (ENTROPY, spec_logdir), FILENAME_MAX);
      strncpy (resultname, setFileNameResults (ENTROPY), FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing entropy.so module", -1);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  sum_flows += numflows;
  writeLogFile (filename, INFO, "Timeslot flows", numflows);
  printf
    ("[Info] Start Computing Entropy for different data: IP source / IP Destination / IP source - source port / IP destination - destination port / Packets number - Bytes Number / IP source - source port - IP destination - Destination port \n");
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
  int ret_func = 0;
  // Analyze data by different entropy base
  // IP source
  ret_func = process (r_current, current_flows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  //Compute the entropy of IP Source
  entropy_src = compute_entropy_ips (data.unique_src, current_flows);
  entropy_res_src = entropy_src;
  //Output results
  printf ("[Info] Unique IP Source %d \n", data.unique_src);
  printf ("[Info] Entropy of IP Source Addresses is %f \n", entropy_src);
  writeLogFile (filename, INFO, "Unique IP Source", data.unique_src);
  //Compute the entropy of IP Destination
  entropy_dst = compute_entropy_ipd (data.unique_dst, current_flows);
  entropy_res_dst = entropy_dst;
  //Output results
  printf ("[Info] Unique IP Destination %d \n", data.unique_dst);
  printf ("[Info] Entropy of IP Destination Addresses is %f \n", entropy_dst);
  writeLogFile (filename, INFO, "Unique IP Destination", data.unique_dst);
  //Compute the entropy of IP Source - Source Port
  entropy_ipsrcport =
    compute_entropy_ipsrcport (data.unique_ipsrc_srcport, current_flows);
  entropy_res_srcport = entropy_ipsrcport;
  //Output results
  printf ("[Info] Unique IP Source - Source Port %d \n",
	  data.unique_ipsrc_srcport);
  printf ("[Info] Entropy of IP Source - Source Port is %f \n",
	  entropy_ipsrcport);
  writeLogFile (filename, INFO, "Unique IP Source - Source Port",
		data.unique_ipsrc_srcport);
  //Compute the entropy of IP Destination - Destination Port
  entropy_ipdstport =
    compute_entropy_ipdstport (data.unique_ipdst_dstport, current_flows);
  entropy_res_dstport = entropy_ipdstport;
  //Output results
  printf ("[Info] Unique IP Destination - Destination Port %d \n",
	  data.unique_ipdst_dstport);
  printf ("[Info] Entropy of IP Destination - Destination Port is %f \n",
	  entropy_ipdstport);
  writeLogFile (filename, INFO, "Unique IP Destination - Destination Port",
		data.unique_ipdst_dstport);
  //Compute the entropy of Packets Number - Bytes Number
  entropy_npack_nbytes =
    compute_entropy_npackets_nbytes (data.unique_npack_nbytes, current_flows);
  entropy_res_npackbytes = entropy_npack_nbytes;
  //Output results
  printf ("[Info] Unique Packets Number - Bytes Number %d \n",
	  data.unique_npack_nbytes);
  printf ("[Info] Entropy of Packets Number - Bytes Number is %f \n",
	  entropy_npack_nbytes);
  writeLogFile (filename, INFO, "Unique Packets Number - Bytes Number",
		data.unique_npack_nbytes);
  //Compute the entropy of IP source - source port - IP destination - destination port
  entropy_ipsrcdstport =
    compute_entropy_ipsrcdstport (data.unique_ipsrcdstport, current_flows);
  entropy_res_ipsrcdstport = entropy_ipsrcdstport;
  //Output results
  printf
    ("[Info] Unique IP Source - Source Port - IP Destination - Destination Port %d \n",
     data.unique_ipsrcdstport);
  printf
    ("[Info] Entropy of IP Source - Source Port - IP Destination - Destination Port is %f \n",
     entropy_ipsrcdstport);
  writeLogFile (filename, INFO,
		"Unique IP Source Addresses - IP Destination Addresses - Source Port - Destination Port",
		data.unique_ipsrcdstport);
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
  // free resources
  struct ip_src_frequency *ip_src, *tmp;
  HASH_ITER (hh, data.ips, ip_src, tmp)
  {
    HASH_DEL (data.ips, ip_src);
    free (ip_src);
  }
  struct ip_dst_frequency *ip_dst, *tmp2;
  HASH_ITER (hh, data.ipd, ip_dst, tmp2)
  {
    HASH_DEL (data.ipd, ip_dst);
    free (ip_dst);
  }
  struct ip_src_srcport_frequency *current_user_p, *tmp1;
  HASH_ITER (hh, data.ipsp, current_user_p, tmp1)
  {
    HASH_DEL (data.ipsp, current_user_p);
    free (current_user_p);
  }
  struct ip_dst_dstport_frequency *dst_dstport, *tmp3;
  HASH_ITER (hh, data.ipdp, dst_dstport, tmp3)
  {
    HASH_DEL (data.ipdp, dst_dstport);
    free (dst_dstport);
  }
  struct npackets_nbytes *np, *tmp4;
  HASH_ITER (hh, data.pb, np, tmp4)
  {
    HASH_DEL (data.pb, np);
    free (np);
  }
  struct ipsrcdst_srcdstport *spcp, *tmp5;
  HASH_ITER (hh, data.ipsdp, spcp, tmp5)
  {
    HASH_DEL (data.ipsdp, spcp);
    free (spcp);
  }
  free (data.ips);
  free (data.ipd);
  free (data.ipsp);
  free (data.ipdp);
  free (data.pb);
  free (data.ipsdp);
  data.ips = NULL;
  data.ipd = NULL;
  data.ipsp = NULL;
  data.ipdp = NULL;
  data.pb = NULL;
  data.ipsdp = NULL;
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
  data.ips = NULL;
  data.ipd = NULL;
  data.ipsp = NULL;
  data.ipdp = NULL;
  data.pb = NULL;
  data.ipsdp = NULL;
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
      // Collect ip src
      struct ip_src_frequency *s;
      HASH_FIND_INT (data.ips, &r_current[z].ip_union._v4_2.srcaddr, s);
      if (s == NULL)
	{
	  s =
	    (struct ip_src_frequency *)
	    malloc (sizeof (struct ip_src_frequency));
	  if (s == NULL)
	    {
	      printf ("[Info] Problem in memory allocation in process \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in process",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (s, 0, sizeof (struct ip_src_frequency));
	  s->ip_src = r_current[z].ip_union._v4_2.srcaddr;
	  s->frequency = 1;
	  HASH_ADD_INT (data.ips, ip_src, s);
	}
      else
	s->frequency += 1;


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
      struct ip_dst_dstport_frequency l, *t, *dstport;
      memset (&l, 0, sizeof (struct ip_dst_dstport_frequency));
      l.key.ip_dst = r_current[z].ip_union._v4_2.dstaddr;
      l.key.dstport = r_current[z].dstport;
      HASH_FIND (hh, data.ipdp, &l.key,
		 sizeof (struct key_ipdstport_frequency), t);
      if (t == NULL)
	{
	  dstport =
	    (struct ip_dst_dstport_frequency *)
	    malloc (sizeof (struct ip_dst_dstport_frequency));
	  if (dstport == NULL)
	    {
	      printf ("[Info] Problem in memory allocation in process \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in process",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (dstport, 0, sizeof (struct ip_dst_dstport_frequency));
	  dstport->key.ip_dst = r_current[z].ip_union._v4_2.dstaddr;
	  dstport->key.dstport = r_current[z].dstport;
	  dstport->ip_dst = r_current[z].ip_union._v4_2.dstaddr;
	  dstport->dstport = r_current[z].dstport;
	  dstport->frequency = 1;
	  HASH_ADD (hh, data.ipdp, key,
		    sizeof (struct key_ipdstport_frequency), dstport);
	}
      else
	t->frequency += 1;


      // Collect packets number - bytes number
      struct npackets_nbytes f, *b, *npackbyt;
      memset (&f, 0, sizeof (struct npackets_nbytes));
      f.key.dOctets = r_current[z].dOctets;
      f.key.dPkts = r_current[z].dPkts;
      HASH_FIND (hh, data.pb, &f.key, sizeof (struct key_npackets_nbytes), b);
      if (b == NULL)
	{
	  npackbyt =
	    (struct npackets_nbytes *)
	    malloc (sizeof (struct npackets_nbytes));
	  if (npackbyt == NULL)
	    {
	      printf ("[Info] Problem in memory allocation in process \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in process",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (npackbyt, 0, sizeof (struct npackets_nbytes));
	  npackbyt->key.dOctets = r_current[z].dOctets;
	  npackbyt->key.dPkts = r_current[z].dPkts;
	  npackbyt->dOctets = r_current[z].dOctets;
	  npackbyt->dPkts = r_current[z].dPkts;
	  npackbyt->frequency = 1;
	  HASH_ADD (hh, data.pb, key, sizeof (struct key_npackets_nbytes),
		    npackbyt);
	}
      else
	b->frequency += 1;

      // Collect ip src - ip dst - src port - dst port
      struct ipsrcdst_srcdstport v, *m, *ipsrcdstport;
      memset (&v, 0, sizeof (struct ipsrcdst_srcdstport));
      v.key.ip_src = r_current[z].ip_union._v4_2.srcaddr;
      v.key.srcport = r_current[z].srcport;
      v.key.ip_dst = r_current[z].ip_union._v4_2.dstaddr;
      v.key.dstport = r_current[z].dstport;
      HASH_FIND (hh, data.ipsdp, &v.key,
		 sizeof (struct key_ipsrcdst_srcdstport), m);
      if (m == NULL)
	{
	  ipsrcdstport =
	    (struct ipsrcdst_srcdstport *)
	    malloc (sizeof (struct ipsrcdst_srcdstport));
	  if (ipsrcdstport == NULL)
	    {
	      printf ("[Info] Problem in memory allocation in process \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in process",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (ipsrcdstport, 0, sizeof (struct ipsrcdst_srcdstport));
	  ipsrcdstport->key.ip_src = r_current[z].ip_union._v4_2.srcaddr;
	  ipsrcdstport->key.srcport = r_current[z].srcport;
	  ipsrcdstport->key.ip_dst = r_current[z].ip_union._v4_2.dstaddr;
	  ipsrcdstport->key.dstport = r_current[z].dstport;
	  ipsrcdstport->ip_src = r_current[z].ip_union._v4_2.srcaddr;
	  ipsrcdstport->srcport = r_current[z].srcport;
	  ipsrcdstport->ip_dst = r_current[z].ip_union._v4_2.dstaddr;
	  ipsrcdstport->dstport = r_current[z].dstport;
	  ipsrcdstport->frequency = 1;
	  HASH_ADD (hh, data.ipsdp, key,
		    sizeof (struct key_ipsrcdst_srcdstport), ipsrcdstport);
	}
      else
	m->frequency += 1;

      // Collect ip src - src port
      struct ip_src_srcport_frequency p, *rs, *ipsrcport;
      memset (&p, 0, sizeof (struct ip_src_srcport_frequency));
      p.key.ip_src = r_current[z].ip_union._v4_2.srcaddr;
      p.key.srcport = r_current[z].srcport;
      HASH_FIND (hh, data.ipsp, &p.key,
		 sizeof (struct key_ipsrcport_frequency), rs);
      if (rs == NULL)
	{
	  ipsrcport =
	    (struct ip_src_srcport_frequency *)
	    malloc (sizeof (struct ip_src_srcport_frequency));
	  if (ipsrcport == NULL)
	    {
	      printf ("[Info] Problem in memory allocation in process \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in process",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (ipsrcport, 0, sizeof (struct ip_src_srcport_frequency));
	  ipsrcport->key.ip_src = r_current[z].ip_union._v4_2.srcaddr;
	  ipsrcport->key.srcport = r_current[z].srcport;
	  ipsrcport->ip_src = r_current[z].ip_union._v4_2.srcaddr;
	  ipsrcport->srcport = r_current[z].srcport;
	  ipsrcport->frequency = 1;
	  HASH_ADD (hh, data.ipsp, key,
		    sizeof (struct key_ipsrcport_frequency), ipsrcport);
	}
      else
	rs->frequency += 1;
    }
  // Copy Number of elements to compute the entropy
  unsigned int num_ip_src;
  num_ip_src = HASH_COUNT (data.ips);
  data.unique_src = num_ip_src;
  unsigned int num_ip_srcport;
  num_ip_srcport = HASH_COUNT (data.ipsp);
  data.unique_ipsrc_srcport = num_ip_srcport;
  unsigned int num_ip_dst;
  num_ip_dst = HASH_COUNT (data.ipd);
  data.unique_dst = num_ip_dst;
  unsigned int num_ip_dstport;
  num_ip_dstport = HASH_COUNT (data.ipdp);
  data.unique_ipdst_dstport = num_ip_dstport;
  unsigned int num_npackbyt;
  num_npackbyt = HASH_COUNT (data.pb);
  data.unique_npack_nbytes = num_npackbyt;
  unsigned int num_ipsrcdstport;
  num_ipsrcdstport = HASH_COUNT (data.ipsdp);
  data.unique_ipsrcdstport = num_ipsrcdstport;
  return STATUS_OK;
}

// Entropy ip src computing function
float
compute_entropy_ips (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct ip_src_frequency *s;
  for (s = data.ips; s != NULL; s = s->hh.next)
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

// Entropy ip src - src port computing function
float
compute_entropy_ipsrcport (int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  struct ip_src_srcport_frequency *s;
  for (s = data.ipsp; s != NULL; s = s->hh.next)
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
  for (s = data.ipdp; s != NULL; s = s->hh.next)
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
  for (s = data.pb; s != NULL; s = s->hh.next)
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
  for (s = data.ipsdp; s != NULL; s = s->hh.next)
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

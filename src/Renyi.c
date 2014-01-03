 /*************************************************************************
 *  Renyi.c
 *
 *  Compute Source Address IP Renyi divergence   
 *  Compute Destination Address IP Renyi divergence
 *  Compute Source Addresses IP - Source Port Renyi divergence
 *  Compute Dest Addresses IP - Dest Port Renyi divergence
 *  Compute Packets Number - Bytes Number Renyi divergence
 *  Compute Source Addresses IP - Source Port - Destination Addresses IP - Destination Port Renyi divergence
 *
 *  This module get in input a collection of flow from a timeslot and the last timeslot, and compute the Renyi
 *  divergence on six different configurations. The informations are returned by stdout and logged into a file named with 
 *  metricname_datehourminutessecondsmilliseconds in the log folder. The twodist_data structure is complex:
 *  each field is a pointer to specific data structures, one for each configuration. In the init phase, these data
 *  structures are initialized, in the process phase are filled with data and then these data are used to compute Renyi divergence,
 *  in the close phase the data structures are freed and a new timeslot flows block is ready to be analyzed with the last timeslot.
 *
 *  Copyright (C) Andrea Cosentino 2012
 *
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <dlfcn.h>
#include "frequency.h"
#include "log.h"

#define LIM_IPSRC (2.70)
#define LIM_IPDST (2.70)
#define LIM_IPSRCPORT (2.70)
#define LIM_IPDSTPORT (2.70)
#define LIM_PACKBYTES (2.70)
#define LIM_IPSRCDSTPORT (2.70)

// Global Variable for passing results to other modules if needed
float re_res_src = 0.0;
float re_res_dst = 0.0;
float re_res_srcport = 0.0;
float re_res_dstport = 0.0;
float re_res_npackbytes = 0.0;
float re_res_ipsrcdstport = 0.0;

// Global variables
// twodist_data data structure is defined in frequency.h
struct twodist_data data;
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

// Initialize the data struct twodist_data and its field
int re_init_all (int numflows);
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

// Compute Renyi on hash tables by IP Source
float compute_src_div (void);
// Compute Renyi on hash tables by IP Destination
float compute_dst_div (void);
// Compute Renyi on hash tables by IP Source - Source Port
float compute_srcport_div (void);
// Compute Renyi on hash tables by IP Destination - Destination Port
float compute_dstport_div (void);
// Compute Renyi on hash tables by IP Destination - Destination Port
float compute_npackbyt_div (void);
// Compute Renyi on hash tables by IP Source - Source Port - IP Destination - Destination Port
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
      strncpy (filename, setFileName (RENYILOGNAME, spec_logdir),
	       FILENAME_MAX);
      strncpy (resultname, setFileNameResults (RENYILOGNAME), FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Renyi.so module", -1);
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
	("[Info] Start Computing Renyi Divergence on the last two Timeslots \n");
      printf ("[Info] Last Timeslot Flows Number %d \n", last_numflows);
      printf ("[Info] Current Timeslot Flows Number %d \n", current_numflows);
    }
  re_init_all (numflows);
  return 0;
}

// Process Data
// r_current --> current timeslot flows
// current_flows --> number of current timeslot flows
double
so_process (nf_record_t * r_current, int current_flows, char *bucket_id)
{
  writeLogFile (filename, BUCKET, bucket_id, -1);
  float re_divergence_src = 0.0;
  float re_divergence_dst = 0.0;
  float re_divergence_ipsrcport = 0.0;
  float re_divergence_ipdstport = 0.0;
  float re_divergence_npackbytes = 0.0;
  float re_divergence_ipsrcdstport = 0.0;
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
      re_divergence_src = compute_src_div ();
      re_res_src = re_divergence_src;
      re_divergence_dst = compute_dst_div ();
      re_res_dst = re_divergence_dst;
      re_divergence_ipsrcport = compute_srcport_div ();
      re_res_srcport = re_divergence_ipsrcport;
      re_divergence_ipdstport = compute_dstport_div ();
      re_res_dstport = re_divergence_ipdstport;
      re_divergence_npackbytes = compute_npackbyt_div ();
      re_res_npackbytes = re_divergence_npackbytes;
      re_divergence_ipsrcdstport = compute_ipsrcdstport_div ();
      re_res_ipsrcdstport = re_divergence_ipsrcdstport;
      printf ("[Info] IP Source Renyi Divergence is: %f \n",
	      re_divergence_src);
      printf ("[Info] IP Destination Renyi Divergence is: %f \n",
	      re_divergence_dst);
      printf ("[Info] IP Source - Source Port Renyi Divergence is: %f \n",
	      re_divergence_ipsrcport);
      printf
	("[Info] IP Destination - Destination Port Renyi Divergence is: %f \n",
	 re_divergence_ipdstport);
      printf
	("[Info] Packets Number - Bytes Number Renyi Divergence is: %f \n",
	 re_divergence_npackbytes);
      printf
	("[Info] IP Source - Source Port - IP Destination - Destination Port Renyi Divergence is: %f \n",
	 re_divergence_ipsrcdstport);
      if (re_divergence_src >= LIM_IPSRC)
	{
	  printf
	    ("[!!!Alarm!!!] Renyi Divergence of IP Source is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Renyi Divergence of IP Source is over the limit\n\n",
			-1);
	  alarm_src = 1;
	}
      if (re_divergence_dst >= LIM_IPDST)
	{
	  printf
	    ("[!!!Alarm!!!] Renyi Divergence of IP Destination is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Renyi Divergence of IP Destination is over the limit\n\n",
			-1);
	  alarm_dst = 1;
	}
      if (re_divergence_ipsrcport >= LIM_IPSRCPORT)
	{
	  printf
	    ("[!!!Alarm!!!] Renyi Divergence of IP Source - Source Port is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Renyi Divergence of IP Source - Source Port is over the limit\n\n",
			-1);
	  alarm_ipsrcport = 1;
	}
      if (re_divergence_ipdstport >= LIM_IPDSTPORT)
	{
	  printf
	    ("[!!!Alarm!!!] Renyi Divergence of IP Destination - Destination Port is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Renyi Divergence of IP Destination - Destination Port is over the limit\n\n",
			-1);
	  alarm_ipdstport = 1;
	}
      if (re_divergence_npackbytes >= LIM_PACKBYTES)
	{
	  printf
	    ("[!!!Alarm!!!] Renyi Divergence of Packets Number - Bytes Number is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Renyi Divergence of Packets Number - Bytes Number is over the limit\n\n",
			-1);
	  alarm_npack_nbytes = 1;
	}
      if (re_divergence_ipsrcdstport >= LIM_IPSRCDSTPORT)
	{
	  printf
	    ("[!!!Alarm!!!] Renyi Divergence of IP source - source port - IP destination - destination port is over the limit\n");
	  writeLogFile (filename, ALARM,
			"Renyi Divergence of IP source - source port - IP destination - destination port is over the limit\n\n",
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
	       "Timeslot Bucket,Ip src Renyi divergence, Ip dst Renyi divergence, Ip src - src port Renyi divergence, Ip dst - dst port Renyi divergence, packets number - bytes number Renyi divergence, Ip src - src port - Ip dst - dst port Renyi divergence, alarm src, alarm dst, alarm src - src port, alarm dst - dst port, alarm packets number - bytes number, alarm Ip src - src port - Ip dst - dst port \n");
    }
  fprintf (fs, "%s,%3.6f,%3.6f,%3.6f,%3.6f,%3.6f,%3.6f,%d,%d,%d,%d,%d,%d \n",
	   bucket_id, re_divergence_src, re_divergence_dst,
	   re_divergence_ipsrcport, re_divergence_ipdstport,
	   re_divergence_npackbytes, re_divergence_ipsrcdstport, alarm_src,
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
  struct ip_src_frequency *ip_src, *tmp;
  HASH_ITER (hh, data.ipsrc_current, ip_src, tmp)
  {
    HASH_DEL (data.ipsrc_current, ip_src);
    free (ip_src);
  }
  struct ip_dst_frequency *ip_dst, *tmp2;
  HASH_ITER (hh, data.ipdst_current, ip_dst, tmp2)
  {
    HASH_DEL (data.ipdst_current, ip_dst);
    free (ip_dst);
  }
  struct ip_src_srcport_frequency *current_user_p, *tmp1;
  HASH_ITER (hh, data.ipsrcport_current, current_user_p, tmp1)
  {
    HASH_DEL (data.ipsrcport_current, current_user_p);
    free (current_user_p);
  }
  struct ip_dst_dstport_frequency *dst_dstport, *tmp3;
  HASH_ITER (hh, data.ipdstport_current, dst_dstport, tmp3)
  {
    HASH_DEL (data.ipdstport_current, dst_dstport);
    free (dst_dstport);
  }
  struct npackets_nbytes *np, *tmp4;
  HASH_ITER (hh, data.pb_current, np, tmp4)
  {
    HASH_DEL (data.pb_current, np);
    free (np);
  }
  struct ipsrcdst_srcdstport *spcp, *tmp5;
  HASH_ITER (hh, data.ipsrcdstport_current, spcp, tmp5)
  {
    HASH_DEL (data.ipsrcdstport_current, spcp);
    free (spcp);
  }
  free (data.ipsrc_current);
  free (data.ipdst_current);
  free (data.ipsrcport_current);
  free (data.ipdstport_current);
  free (data.pb_current);
  free (data.ipsrcdstport_current);
  data.ipsrc_current = NULL;
  data.ipdst_current = NULL;
  data.ipsrcport_current = NULL;
  data.ipdstport_current = NULL;
  data.pb_current = NULL;
  data.ipsrcdstport_current = NULL;
  if (iterations >= 2)
    {
      writeLogFile (filename, INFO, "Total analyzed flows", sum_flows);
      printf
	("[Info] End Computing Renyi Divergence on the last two Timeslots \n");
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
  *(float *) pt[0] = re_res_src;
  *(float *) pt[1] = re_res_dst;
  *(float *) pt[2] = re_res_srcport;
  *(float *) pt[3] = re_res_dstport;
  *(float *) pt[4] = re_res_npackbytes;
  *(float *) pt[5] = re_res_ipsrcdstport;
  return pt;
}

// Init all provide to initialize the data field of the twodist_data struct
// INPUT: numflows, the flows of the current timeslot
// data.ipsrc_current -> ip source current timeslot
// data.count_ipsrc_current -> ip source current timeslot count informations (unique values, total values)
// data.ipdst_current -> ip destination current timeslot
// data.count_ipdst_current -> ip dst current timeslot count informations (unique values, total values)
// data.ipsrcport_current -> ip source - source port current timeslot
// data.count_ipsrcport_current -> ip source - source port current timeslot count informations (unique values, total values)
// data.ipdstport_current -> ip dst - dst port current timeslot
// data.count_ipdstport_current -> ip dst - dst port current timeslot count informations (unique values, total values)
// data.pb_current -> packets number - bytes number current timeslot
// data.count_pb_current -> packets number - bytes number current timeslot count informations (unique values, total values)
// data.ipsrcdstport_current -> ip source - source port - ip destination - destination port current timeslot
// data.count_ipsrcdstport_current -> ip source - source port - ip destination - destination port current timeslot count informations (unique values, total values)
int
re_init_all (int numflows)
{
  data.ipsrc_current = NULL;
  data.ipdst_current = NULL;
  data.ipsrcport_current = NULL;
  data.ipdstport_current = NULL;
  data.pb_current = NULL;
  data.ipsrcdstport_current = NULL;
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
      HASH_FIND_INT (data.ipsrc_current, &r_current[z].ip_union._v4_2.srcaddr,
		     s);
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
	  HASH_ADD_INT (data.ipsrc_current, ip_src, s);
	}
      else
	s->frequency += 1;


      // Collect ip dst
      struct ip_dst_frequency *d;	// Compute Kullback-Leibler on hash tables
      HASH_FIND_INT (data.ipdst_current, &r_current[z].ip_union._v4_2.dstaddr,
		     d);
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
	  HASH_ADD_INT (data.ipdst_current, ip_dst, d);
	}
      else
	d->frequency += 1;


      // Collect ip dst - dst port
      struct ip_dst_dstport_frequency l, *t, *dstport;
      memset (&l, 0, sizeof (struct ip_dst_dstport_frequency));
      l.key.ip_dst = r_current[z].ip_union._v4_2.dstaddr;
      l.key.dstport = r_current[z].dstport;
      HASH_FIND (hh, data.ipdstport_current, &l.key,
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
	  HASH_ADD (hh, data.ipdstport_current, key,
		    sizeof (struct key_ipdstport_frequency), dstport);
	}
      else
	t->frequency += 1;


      // Collect packets number - bytes number
      struct npackets_nbytes f, *b, *npackbyt;
      memset (&f, 0, sizeof (struct npackets_nbytes));
      f.key.dOctets = r_current[z].dOctets;
      f.key.dPkts = r_current[z].dPkts;
      HASH_FIND (hh, data.pb_current, &f.key,
		 sizeof (struct key_npackets_nbytes), b);
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
	  HASH_ADD (hh, data.pb_current, key,
		    sizeof (struct key_npackets_nbytes), npackbyt);
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
      HASH_FIND (hh, data.ipsrcdstport_current, &v.key,
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
	  HASH_ADD (hh, data.ipsrcdstport_current, key,
		    sizeof (struct key_ipsrcdst_srcdstport), ipsrcdstport);
	}
      else
	m->frequency += 1;

      // Collect ip src - src port
      struct ip_src_srcport_frequency p, *rs, *ipsrcport;
      memset (&p, 0, sizeof (struct ip_src_srcport_frequency));
      p.key.ip_src = r_current[z].ip_union._v4_2.srcaddr;
      p.key.srcport = r_current[z].srcport;
      HASH_FIND (hh, data.ipsrcport_current, &p.key,
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
	  HASH_ADD (hh, data.ipsrcport_current, key,
		    sizeof (struct key_ipsrcport_frequency), ipsrcport);
	}
      else
	rs->frequency += 1;
    }
  // Copy Number of elements to compute the entropy
  unsigned int num_ip_src;
  num_ip_src = HASH_COUNT (data.ipsrc_current);
  data.unique_src_current = num_ip_src;
  unsigned int num_ip_srcport;
  num_ip_srcport = HASH_COUNT (data.ipsrcport_current);
  data.unique_ipsrc_srcport_current = num_ip_srcport;
  unsigned int num_ip_dst;
  num_ip_dst = HASH_COUNT (data.ipdst_current);
  data.unique_dst_current = num_ip_dst;
  unsigned int num_ip_dstport;
  num_ip_dstport = HASH_COUNT (data.ipdstport_current);
  data.unique_ipdst_dstport_current = num_ip_dstport;
  unsigned int num_npackbyt;
  num_npackbyt = HASH_COUNT (data.pb_current);
  data.unique_npack_nbytes_current = num_npackbyt;
  unsigned int num_ipsrcdstport;
  num_ipsrcdstport = HASH_COUNT (data.ipsrcdstport_current);
  data.unique_ipsrcdstport_current = num_ipsrcdstport;
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_src (void)
{
  data.ipsrc_past = NULL;
  struct ip_src_frequency *ip_src, *tmp;
  HASH_ITER (hh, data.ipsrc_current, ip_src, tmp)
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
    HASH_ADD_INT (data.ipsrc_past, ip_src, s);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_dst (void)
{
  data.ipdst_past = NULL;
  struct ip_dst_frequency *ip_dst, *tmp;
  HASH_ITER (hh, data.ipdst_current, ip_dst, tmp)
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
    HASH_ADD_INT (data.ipdst_past, ip_dst, s);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_srcport (void)
{
  data.ipsrcport_past = NULL;
  struct ip_src_srcport_frequency *ip_src, *tmp;
  HASH_ITER (hh, data.ipsrcport_current, ip_src, tmp)
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
    HASH_ADD (hh, data.ipsrcport_past, key,
	      sizeof (struct key_ipsrcport_frequency), ipsrcport);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_dstport (void)
{
  data.ipdstport_past = NULL;
  struct ip_dst_dstport_frequency *ip_dst, *tmp;
  HASH_ITER (hh, data.ipdstport_current, ip_dst, tmp)
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
    HASH_ADD (hh, data.ipdstport_past, key,
	      sizeof (struct key_ipdstport_frequency), ipdstport);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_npackbyt (void)
{
  data.pb_past = NULL;
  struct npackets_nbytes *pb, *tmp;
  HASH_ITER (hh, data.pb_current, pb, tmp)
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
    HASH_ADD (hh, data.pb_past, key, sizeof (struct key_npackets_nbytes),
	      npackbyt);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_ipsrcdstport (void)
{
  data.ipsrcdstport_past = NULL;
  struct ipsrcdst_srcdstport *spdp, *tmp;
  HASH_ITER (hh, data.ipsrcdstport_current, spdp, tmp)
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
    HASH_ADD (hh, data.ipsrcdstport_past, key,
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
  float Renyi_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  float sum = 0.0;
  float param = (float) 1 / (float) (RENYI_ALPHA - 1);
  float power_p_current = 0.0;
  float power_p_last = 0.0;
  int cnt = 0;
  struct ip_src_frequency *ip_src_current, *tmp_current;
  HASH_ITER (hh, data.ipsrc_current, ip_src_current, tmp_current)
  {
    struct ip_src_frequency *s;
    HASH_FIND_INT (data.ipsrc_past, &ip_src_current->ip_src, s);
    if (s != NULL)
      {
	sum_frequency_current += ip_src_current->frequency;
	sum_frequency_past += s->frequency;
      }
  }
  HASH_ITER (hh, data.ipsrc_current, ip_src_current, tmp_current)
  {
    struct ip_src_frequency *s;
    HASH_FIND_INT (data.ipsrc_past, &ip_src_current->ip_src, s);
    if (s != NULL)
      {
	cnt++;
	// Probability of i-th elements in current time-slot
	p_current =
	  (float) ip_src_current->frequency / (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) s->frequency / (float) sum_frequency_past;
	// Compute KL
	power_p_current = (float) pow (p_current, RENYI_ALPHA);
	power_p_last = (float) pow (p_last, RENYI_ALPHA - 1);
	if (p_current > 0.0 && p_last > 0.0)
	  sum += power_p_current / power_p_last;
	//printf("p_Current %f p_Last %f Sum %f Log %f \n", p_current,p_last,sum,log (sum));
      }
  }
  if (sum != 0.0)
    Renyi_divergence = param * log (sum);
  struct ip_src_frequency *ip_src, *tmp;
  HASH_ITER (hh, data.ipsrc_past, ip_src, tmp)
  {
    HASH_DEL (data.ipsrc_past, ip_src);
    free (ip_src);
  }
  data.ipsrc_past = NULL;
  printf ("[Info] Common Unique IP Source Addresses: %d \n", cnt);
  writeLogFile (filename, INFO, "Common Unique IP Source Addresses", cnt);
  return Renyi_divergence;
}

// Compute Kullback-Leibler on hash tables by IP Destination
float
compute_dst_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float Renyi_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  float sum = 0.0;
  float param = (float) 1 / (float) (RENYI_ALPHA - 1);
  float power_p_current = 0.0;
  float power_p_last = 0.0;
  int cnt = 0;
  struct ip_dst_frequency *ip_dst_current, *tmp_current;
  HASH_ITER (hh, data.ipdst_current, ip_dst_current, tmp_current)
  {
    struct ip_dst_frequency *s;
    HASH_FIND_INT (data.ipdst_past, &ip_dst_current->ip_dst, s);
    if (s != NULL)
      {
	sum_frequency_current += ip_dst_current->frequency;
	sum_frequency_past += s->frequency;
      }
  }
  HASH_ITER (hh, data.ipdst_current, ip_dst_current, tmp_current)
  {
    struct ip_dst_frequency *s;
    HASH_FIND_INT (data.ipdst_past, &ip_dst_current->ip_dst, s);
    if (s != NULL)
      {
	cnt++;
	// Probability of i-th elements in current time-slot
	p_current =
	  (float) ip_dst_current->frequency / (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) s->frequency / (float) sum_frequency_past;
	// Compute KL
	power_p_current = (float) pow (p_current, RENYI_ALPHA);
	power_p_last = (float) pow (p_last, RENYI_ALPHA - 1);
	if (p_current > 0.0 && p_last > 0.0)
	  sum += power_p_current / power_p_last;
	//printf("p_Current %f p_Last %f Sum %f Log %f \n", p_current,p_last,sum,log (sum));
      }
  }
  if (sum != 0.0)
    Renyi_divergence = param * log (sum);
  struct ip_dst_frequency *ip_dst, *tmp;
  HASH_ITER (hh, data.ipdst_past, ip_dst, tmp)
  {
    HASH_DEL (data.ipdst_past, ip_dst);
    free (ip_dst);
  }
  data.ipdst_past = NULL;
  printf ("[Info] Common Unique IP Destination Addresses: %d \n", cnt);
  writeLogFile (filename, INFO, "Common Unique IP Destination Addresses",
		cnt);
  return Renyi_divergence;
}

// Compute Kullback-Leibler on hash tables by IP Destination
float
compute_srcport_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float Renyi_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  float sum = 0.0;
  float param = (float) 1 / (float) (RENYI_ALPHA - 1);
  float power_p_current = 0.0;
  float power_p_last = 0.0;
  int cnt = 0;
  struct ip_src_srcport_frequency *ip_srcport_current, *tmp_current;
  HASH_ITER (hh, data.ipsrcport_current, ip_srcport_current, tmp_current)
  {
    struct ip_src_srcport_frequency *rs;
    HASH_FIND (hh, data.ipsrcport_past, &ip_srcport_current->key,
	       sizeof (struct key_ipsrcport_frequency), rs);
    if (rs != NULL)
      {
	sum_frequency_current += ip_srcport_current->frequency;
	sum_frequency_past += rs->frequency;
      }
  }
  HASH_ITER (hh, data.ipsrcport_current, ip_srcport_current, tmp_current)
  {
    struct ip_src_srcport_frequency *rs;
    HASH_FIND (hh, data.ipsrcport_past, &ip_srcport_current->key,
	       sizeof (struct key_ipsrcport_frequency), rs);
    if (rs != NULL)
      {
	cnt++;
	// Probability of i-th elements in current time-slot
	p_current =
	  (float) ip_srcport_current->frequency /
	  (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) rs->frequency / (float) sum_frequency_past;
	// Compute KL
	power_p_current = (float) pow (p_current, RENYI_ALPHA);
	power_p_last = (float) pow (p_last, RENYI_ALPHA - 1);
	if (p_current > 0.0 && p_last > 0.0)
	  sum += power_p_current / power_p_last;
	//printf("p_Current %f p_Last %f Sum %f Log %f \n", p_current,p_last,sum,log (sum));
      }
  }
  if (sum != 0.0)
    Renyi_divergence = param * log (sum);
  struct ip_src_srcport_frequency *current_user_p, *tmp1;
  HASH_ITER (hh, data.ipsrcport_past, current_user_p, tmp1)
  {
    HASH_DEL (data.ipsrcport_past, current_user_p);
    free (current_user_p);
  }
  printf ("[Info] Common Unique IP Source Addresses - Source Port: %d \n",
	  cnt);
  writeLogFile (filename, INFO,
		"Common Unique IP Source Addresses - Source Port", cnt);
  data.ipsrcport_past = NULL;
  return Renyi_divergence;
}

// Compute Kullback-Leibler on hash tables by IP Destination - Destination Port
float
compute_dstport_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float Renyi_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  float sum = 0.0;
  float param = (float) 1 / (float) (RENYI_ALPHA - 1);
  float power_p_current = 0.0;
  float power_p_last = 0.0;
  int cnt = 0;
  struct ip_dst_dstport_frequency *ip_dstport_current, *tmp_current;
  HASH_ITER (hh, data.ipdstport_current, ip_dstport_current, tmp_current)
  {
    struct ip_dst_dstport_frequency *rs;
    HASH_FIND (hh, data.ipdstport_past, &ip_dstport_current->key,
	       sizeof (struct key_ipdstport_frequency), rs);
    if (rs != NULL)
      {
	sum_frequency_current += ip_dstport_current->frequency;
	sum_frequency_past += rs->frequency;
      }
  }
  HASH_ITER (hh, data.ipdstport_current, ip_dstport_current, tmp_current)
  {
    struct ip_dst_dstport_frequency *rs;
    HASH_FIND (hh, data.ipdstport_past, &ip_dstport_current->key,
	       sizeof (struct key_ipdstport_frequency), rs);
    if (rs != NULL)
      {
	cnt++;
	// Probability of i-th elements in current time-slot
	p_current =
	  (float) ip_dstport_current->frequency /
	  (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) rs->frequency / (float) sum_frequency_past;
	// Compute KL
	power_p_current = (float) pow (p_current, RENYI_ALPHA);
	power_p_last = (float) pow (p_last, RENYI_ALPHA - 1);
	if (p_current > 0.0 && p_last > 0.0)
	  sum += power_p_current / power_p_last;
	//printf("p_Current %f p_Last %f Sum %f Log %f \n", p_current,p_last,sum,log (sum));
      }
  }
  if (sum != 0.0)
    Renyi_divergence = param * log (sum);
  struct ip_dst_dstport_frequency *current_user_p, *tmp1;
  HASH_ITER (hh, data.ipdstport_past, current_user_p, tmp1)
  {
    HASH_DEL (data.ipdstport_past, current_user_p);
    free (current_user_p);
  }
  printf
    ("[Info] Common Unique IP Destination Addresses - Destination Port: %d \n",
     cnt);
  writeLogFile (filename, INFO,
		"Common Unique IP Destination Addresses - Destination Port",
		cnt);
  data.ipdstport_past = NULL;
  return Renyi_divergence;
}

// Compute Kullback-Leibler on hash tables by Packets Number - Bytes Number 
float
compute_npackbyt_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float Renyi_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  float sum = 0.0;
  float param = (float) 1 / (float) (RENYI_ALPHA - 1);
  float power_p_current = 0.0;
  float power_p_last = 0.0;
  int cnt = 0;
  struct npackets_nbytes *m, *tmp_current;
  HASH_ITER (hh, data.pb_current, m, tmp_current)
  {
    struct npackets_nbytes *rs;
    HASH_FIND (hh, data.pb_past, &m->key, sizeof (struct key_npackets_nbytes),
	       rs);
    if (rs != NULL)
      {
	sum_frequency_current += m->frequency;
	sum_frequency_past += rs->frequency;
      }
  }
  HASH_ITER (hh, data.pb_current, m, tmp_current)
  {
    struct npackets_nbytes *rs;
    HASH_FIND (hh, data.pb_past, &m->key, sizeof (struct key_npackets_nbytes),
	       rs);
    if (rs != NULL)
      {
	cnt++;
	// Probability of i-th elements in current time-slot
	p_current = (float) m->frequency / (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) rs->frequency / (float) sum_frequency_past;
	// Compute KL
	power_p_current = (float) pow (p_current, RENYI_ALPHA);
	power_p_last = (float) pow (p_last, RENYI_ALPHA - 1);
	if (p_current > 0.0 && p_last > 0.0)
	  sum += power_p_current / power_p_last;
	//printf("p_Current %f p_Last %f Sum %f Log %f \n", p_current,p_last,sum,log (sum));
      }
  }
  if (sum != 0.0)
    Renyi_divergence = param * log (sum);
  struct npackets_nbytes *current_user_p, *tmp1;
  HASH_ITER (hh, data.pb_past, current_user_p, tmp1)
  {
    HASH_DEL (data.pb_past, current_user_p);
    free (current_user_p);
  }
  printf ("[Info] Common Unique Packets Number - Bytes Number: %d \n", cnt);
  writeLogFile (filename, INFO, "Common Unique Packets Number - Bytes Number",
		cnt);
  data.pb_past = NULL;
  return Renyi_divergence;
}

// Compute Kullback-Leibler on hash tables by IP Source - Source Port - IP Destination - Destination Port
float
compute_ipsrcdstport_div (void)
{
  float p_current = 0.0;
  float p_last = 0.0;
  float Renyi_divergence = 0.0;
  int sum_frequency_current = 0.0;
  int sum_frequency_past = 0.0;
  float sum = 0.0;
  float param = (float) 1 / (float) (RENYI_ALPHA - 1);
  float power_p_current = 0.0;
  float power_p_last = 0.0;
  int cnt = 0;
  struct ipsrcdst_srcdstport *m, *tmp_current;
  HASH_ITER (hh, data.ipsrcdstport_current, m, tmp_current)
  {
    struct ipsrcdst_srcdstport *rs;
    HASH_FIND (hh, data.ipsrcdstport_past, &m->key,
	       sizeof (struct key_ipsrcdst_srcdstport), rs);
    if (rs != NULL)
      {
	sum_frequency_current += m->frequency;
	sum_frequency_past += rs->frequency;
      }
  }
  HASH_ITER (hh, data.ipsrcdstport_current, m, tmp_current)
  {
    struct ipsrcdst_srcdstport *rs;
    HASH_FIND (hh, data.ipsrcdstport_past, &m->key,
	       sizeof (struct key_ipsrcdst_srcdstport), rs);
    if (rs != NULL)
      {
	cnt++;
	// Probability of i-th elements in current time-slot
	p_current = (float) m->frequency / (float) sum_frequency_current;
	// Probability of i-th elements in last time-slot
	p_last = (float) rs->frequency / (float) sum_frequency_past;
	// Compute KL
	power_p_current = (float) pow (p_current, RENYI_ALPHA);
	power_p_last = (float) pow (p_last, RENYI_ALPHA - 1);
	if (p_current > 0.0 && p_last > 0.0)
	  sum += power_p_current / power_p_last;
	//printf("p_Current %f p_Last %f Sum %f Log %f \n", p_current,p_last,sum,log (sum));
      }
  }
  if (sum != 0.0)
    Renyi_divergence = param * log (sum);
  struct ipsrcdst_srcdstport *current_user_p, *tmp1;
  HASH_ITER (hh, data.ipsrcdstport_past, current_user_p, tmp1)
  {
    HASH_DEL (data.ipsrcdstport_past, current_user_p);
    free (current_user_p);
  }
  printf
    ("[Info] Common Unique IP Source - IP Destination - Source Port - Destination Port: %d \n",
     cnt);
  writeLogFile (filename, INFO,
		"Common Unique IP Source - IP Destination - Source Port - Destination Port",
		cnt);
  data.ipsrcdstport_past = NULL;
  return Renyi_divergence;
}

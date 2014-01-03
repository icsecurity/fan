 /*************************************************************************
 *  frequency_mod.c
 *
 *  Compute Source Address IP Entropy   
 *  Compute Destination Address IP Entropy 
 *  Compute Source Addresses IP - Source Port Entropy 
 *  Compute Dest Addresses IP - Dest Port Entropy
 *  Compute Packets Number - Bytes Number Entropy
 *  Compute Source Addresses IP - Source Port - Destination Addresses IP - Destination Port Entropy
 *
 *  This module get in input a collection of flow from a timeslot and save it in a data structure to pass to other module who are 
 *  dependent from it.
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

#define LIM_IPSRC 0.30
#define LIM_IPDST 0.30
#define LIM_IPSRCPORT 0.30
#define LIM_IPDSTPORT 0.30
#define LIM_PACKBYTES 0.30
#define LIM_IPSRCDSTPORT 0.30

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
struct twodist_data data_two;
struct entropy_data data_cpy;
struct twodist_data data_two_cpy;
int iterations = 0;
// File for logging purpose
char filename[FILENAME_MAX];
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
struct entropy_data *so_getResult (void);
struct twodist_data *so_getResulttwodistre (void);
struct twodist_data *so_getResulttwodist (void);

// Initialize the data struct entropy_data and its field
double init_all (int numflows);
// Process data from ip source point of view
int process (nf_record_t * r_current, int current_flows);
int process_twodist (nf_record_t * r_current, int current_flows);
// Free resources
double free_resources (void);

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

// so_init initializes the field of the entropy_data data structure
// numflows --> number of current timeslot flows
double
so_init (int numflows)
{
  int ret_func = 0;
  iterations++;

  if (iterations == 1)
    {
      strncpy (filename, setFileName (FREQUENCYMOD, spec_logdir),
	       FILENAME_MAX);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  sum_flows += numflows;
  if (iterations > 1)
    free_resources ();
  writeLogFile (filename, STATUS_OK, "Start Collecting Frequencies Data", -1);
  writeLogFile (filename, INFO, "Timeslot flows", numflows);
  printf ("[Info] Start Collecting Frequencies Data \n");
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
  int ret_func = 0;
  // Analyze data by different entropy base
  // IP source
  ret_func = process (r_current, current_flows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  ret_func = process_twodist (r_current, current_flows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  return STATUS_OK;
}

// Close operations
// Free resources
double
so_close (void)
{
  printf ("[Info] End Collecting Frequencies Data \n");
  writeLogFile (filename, INFO, "Total analyzed flows", sum_flows);
  writeLogFile (filename, STATUS_OK, "End Collecting Frequencies Data", -1);
  return STATUS_OK;
}

double
free_resources (void)
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
  HASH_ITER (hh, data_two.ipsrc_current, ip_src, tmp)
  {
    HASH_DEL (data_two.ipsrc_current, ip_src);
    free (ip_src);
  }
  HASH_ITER (hh, data_two.ipdst_current, ip_dst, tmp2)
  {
    HASH_DEL (data_two.ipdst_current, ip_dst);
    free (ip_dst);
  }
  HASH_ITER (hh, data_two.ipsrcport_current, current_user_p, tmp1)
  {
    HASH_DEL (data_two.ipsrcport_current, current_user_p);
    free (current_user_p);
  }
  HASH_ITER (hh, data_two.ipdstport_current, dst_dstport, tmp3)
  {
    HASH_DEL (data_two.ipdstport_current, dst_dstport);
    free (dst_dstport);
  }
  HASH_ITER (hh, data_two.pb_current, np, tmp4)
  {
    HASH_DEL (data_two.pb_current, np);
    free (np);
  }
  HASH_ITER (hh, data_two.ipsrcdstport_current, spcp, tmp5)
  {
    HASH_DEL (data_two.ipsrcdstport_current, spcp);
    free (spcp);
  }
  free (data_two.ipsrc_current);
  free (data_two.ipdst_current);
  free (data_two.ipsrcport_current);
  free (data_two.ipdstport_current);
  free (data_two.pb_current);
  free (data_two.ipsrcdstport_current);
  data_two.ipsrc_current = NULL;
  data_two.ipdst_current = NULL;
  data_two.ipsrcport_current = NULL;
  data_two.ipdstport_current = NULL;
  data_two.pb_current = NULL;
  data_two.ipsrcdstport_current = NULL;
  HASH_ITER (hh, data_two_cpy.ipsrc_current, ip_src, tmp)
  {
    HASH_DEL (data_two_cpy.ipsrc_current, ip_src);
    free (ip_src);
  }
  HASH_ITER (hh, data_two_cpy.ipdst_current, ip_dst, tmp2)
  {
    HASH_DEL (data_two_cpy.ipdst_current, ip_dst);
    free (ip_dst);
  }
  HASH_ITER (hh, data_two_cpy.ipsrcport_current, current_user_p, tmp1)
  {
    HASH_DEL (data_two_cpy.ipsrcport_current, current_user_p);
    free (current_user_p);
  }
  HASH_ITER (hh, data_two_cpy.ipdstport_current, dst_dstport, tmp3)
  {
    HASH_DEL (data_two_cpy.ipdstport_current, dst_dstport);
    free (dst_dstport);
  }
  HASH_ITER (hh, data_two_cpy.pb_current, np, tmp4)
  {
    HASH_DEL (data_two_cpy.pb_current, np);
    free (np);
  }
  HASH_ITER (hh, data_two_cpy.ipsrcdstport_current, spcp, tmp5)
  {
    HASH_DEL (data_two_cpy.ipsrcdstport_current, spcp);
    free (spcp);
  }
  free (data_two_cpy.ipsrc_current);
  free (data_two_cpy.ipdst_current);
  free (data_two_cpy.ipsrcport_current);
  free (data_two_cpy.ipdstport_current);
  free (data_two_cpy.pb_current);
  free (data_two_cpy.ipsrcdstport_current);
  data_two_cpy.ipsrc_current = NULL;
  data_two_cpy.ipdst_current = NULL;
  data_two_cpy.ipsrcport_current = NULL;
  data_two_cpy.ipdstport_current = NULL;
  data_two_cpy.pb_current = NULL;
  data_two_cpy.ipsrcdstport_current = NULL;
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
struct entropy_data *
so_getResult (void)
{
  struct entropy_data *pt = NULL;
  pt = &data;
  return pt;
}

// With this function other modules (Kullback) can access the results of this one and use them in their computation
struct twodist_data *
so_getResulttwodist (void)
{
  struct twodist_data *pt = NULL;
  pt = &data_two;
  return pt;
}

// With this function other modules (Renyi) can access the results of this one and use them in their computation
struct twodist_data *
so_getResulttwodistre (void)
{
  struct twodist_data *pt = NULL;
  copy_current_src ();
  copy_current_dst ();
  copy_current_srcport ();
  copy_current_dstport ();
  copy_current_npackbyt ();
  copy_current_ipsrcdstport ();
  pt = &data_two_cpy;
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
  data_two.ipsrc_current = NULL;
  data_two.ipdst_current = NULL;
  data_two.ipsrcport_current = NULL;
  data_two.ipdstport_current = NULL;
  data_two.pb_current = NULL;
  data_two.ipsrcdstport_current = NULL;
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

// Process the flows with ip source point of view
// r_current --> flows of the current timeslot
// current_flows --> number of the flows of the current timeslot
int
process_twodist (nf_record_t * r_current, int current_flows)
{
  // Default block dimension
  int z = 0;
  for (z = 1; z <= current_flows; z++)
    {
      // Collect ip src
      struct ip_src_frequency *s;
      HASH_FIND_INT (data_two.ipsrc_current,
		     &r_current[z].ip_union._v4_2.srcaddr, s);
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
	  HASH_ADD_INT (data_two.ipsrc_current, ip_src, s);
	}
      else
	s->frequency += 1;


      // Collect ip dst
      struct ip_dst_frequency *d;	// Compute Kullback-Leibler on hash tables
      HASH_FIND_INT (data_two.ipdst_current,
		     &r_current[z].ip_union._v4_2.dstaddr, d);
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
	  HASH_ADD_INT (data_two.ipdst_current, ip_dst, d);
	}
      else
	d->frequency += 1;


      // Collect ip dst - dst port
      struct ip_dst_dstport_frequency l, *t, *dstport;
      memset (&l, 0, sizeof (struct ip_dst_dstport_frequency));
      l.key.ip_dst = r_current[z].ip_union._v4_2.dstaddr;
      l.key.dstport = r_current[z].dstport;
      HASH_FIND (hh, data_two.ipdstport_current, &l.key,
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
	  HASH_ADD (hh, data_two.ipdstport_current, key,
		    sizeof (struct key_ipdstport_frequency), dstport);
	}
      else
	t->frequency += 1;


      // Collect packets number - bytes number
      struct npackets_nbytes f, *b, *npackbyt;
      memset (&f, 0, sizeof (struct npackets_nbytes));
      f.key.dOctets = r_current[z].dOctets;
      f.key.dPkts = r_current[z].dPkts;
      HASH_FIND (hh, data_two.pb_current, &f.key,
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
	  HASH_ADD (hh, data_two.pb_current, key,
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
      HASH_FIND (hh, data_two.ipsrcdstport_current, &v.key,
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
	  HASH_ADD (hh, data_two.ipsrcdstport_current, key,
		    sizeof (struct key_ipsrcdst_srcdstport), ipsrcdstport);
	}
      else
	m->frequency += 1;

      // Collect ip src - src port
      struct ip_src_srcport_frequency p, *rs, *ipsrcport;
      memset (&p, 0, sizeof (struct ip_src_srcport_frequency));
      p.key.ip_src = r_current[z].ip_union._v4_2.srcaddr;
      p.key.srcport = r_current[z].srcport;
      HASH_FIND (hh, data_two.ipsrcport_current, &p.key,
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
	  HASH_ADD (hh, data_two.ipsrcport_current, key,
		    sizeof (struct key_ipsrcport_frequency), ipsrcport);
	}
      else
	rs->frequency += 1;
    }
  // Copy Number of elements to compute the entropy
  unsigned int num_ip_src;
  num_ip_src = HASH_COUNT (data_two.ipsrc_current);
  data_two.unique_src_current = num_ip_src;
  unsigned int num_ip_srcport;
  num_ip_srcport = HASH_COUNT (data_two.ipsrcport_current);
  data_two.unique_ipsrc_srcport_current = num_ip_srcport;
  unsigned int num_ip_dst;
  num_ip_dst = HASH_COUNT (data_two.ipdst_current);
  data_two.unique_dst_current = num_ip_dst;
  unsigned int num_ip_dstport;
  num_ip_dstport = HASH_COUNT (data_two.ipdstport_current);
  data_two.unique_ipdst_dstport_current = num_ip_dstport;
  unsigned int num_npackbyt;
  num_npackbyt = HASH_COUNT (data_two.pb_current);
  data_two.unique_npack_nbytes_current = num_npackbyt;
  unsigned int num_ipsrcdstport;
  num_ipsrcdstport = HASH_COUNT (data_two.ipsrcdstport_current);
  data_two.unique_ipsrcdstport_current = num_ipsrcdstport;
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_src (void)
{
  data_two_cpy.ipsrc_current = NULL;
  struct ip_src_frequency *ip_src, *tmp;
  HASH_ITER (hh, data_two.ipsrc_current, ip_src, tmp)
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
    HASH_ADD_INT (data_two_cpy.ipsrc_current, ip_src, s);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_dst (void)
{
  data_two_cpy.ipdst_current = NULL;
  struct ip_dst_frequency *ip_dst, *tmp;
  HASH_ITER (hh, data_two.ipdst_current, ip_dst, tmp)
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
    HASH_ADD_INT (data_two_cpy.ipdst_current, ip_dst, s);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_srcport (void)
{
  data_two_cpy.ipsrcport_current = NULL;
  struct ip_src_srcport_frequency *ip_src, *tmp;
  HASH_ITER (hh, data_two.ipsrcport_current, ip_src, tmp)
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
    HASH_ADD (hh, data_two_cpy.ipsrcport_current, key,
	      sizeof (struct key_ipsrcport_frequency), ipsrcport);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_dstport (void)
{
  data_two_cpy.ipdstport_current = NULL;
  struct ip_dst_dstport_frequency *ip_dst, *tmp;
  HASH_ITER (hh, data_two.ipdstport_current, ip_dst, tmp)
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
    HASH_ADD (hh, data_two_cpy.ipdstport_current, key,
	      sizeof (struct key_ipdstport_frequency), ipdstport);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_npackbyt (void)
{
  data_two_cpy.pb_current = NULL;
  struct npackets_nbytes *pb, *tmp;
  HASH_ITER (hh, data_two.pb_current, pb, tmp)
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
    HASH_ADD (hh, data_two_cpy.pb_current, key,
	      sizeof (struct key_npackets_nbytes), npackbyt);
  }
  return STATUS_OK;
}

// Copy the current timeslot flows with ip source point of view in the past timeslot flows
int
copy_current_ipsrcdstport (void)
{
  data_two_cpy.ipsrcdstport_current = NULL;
  struct ipsrcdst_srcdstport *spdp, *tmp;
  HASH_ITER (hh, data_two.ipsrcdstport_current, spdp, tmp)
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
    HASH_ADD (hh, data_two_cpy.ipsrcdstport_current, key,
	      sizeof (struct key_ipsrcdst_srcdstport), ipsrcdstport);
  }
  return STATUS_OK;
}

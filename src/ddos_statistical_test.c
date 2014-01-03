 /*************************************************************************
 *  ddos_statistical_test.c
 *
 *  Detecting Distributed Denial-of-Service Attack Traffic by Statistical Test - ChinaCom 2008  
 * 
 *  Copyright (C) Andrea Cosentino 2012
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "frequency.h"

#define UNUSUAL_HAND_NUM (4)
#define MAX_VIOLATIONS (3)

// Global values to store results
float syn_pack_rate = 0.0;
float complete_connections_rate = 0.0;
float incomplete_connections_rate = 0.0;

// Global Variable for passing results to other modules if needed
float entropy_res = 0.0;

// Metric values
float threshold = 0.3;
float over_mean = 0.05;
float threshold_connections = 0.035;

// Global variables
struct freq_connections *data = NULL;
// iterations number
int iterations = 0;
// repeated violations number
int violations = 0;
// consecutive violations indicator
int consecutive = 0;
// filename to log into
char filename[FILENAME_MAX];
// File for logging purpose
char resultname[FILENAME_MAX];
// Total analyzed flows
int sum_flows = 0;
// Logdir specified
char *spec_logdir = NULL;
// SYN Packets in WINDOWS timeslot
float *windows_syn = NULL;
// incomplete connections in WINDOWS timeslot
float *windows_inco_connections = NULL;
// connections in WINDOWS timeslot
float *windows_co_connections = NULL;

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

// Init hash table
double init_all (int numflows);
// Computing syn packets number
int count_syn (void);
// Computing incomplete syn/syn-ack/ack connection
int count_incomplete_syn (void);
// Computing complete handshakes (syn,syn/ack,ack) occurrences
int count_complete_syn (void);
// Set the correct value for threshold
void adjust_threshold (void);
// Process the flows with ip source point of view
int process (nf_record_t * r_current, int current_flows);

//standard entry point
double
so_init (int numflows)
{
  int ret_func = 0;
  iterations++;
  sum_flows += numflows;
  if (iterations == 1)
    {
      strncpy (filename, setFileName (STATEST, spec_logdir), FILENAME_MAX);
      strncpy (resultname, setFileNameResults (STATEST), FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Ddos_statistical_test.so module", -1);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  //Allocate the space for block dimension data_synf
  printf
    ("[Info] Start Computing DDoS Statistical Test for the last timeslot \n");
  writeLogFile (filename, INFO, "Timeslot flows", numflows);
  printf ("[Info] Timeslot flows %d \n", numflows);
  ret_func = init_all (numflows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  return STATUS_OK;
}

//standard entry point
double
so_process (nf_record_t * r_current, int current_flows, char *bucket_id)
{
  writeLogFile (filename, BUCKET, bucket_id, -1);
  // syn packet
  int u1 = 0;
  // syn/syn ack/ack incomplete connections
  int u2 = 0;
  // syn/syn ack/ack complete connections
  int u3 = 0;
  int alarm_high = 0;
  int alarm_low = 0;
  int ret_func = 0;
  ret_func = process (r_current, current_flows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  // Output the number total flows 
  u1 = count_syn ();
  u2 = count_incomplete_syn ();
  u3 = count_complete_syn ();
  // Allocate space to mantain the data of different timeslot
  syn_pack_rate = (float) u1 / current_flows;
  incomplete_connections_rate = (float) u2 / current_flows;
  complete_connections_rate = (float) u3 / current_flows;
  printf ("[Info] Syn Packet Threshold is %f \n", threshold);
  printf ("[Info] Incomplete Connections Threshold is %f \n",
	  threshold_connections);
  printf ("[Info] Syn Packets Rate of current timeslot: %f \n",
	  syn_pack_rate);
  printf ("[Info] Incomplete connections Rate of current timeslot: %f \n",
	  incomplete_connections_rate);
  printf ("[Info] Complete connections Rate of current timeslot: %f \n",
	  complete_connections_rate);
  // High-rate attack checking by threshold comparing
  if (syn_pack_rate >= threshold)
    {
      printf ("[Alarm] Syn Packets Rate is Over Threshold! \n");
      writeLogFile (filename, ALARM,
		    "Syn Packets Rate is Over Threshold. High-rate Attack Detected.\n\n",
		    -1);
      alarm_high = 1;
    }
  // Low-rate attack checking
  else
    {
      float difference =
	complete_connections_rate - incomplete_connections_rate;
      if (difference >= threshold_connections)
	{
	  printf
	    ("[Alarm] Incomplete Connections Rate is Over Threshold! \n");
	  writeLogFile (filename, ALARM,
			"Incomplete Connections Rate is Over Threshold. Low-rate Attack Detected.\n\n",
			-1);
	  alarm_low = 1;
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
	       "Timeslot Bucket,Syn packets Rate,Incomplete Connections Rate, Complete connections rate, alarm High Rate attack, alarm low rate attack \n");
    }
  fprintf (fs, "%s,%.6f,%.6f,%.6f,%d,%d \n", bucket_id,
	   syn_pack_rate,
	   incomplete_connections_rate,
	   complete_connections_rate, alarm_high, alarm_low);
  fclose (fs);
  return STATUS_OK;
  //when returning the value the worker will read and save it in its own structure
  //in case of a dependency the worker will save this result in the dep_results array you don't have to do it here
}

//standard entry point
double
so_close (void)
{
  // free resources
  struct freq_connections *spcp, *tmp5;
  HASH_ITER (hh, data, spcp, tmp5)
  {
    int i = 0;
    for (i = 0; i < spcp->num; i++)
      {
	free (spcp->str_flag[i]);
      }
    HASH_DEL (data, spcp);
    free (spcp);
  }
  free (data);
  data = NULL;
  writeLogFile (filename, INFO, "Total analyzed flows", sum_flows);
  return STATUS_OK;
}

// Logging function
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
  pt = (void **) malloc (3 * sizeof (void *));
  pt[0] = malloc (sizeof (void *));
  pt[1] = malloc (sizeof (void *));
  pt[2] = malloc (sizeof (void *));
  *(float *) pt[0] = syn_pack_rate;
  *(float *) pt[1] = incomplete_connections_rate;
  *(float *) pt[2] = complete_connections_rate;
  return pt;
}

// Init all provide to initialize the data field of the entropy_data struct
// INPUT: numflows, the flows of the current timeslot
double
init_all (int numflows)
{
  data = NULL;
  return STATUS_OK;
}

// Process the flows with ip source point of view
// r_current --> flows of the current timeslot
// current_flows --> number of the flows of the current timeslot
int
process (nf_record_t * r_current, int current_flows)
{
  int z = 0;
  for (z = 1; z <= current_flows; z++)
    {
      // Collect ip src - src port
      struct freq_connections p, *rs, *conn;
      memset (&p, 0, sizeof (struct freq_connections));
      p.key.ip_src = r_current[z].ip_union._v4_2.srcaddr;
      p.key.ip_dst = r_current[z].ip_union._v4_2.dstaddr;
      HASH_FIND (hh, data, &p.key, sizeof (struct key_connections), rs);
      if (rs == NULL)
	{
	  conn =
	    (struct freq_connections *)
	    malloc (sizeof (struct freq_connections));
	  if (conn == NULL)
	    {
	      printf ("[Info] Problem in memory allocation in process \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in process",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (conn, 0, sizeof (struct freq_connections));
	  conn->num = conn->num + 1;
	  conn->key.ip_src = r_current[z].ip_union._v4_2.srcaddr;
	  conn->key.ip_dst = r_current[z].ip_union._v4_2.dstaddr;
	  conn->ip_src = r_current[z].ip_union._v4_2.srcaddr;
	  conn->ip_dst = r_current[z].ip_union._v4_2.dstaddr;
	  conn->str_flag = malloc (sizeof (char *));
	  conn->str_flag[(conn->num) - 1] = malloc (16 * sizeof (char));
	  strncpy (conn->str_flag[(conn->num) - 1],
		   r_current[z].tcp_flags_str, 16);
	  conn->first = r_current[z].first;
	  HASH_ADD (hh, data, key, sizeof (struct key_connections), conn);
	}
      else
	{
	  conn->num = conn->num + 1;
	  conn->str_flag =
	    realloc (conn->str_flag, (conn->num) * sizeof (char *));
	  conn->str_flag[(conn->num) - 1] = malloc (16 * sizeof (char));
	  strncpy (conn->str_flag[(conn->num) - 1],
		   r_current[z].tcp_flags_str, 16);
	}
    }
  return STATUS_OK;
}

// Computing unusual handshakes (syn,d) occurrences
// data struct flags_info
// count number of flows
int
count_syn (void)
{
  int syn = 0;
  struct freq_connections *conn_curr, *tmp_current;
  HASH_ITER (hh, data, conn_curr, tmp_current)
  {
    int i = 0;
    for (i = 0; i < conn_curr->num; i++)
      {
	if (conn_curr->str_flag[i][4] == 'S')
	  syn++;
      }
  }
  return syn;
}

// Computing incomplete handshakes (syn,syn/ack,ack) occurrences
int
count_incomplete_syn (void)
{
  int incomplete_syn = 0;
  int i = 0;
  int f = 0;
  int z = 0;
  int found = 0;
  struct freq_connections *conn_curr, *tmp_current;
  HASH_ITER (hh, data, conn_curr, tmp_current)
  {
    for (i = 0; i < conn_curr->num; i++)
      {
	if (conn_curr->str_flag[i][4] == 'S'
	    && conn_curr->str_flag[i][1] == '.')
	  {
	    struct freq_connections *rs;
	    struct freq_connections p;
	    p.key.ip_src = conn_curr->key.ip_dst;
	    p.key.ip_dst = conn_curr->key.ip_src;
	    HASH_FIND (hh, data, &p.key, sizeof (struct key_connections), rs);
	    if (rs != NULL)
	      {
		for (f = 0; f < rs->num; f++)
		  {
		    if (rs->str_flag[f][4] == 'S'
			&& rs->str_flag[f][1] == 'A')
		      {
			for (z = 0; z < conn_curr->num; z++)
			  {
			    if (conn_curr->str_flag[z][1] == 'A')
			      {
				found = 1;
				break;
			      }
			  }
			if (found == 0)
			  incomplete_syn++;
			found = 0;
		      }
		    else
		      incomplete_syn++;
		  }
	      }
	  }
      }
  }
  return incomplete_syn;
}

// Computing complete handshakes (syn,syn/ack,ack) occurrences
int
count_complete_syn (void)
{
  int complete_syn = 0;
  int i = 0;
  int f = 0;
  int z = 0;
  struct freq_connections *conn_curr, *tmp_current;
  HASH_ITER (hh, data, conn_curr, tmp_current)
  {
    for (i = 0; i < conn_curr->num; i++)
      {
	if (conn_curr->str_flag[i][4] == 'S'
	    && conn_curr->str_flag[i][1] == '.')
	  {
	    struct freq_connections *rs;
	    struct freq_connections p;
	    p.key.ip_src = conn_curr->key.ip_dst;
	    p.key.ip_dst = conn_curr->key.ip_src;
	    HASH_FIND (hh, data, &p.key, sizeof (struct key_connections), rs);
	    if (rs != NULL)
	      {
		for (f = 0; f < rs->num; f++)
		  {
		    if (rs->str_flag[f][4] == 'S'
			&& rs->str_flag[f][1] == 'A')
		      {
			for (z = 0; z < conn_curr->num; z++)
			  {
			    if (conn_curr->str_flag[z][1] == 'A')
			      {
				complete_syn++;
				break;
			      }
			  }
		      }
		  }
	      }
	  }
      }
  }
  return complete_syn;
}

// Threshold update. Every timeslot we call this function
void
adjust_threshold (void)
{
  int i;
  float sum = 0;
  float mean = 0.0;
  for (i = iterations - 2; i >= 0; i--)
    {
      sum += windows_syn[i];
    }
  mean = (float) sum / (iterations - 2);
  threshold = (1 + over_mean) * mean;
}

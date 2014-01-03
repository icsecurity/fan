 /*************************************************************************
 *  syn_flooding.c
 *
 *  SYN Flooding Attack Detection based on entropy computing - Globecom 2009  
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

// Global Variable for passing results to other modules if needed
float entropy_res = 0.0;

// Metric values
float threshold = 0.3;
float over_mean = 0.05;

// Global variables
struct freq_connections *data = NULL;
int *frequency_array_synf = NULL;
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
float *windows_entropy = NULL;

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

// count syn pkts in the last timeslot
int count_syn_packets (struct flags_info *data, int count);
// Process the flows with ip source point of view
// r_current --> flows of the current timeslot
// current_flows --> number of the flows of the current timeslot
int process (nf_record_t * r_current, int current_flows);
// Computing unusual handshakes (syn,d) occurrences
int count_unusual_handshakes_syn (int delay);

// Computing unusual handshakes (syn(client,server),rst(server,client)) occurrences
int count_unusual_handshakes_un_syn_rst_sc (void);

// Computing unusual handshakes (syn,syn/ack,d) occurrences
int count_unusual_handshakes_un_syn_synack (int delay);

// Computing unusual handshakes (syn,syn/ack,rst(client,server)) occurrences
int count_unusual_handshakes_un_syn_synack_rst_cs (void);

//standard entry point
double
so_init (int numflows)
{
  iterations++;
  sum_flows += numflows;
  if (iterations == 1)
    {
      strncpy (filename, setFileName (SYNFLOODINGLOGNAME, spec_logdir),
	       FILENAME_MAX);
      strncpy (resultname, setFileNameResults (SYNFLOODINGLOGNAME),
	       FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Syn_flooding.so module", -1);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  //Allocate the space for block dimension data_synf
  printf
    ("[Info] Start Computing Unusual Handshake Entropy for the last timeslot \n");
  writeLogFile (filename, INFO, "Timeslot flows", numflows);
  printf ("[Info] Timeslot flows %d \n", numflows);
  frequency_array_synf = (int *) malloc (UNUSUAL_HAND_NUM * sizeof (int));
  if (frequency_array_synf == NULL)
    {
      writeLogFile (filename, MEMORY_ERROR, "Problem in memory allocation",
		    -1);
      return MEMORY_ERROR;
    }
  memset (frequency_array_synf, 0, UNUSUAL_HAND_NUM * sizeof (int));
  return STATUS_OK;
}

//standard entry point
double
so_process (nf_record_t * r_current, int current_flows, char *bucket_id)
{
  writeLogFile (filename, BUCKET, bucket_id, -1);
  // Sum of unusual handshake
  int unusual_sum = 0;
  // (syn,d) unusual handshake
  int u1 = 0;
  // (syn(client,server),rst(server,client)) unusual handshake
  int u2 = 0;
  // (syn,syn/ack,d) unusual handshake
  int u3 = 0;
  // (syn,syn/ack,rst(client,server)) unusual handshake
  int u4 = 0;
  int alarm_ent = 0;
  int i = 0;
  float entropy = 0.0;
  // Total elements
  int ret_func = 0;
  ret_func = process (r_current, current_flows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  // Computing the unusual handshakes occurences  
  u1 = count_unusual_handshakes_syn (DELAY_SYN_FLOODING);
  u2 = count_unusual_handshakes_un_syn_rst_sc ();
  u3 = count_unusual_handshakes_un_syn_synack (DELAY_SYN_FLOODING);
  u4 = count_unusual_handshakes_un_syn_synack_rst_cs ();
  // Storing the unusual handshake occurences
  frequency_array_synf[0] = u1;
  frequency_array_synf[1] = u2;
  frequency_array_synf[2] = u3;
  frequency_array_synf[3] = u4;
  // Computing the unusual handshakes sum
  for (i = 0; i < UNUSUAL_HAND_NUM; i++)
    unusual_sum += frequency_array_synf[i];
  printf ("[Info] Total Unusual Handshakes: %d \n", unusual_sum);
  writeLogFile (filename, INFO, "Total Unusual Handshakes", unusual_sum);
  printf ("[Info] Unusual Handshakes (syn,d): %d \n",
	  frequency_array_synf[0]);
  printf
    ("[Info] Unusual Handshakes (syn(client,server),rst(server,client)): %d \n",
     frequency_array_synf[1]);
  printf ("[Info] Unusual Handshakes (syn,syn/ack,d): %d \n",
	  frequency_array_synf[2]);
  printf ("[Info] Unusual Handshakes (syn,syn/ack,rst(client,server)): %d \n",
	  frequency_array_synf[3]);
  // if we have > 0 unusual handshake then we compute entropy
  if (unusual_sum > 0)
    {
      entropy =
	compute_entropy (frequency_array_synf, UNUSUAL_HAND_NUM, unusual_sum);
    }
  printf ("[Info] Entropy of unusual handshake Threshold is: %f \n",
	  threshold);
  printf ("[Info] Entropy of Unusual Handshakes is: %f \n", entropy);
  entropy_res = entropy;
  if (entropy <= threshold)
    {
      consecutive = 1;
      violations++;
    }
  else
    {
      consecutive = 0;
      violations = 0;
    }
  if (consecutive == 1 && violations == MAX_VIOLATIONS)
    {
      printf
	("[!!!Alarm!!!] Entropy of Unusual Handshakes is under the threshold in the last %d timeslot \n",
	 MAX_VIOLATIONS);
      writeLogFile (filename, ALARM,
		    "Entropy of Unusual Handshakes is under the threshold\n\n",
		    -1);
      violations = 0;
      consecutive = 0;
      alarm_ent = 1;
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
	       "Timeslot Bucket,Unusual handshake (syn d),Unusual Handshakes (syn(client server) rst(server client)),Unusual Handshakes (syn syn/ack d), Unusual Handshakes (syn syn/ack rst(client server)), Total unusual handshakes, Unusual handshakes entropy, threshold, alarm syn flooding\n");
    }
  fprintf (fs, "%s,%d,%d,%d,%d,%d,%.6f,%.6f,%d \n", bucket_id,
	   frequency_array_synf[0], frequency_array_synf[1],
	   frequency_array_synf[2], frequency_array_synf[3], unusual_sum,
	   entropy, threshold, alarm_ent);
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
  free (frequency_array_synf);
  frequency_array_synf = NULL;
  writeLogFile (filename, INFO, "Total analyzed flows", sum_flows);
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
  pt = (void **) malloc (1 * sizeof (void *));
  pt[0] = malloc (sizeof (void *));
  *(float *) pt[0] = entropy_res;
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
// delay a detection delay
int
count_unusual_handshakes_syn (int delay)
{
  int un_syn = 0;
  int i = 0;
  int f = 0;
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
		    if (rs->str_flag[f][4] == 'S' && rs->str_flag[f][1] == 'A'
			&& (rs->first > delay))
		      {
			found = 1;
		      }
		  }
		if (found == 0)
		  un_syn++;
		found = 0;
	      }
	  }
      }
  }
  return un_syn;
}

// Computing unusual handshakes (syn(client,server),rst(server,client)) occurrences
// data struct flags_info
// count number of flows
int
count_unusual_handshakes_un_syn_rst_sc (void)
{
  int un_syn_rst_sc = 0;
  int i = 0;
  int f = 0;
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
		    if ((rs->str_flag[f][3] == 'R'))
		      {
			un_syn_rst_sc++;
			break;
		      }
		  }
	      }
	  }
      }
  }
  return un_syn_rst_sc;
}

// Computing unusual handshakes (syn,syn/ack,d) occurrences
// data struct flags_info
// count number of flows
// delay a detection delay
int
count_unusual_handshakes_un_syn_synack (int delay)
{
  int un_syn_synack = 0;
  int i = 0;
  int f = 0;
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
		    if (rs->str_flag[f][4] == 'S' && rs->str_flag[f][1] == 'A'
			&& (rs->first > delay))
		      {
			un_syn_synack++;
			break;
		      }
		  }
	      }
	  }
      }
  }
  return un_syn_synack;
}

// Computing unusual handshakes (syn,syn/ack,rst(client,server)) occurrences
// data struct information
// count number of flows
// delay a detection delay
int
count_unusual_handshakes_un_syn_synack_rst_cs (void)
{
  int un_syn_synack_rst_cs = 0;
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
			    if ((conn_curr->str_flag[z][3] == 'R'))
			      {
				un_syn_synack_rst_cs++;
				break;
			      }
			  }
		      }
		  }
	      }
	  }
      }
  }
  return un_syn_synack_rst_cs;
}

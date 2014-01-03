 /*************************************************************************
 *  Kmeans_anomaly.c
 *
 *  Traffic Anomaly Detection Using K-Means Clustering - Muenz 2007 
 * 
 *  Copyright (C) Andrea Cosentino 2012
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <float.h>
#include "frequency.h"
#include "log.h"
#include "./cluster-1.50/src/cluster.h"

// iterations number
int iterations = 0;
int passed_iter = 0;
// filename to log into
char filename[FILENAME_MAX];
// File for logging purpose
char resultname[FILENAME_MAX];
// Total analyzed flows
int sum_flows = 0;
// Logdir specified
char *spec_logdir = NULL;
// Hash table
struct freq_kmeans_anomaly *data;
int f = 0;

// Data structure for clustering
double **dataclust = NULL;
// Normal traffic
double **dataclust_normal = NULL;
// Mask of the clusters
int **mask = NULL;
int **mask_normal = NULL;
// Attributes number
int ncols = 3;
double **cluster = NULL;
double **cluster_normal = NULL;

// protocol to analyze
#define prot_analyze (6)
#define num_cluster (1)
#define max_distance (2.00)
// Threshold
#define tcp_tp (0.1)
#define tcp_tb (3.5)
#define tcp_dp (0.7)
#define udp_tp (0.2)
#define udp_tb (4.0)
#define udp_dp (0.5)
#define icmp_tp (0.6)
#define icmp_tb (3.1)
#define icmp_dp (0.12)

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

// Clustering functions
void show_data (int nrows, int ncols, double **data, int **mask);
int process (nf_record_t * r_current, int current_flows);
double **kmeans (int nrows, int ncols, double **data, int **mask);
double distance (double **cdata, double **cdatanormal, int ncols);

//standard entry point
double
so_init (int numflows)
{
  iterations++;
  passed_iter++;
  sum_flows += numflows;
  if (iterations == 1)
    {
      strncpy (filename, setFileName (KMEANS, spec_logdir), FILENAME_MAX);
      strncpy (resultname, setFileNameResults (KMEANS), FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Kmeans_anomaly.so module", -1);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  printf
    ("[Info] Start Computing Traffic Anomaly Detection Using K-Means Clustering for the last timeslot \n");
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
  int ret_func = 0;
  int udp_num = 0;
  int tcp_num = 0;
  int icmp_num = 0;
  int alarm = 0;
  // Analyze data by different entropy base
  // IP source
  ret_func = process (r_current, current_flows);
  if (ret_func != STATUS_OK)
    {
      return ret_func;
    }
  struct freq_kmeans_anomaly *protocol_freq, *tmp4;
  HASH_ITER (hh, data, protocol_freq, tmp4)
  {
    if (protocol_freq->key.protocol == 6)
      tcp_num++;
    else if (protocol_freq->key.protocol == 17)
      udp_num++;
    else if (protocol_freq->key.protocol == 1)
      icmp_num++;
  }
  if (prot_analyze == 6)
    writeLogFile (filename, STATUS_OK, "Choosen Protocol: TCP", -1);
  if (prot_analyze == 17)
    writeLogFile (filename, STATUS_OK, "Choosen Protocol: UDP", -1);
  if (prot_analyze == 1)
    writeLogFile (filename, STATUS_OK, "Choosen Protocol: ICMP", -1);
  printf ("[Info] TCP elements %d \n", tcp_num);
  writeLogFile (filename, INFO, "TCP elements", tcp_num);
  printf ("[Info] UDP elements %d \n", udp_num);
  writeLogFile (filename, INFO, "UDP elements", udp_num);
  printf ("[Info] ICMP elements %d \n", icmp_num);
  writeLogFile (filename, INFO, "ICMP elements", icmp_num);
  // Collect the data to make traffic cluster
  HASH_ITER (hh, data, protocol_freq, tmp4)
  {
    if (protocol_freq->key.protocol == prot_analyze)
      {
	if (f == 0)
	  {
	    dataclust = malloc (1 * sizeof (double *));
	    mask = malloc (1 * sizeof (int *));
	    dataclust[0] = malloc (ncols * sizeof (double));
	    mask[0] = malloc (ncols * sizeof (int));
	    memset (mask[0], 1, ncols * sizeof (int));
	    dataclust[0][0] = (double) log (protocol_freq->sum_dPkts);
	    dataclust[0][1] = (double) log (protocol_freq->sum_dOctets);
	    dataclust[0][2] = (double) log (protocol_freq->different_pairs);
	    f++;
	  }
	else
	  {
	    dataclust = realloc (dataclust, (f + 1) * sizeof (double *));
	    mask = realloc (mask, (f + 1) * sizeof (int *));
	    dataclust[f] = malloc (ncols * sizeof (double));
	    mask[f] = malloc (ncols * sizeof (int));
	    memset (mask[f], 1, ncols * sizeof (int));
	    dataclust[f][0] = (double) log (protocol_freq->sum_dPkts);
	    dataclust[f][1] = (double) log (protocol_freq->sum_dOctets);
	    dataclust[f][2] = (double) log (protocol_freq->different_pairs);
	    f++;
	  }
      }
  }
  // Prepare data for normal cluster
  dataclust_normal = malloc (1 * sizeof (double *));
  mask_normal = malloc (1 * sizeof (int *));
  dataclust_normal[0] = malloc (ncols * sizeof (double));
  mask_normal[0] = malloc (ncols * sizeof (int));
  memset (mask_normal[0], 1, ncols * sizeof (int));
  if (prot_analyze == 1)
    {
      dataclust_normal[0][0] = (double) icmp_tp;
      dataclust_normal[0][1] = (double) icmp_tb;
      dataclust_normal[0][2] = (double) icmp_dp;
    }
  if (prot_analyze == 6)
    {
      dataclust_normal[0][0] = (double) tcp_tp;
      dataclust_normal[0][1] = (double) tcp_tb;
      dataclust_normal[0][2] = (double) tcp_dp;
    }
  if (prot_analyze == 17)
    {
      dataclust_normal[0][0] = (double) udp_tp;
      dataclust_normal[0][1] = (double) udp_tb;
      dataclust_normal[0][2] = (double) udp_dp;
    }
  // Build the two cluster
  cluster_normal = kmeans (1, ncols, dataclust_normal, mask_normal);
  cluster = kmeans (f, ncols, dataclust, mask);
  printf ("[Info] Clustering:");
  printf ("\t%8s", "Total pkts");
  printf ("\t%8s", "Total bytes");
  printf ("\t%8s", "Diff pairs");
  printf ("\n");
  int i = 0;
  int j = 0;
  printf ("[Info] Cluster %2d:", 0);
  for (j = 0; j < ncols; j++)
    {
      printf ("\t%8.3f", cluster_normal[i][j]);
    }
  printf ("\n");
  printf ("[Info] Cluster %2d:", 1);
  for (j = 0; j < ncols; j++)
    {
      printf ("\t%8.3f", cluster[i][j]);
    }
  printf ("\n");
  // Compute distances between the two clusters
  double dist = distance (cluster, cluster_normal, ncols);
  printf
    ("[Info] Distance between normal cluster and current cluster %.3f \n",
     dist);
  // Verify by threshold if their so much far
  if (dist > max_distance)
    {
      printf ("[!!!Alarm!!!] Distance is over the limit\n");
      writeLogFile (filename, ALARM, "Distance is over the limit\n\n", -1);
      alarm = 1;
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
	       "Timeslot Bucket,Normal cluster total packets, Normal cluster total bytes, Normal cluster different pairs, Traffic cluster total packets, Traffic cluster total bytes, Traffic cluster different pairs, distance, alarm \n");
    }
  fprintf (fs, "%s,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%d \n", bucket_id,
	   cluster_normal[i][0], cluster_normal[i][1], cluster_normal[i][2],
	   cluster[i][0], cluster[i][1], cluster[i][2], dist, alarm);
  fclose (fs);
  free(cluster_normal);
  free(cluster);
  return STATUS_OK;
}

//standard entry point
double
so_close (void)
{
  struct freq_kmeans_anomaly *prot_freq, *tmp4;
  HASH_ITER (hh, data, prot_freq, tmp4)
  {
    HASH_DEL (data, prot_freq);
    //free(prot_freq);
  }
  free (data);
  data = NULL;
  int t;
  for (t = 0; t < f; t++)
    {
      free (dataclust[t]);
      free (mask[t]);
    }
  free (dataclust_normal[0]);
  free (mask_normal[0]);
  dataclust = NULL;
  f = 0;
  printf
    ("[Info] End computing Traffic Anomaly Detection Using K-Means Clustering for the last timeslot \n");
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
  pt = (void **) malloc (((ncols * num_cluster) + 2) * sizeof (void *));
  int i = 0;
  int j = 0;
  for (i = 0; i < (ncols * num_cluster) + 2; i++)
    {
      pt[i] = malloc (sizeof (void *));
    }
  *(int *) pt[0] = num_cluster;
  *(int *) pt[1] = ncols;
  int s = 2;
  for (i = 0; i < num_cluster; i++)
    {
      for (j = 0; j < ncols; j++)
	{
	  *(float *) pt[s] = cluster[i][j];
	  s++;
	}
    }
  return pt;
}

// Collect data
int
process (nf_record_t * r_current, int current_flows)
{
  // Default block dimension
  int z = 0;
  for (z = 1; z <= current_flows; z++)
    {
      // Collect elements
      struct freq_kmeans_anomaly pf, *tf;
      memset (&pf, 0, sizeof (struct freq_kmeans_anomaly));
      pf.key.protocol = r_current[z].prot;
      pf.key.port = r_current[z].srcport;
      HASH_FIND (hh, data, &pf.key, sizeof (struct key_prot_port), tf);
      if (tf == NULL)
	{
	  tf =
	    (struct freq_kmeans_anomaly *)
	    malloc (sizeof (struct freq_kmeans_anomaly));
	  if (tf == NULL)
	    {
	      printf ("[Info] Problem in memory allocation in process \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in process",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (tf, 0, sizeof (struct freq_kmeans_anomaly));
	  tf->key.protocol = r_current[z].prot;
	  tf->key.port = r_current[z].srcport;
	  tf->protocol = r_current[z].prot;
	  tf->port = r_current[z].srcport;
	  tf->sum_dOctets = r_current[z].dOctets;
	  tf->sum_dPkts = r_current[z].dPkts;
	  tf->ip_src = r_current[z].ip_union._v4_2.srcaddr;
	  tf->different_pairs = 1;
	  HASH_ADD (hh, data, key, sizeof (struct key_prot_port), tf);
	}
      else
	{
	  tf->sum_dOctets += r_current[z].dOctets;
	  tf->sum_dPkts += r_current[z].dPkts;
	  tf->different_pairs += 1;
	}
    }
  return STATUS_OK;
}

// K-Means algorithm
double **
kmeans (int nrows, int ncols, double **data, int **mask)
/* Perform k-means clustering on genes */
{
  int i;
  const int nclusters = num_cluster;
  const int transpose = 0;
  const char dist = 'e';
  const char method = 'a';
  int npass = 1;
  int ifound = 0;
  double error;
  int **index;
  int *count;
  double *weight = malloc (ncols * sizeof (double));
  int *clusterid = malloc (nrows * sizeof (int));
  double **cdata = malloc (nclusters * sizeof (double *));
  int **cmask = malloc (nclusters * sizeof (int *));
  for (i = 0; i < nclusters; i++)
    {
      cdata[i] = malloc (ncols * sizeof (double));
      cmask[i] = malloc (ncols * sizeof (int));
    }
  for (i = 0; i < ncols; i++)
    weight[i] = 1.0;
  npass = 2;
  kcluster (num_cluster, nrows, ncols, data, mask, weight, transpose, npass,
	    method, dist, clusterid, &error, &ifound);
  index = malloc (nclusters * sizeof (int *));
  count = malloc (nclusters * sizeof (int));
  for (i = 0; i < nclusters; i++)
    count[i] = 0;
  for (i = 0; i < nrows; i++)
    count[clusterid[i]]++;
  for (i = 0; i < nclusters; i++)
    index[i] = malloc (count[i] * sizeof (int));
  for (i = 0; i < nclusters; i++)
    count[i] = 0;
  for (i = 0; i < nrows; i++)
    {
      int id = clusterid[i];
      index[id][count[id]] = i;
      count[id]++;
    }
  getclustercentroids (nclusters, nrows, ncols, data, mask, clusterid,
		       cdata, cmask, 0, 'a');
  return cdata;
}

// Show data collected (not used)
void
show_data (int nrows, int ncols, double **data, int **mask)
/* Print the data matrix */
{
  int i, j;
  for (j = 0; j < ncols; j++)
    printf ("\tCol %d", j);
  printf ("\n");
  for (i = 0; i < nrows; i++)
    {
      printf ("Row %d", i);
      for (j = 0; j < ncols; j++)
	{
	  if (mask[i][j])
	    printf ("\t%f", data[i][j]);
	  else
	    printf ("\t");	/* mask[i][j]==0, so this data point is missing */
	}
      printf ("\n");
    }
  printf ("\n");
  return;
}

// Compute the distances between the two clusters (normal and traffic) from the centroids values
double
distance (double **cdata, double **cdatanormal, int ncols)
{
  int i = 0;
  float sum = 0.0;
  for (i = 0; i < ncols; i++)
    {
      float intermediate_sum = 0.0;
      float square = 0.0;
      float rad = 0.0;
      intermediate_sum = cdatanormal[0][i] - cdata[0][i];
      square = (float) pow (intermediate_sum, 2);
      rad = sqrt (square);
      sum += rad;
    }
  return sum;
}

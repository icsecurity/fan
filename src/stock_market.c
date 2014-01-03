 /*************************************************************************
 *  stock_market.c
 *
 *  Detection of DdoS traffic by using the 
 *  technical analysis used in the stock market
 *
 * 
 *  Copyright (C) Andrea Cosentino 2012
 **************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "frequency.h"
#include "log.h"

#define TIMESLOT_NUM (10)
#define ROC_THRESHOLD (800)
#define MOMENTUM_THRESHOLD (40)
#define RSI_THRESHOLD (70)
#define MIN_VIOLATIONS (3)

// Global Variable for passing results to other modules if needed
int alarm_res = 0;

int *ts_packets_rate = NULL;
int iterations = 0;
// Logdir specified
char *spec_logdir = NULL;
// filename to log into
char filename[FILENAME_MAX];
// File for logging purpose
char resultname[FILENAME_MAX];
// Total flows
int sum_flows = 0;
// repeated violations number
int violations = 0;
// consecutive violations indicator
int consecutive = 0;

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

double verify_momentum (int n1, int n2);
double verify_RoC (int n1, int n2, int n3);
double verify_RSI (int *data, int iterations);

//standard entry point
double
so_init (int numflows)
{
  //Precomputing Entropy: Consider H(x) = -E p(x)logp(x)  
  iterations++;
  sum_flows += numflows;
  if (iterations == 1)
    {
      strncpy (filename, setFileName (STOCKLOGNAME, spec_logdir),
	       FILENAME_MAX);
      strncpy (resultname, setFileNameResults (STOCKLOGNAME), FILENAME_MAX);
      writeLogFile (filename, STATUS_OK,
		    "Start computing Stock_market.so module", -1);
    }
  if (spec_logdir != NULL)
    free (spec_logdir);
  printf ("[Info] Start computing Stock Market Method \n");
  return STATUS_OK;
}

//standard entry point
double
so_process (nf_record_t * r_current, int current_flows, char *bucket_id)
{
  writeLogFile (filename, BUCKET, bucket_id, -1);
  //dep_result is an array containing the dependencies results
  //dep_results_dim is the dimension of dep_result array since it may vary depend on the stat
  //int cnt=0;
  int packets_rate = 0;
  double momentum = 0;
  int RoC = 0;
  double RSI = 0;
  int i = 0;
  int n1 = 0;
  int n2 = 0;
  double RoC_t1 = 0.0;
  double RoC_t = 0.0;
  double RSI_value = 0.0;
  // In attesa dei netflow di prova commento la parte di acquisizione dati da netflow
  //WARNING  when netflow_n==-1 a dummy single block was sended by the analyzer, remember to skip it with your own checks!
  for (i = 1; i <= current_flows; i++)
    {
      packets_rate += r_current[i].dPkts;
    }
  ts_packets_rate =
    (int *) realloc (ts_packets_rate, (iterations) * sizeof (int));
  ts_packets_rate[iterations - 1] = packets_rate;
  printf ("[Info] Current timeslot Flows Packets Number: %d \n",
	  packets_rate);
  if (iterations >= 2)
    {
      n1 = ts_packets_rate[iterations - 1];
      n2 = ts_packets_rate[iterations - 2];
      momentum = verify_momentum (n1, n2);
      if (momentum >= MOMENTUM_THRESHOLD)
	{
	  if (iterations >= 3)
	    {
	      int n3 = ts_packets_rate[iterations - 3];
	      n2 = ts_packets_rate[iterations - 2];
	      n1 = ts_packets_rate[iterations - 1];
	      RoC_t1 = (double) n2 / n3;
	      RoC_t = (double) n1 / n2;
	      printf ("%f %f \n", RoC_t, RoC_t1);
	      RoC = verify_RoC (n1, n2, n3);
	      if (RoC == 1)
		{
		  consecutive = 1;
		  violations++;
		}
	      else
		{
		  consecutive = 0;
		  violations = 0;
		}
	      if (consecutive == 1 && violations == MIN_VIOLATIONS)
		{
		  RSI_value = verify_RSI (ts_packets_rate, iterations);
		  if (RSI == MOMENTUM_THRESHOLD)
		    {
		      printf ("%s \n", "[!!!Alarm!!!] DDoS Detected");
		      writeLogFile (filename, ALARM, "DDOS detected\n\n", -1);
		      violations = 0;
		      consecutive = 0;
		      alarm_res = 1;
		    }
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
	       "Timeslot Bucket, Momentum, Rate of Change current timeslot, Rate of Change last timeslot, Relative Strenght Index, alarm \n");
    }
  fprintf (fs, "%s,%.6f,%.6f,%.6f,%.6f,%d \n", bucket_id, momentum, RoC_t,
	   RoC_t1, RSI_value, alarm_res);
  fclose (fs);
  return STATUS_OK;
}

//standard entry point
double
so_close ()
{
  //Flush() 
  //write output to disks
  writeLogFile (filename, INFO, "Total analyzed flows", sum_flows);
  printf ("%s \n", "[Info] Stock Market Method End");
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
  *(int *) pt[0] = alarm_res;
  return pt;
}

double
verify_momentum (int n1, int n2)
{
  double difference = 0;
  double division = 0;
  double difference_perc = 0;
  printf ("[Info] Packets Rate last timeslot: %d \n", n2);
  printf ("[Info] Packets Rate current timeslot: %d \n", n1);
  if (n2 != 0)
    {
      difference = (n1 - n2);
      division = (double) difference / n2;
      difference_perc = division * 100;
      printf
	("[Info] Percentage difference between the last two timeslots: %f \n",
	 difference_perc);
    }
  return difference_perc;
}

double
verify_RoC (int n1, int n2, int n3)
{
  if (n2 != 0 && n3 != 0)
    {
      double RoC_t1 = (double) n2 / n3;
      double RoC_t = (double) n1 / n2;
      printf
	("[Info] Rate of change in last time slot: %f \n[Info] Rate of change in current time slot: %f \n",
	 RoC_t1, RoC_t);
      if (RoC_t1 >= ROC_THRESHOLD && RoC_t >= ROC_THRESHOLD)
	return 1;
      else
	return 0;
    }
  else
    return 0;
}

double
verify_RSI (int *data, int iterations)
{
  int n1 = data[iterations - 1];
  int n2 = data[iterations - 2];
  int positive_gain = 0;
  int negative_gain = 0;
  int positive_gain_total_value = 0;
  int negative_gain_total_value = 0;
  int positive_gain_number = 0;
  int negative_gain_number = 0;
  double RSI = 0;
  double RS = 0;
  double G_AVG = 0;
  double L_AVG = 0;
  int i = 0;
  if (n1 - n2 > 0)
    positive_gain = n1 - n2;
  else
    negative_gain = n2 - n1;
  for (i = 0; i < iterations; i++)
    {
      if (i > 1)
	{
	  if (data[i] - data[i - 1] >= 0)
	    {
	      positive_gain_total_value += (data[i] - data[i - 1]);
	      positive_gain_number += 1;
	    }
	  else
	    {
	      negative_gain_total_value += (data[i - 1] - data[i]);
	      negative_gain_number += 1;
	    }
	}
    }
  if (negative_gain_number != 0 && positive_gain_number != 0)
    {
      float mean_positive_gain =
	(double) positive_gain_total_value / positive_gain_number;
      float mean_negative_gain =
	(double) ((negative_gain_total_value / negative_gain_number));
      G_AVG =
	(float) ((mean_positive_gain * (iterations - 1) +
		  positive_gain) / iterations);
      L_AVG =
	(float) (((mean_negative_gain * (iterations - 1) +
		   negative_gain) / iterations));
      RS = (float) G_AVG / L_AVG;
      RSI = (float) (100 - (100 / (1 + RS)));
      printf ("[Info] Relative Strenght Index in current time slot: %f \n",
	      RSI);
    }
  return RSI;
}

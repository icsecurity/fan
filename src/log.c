#include "log.h"

// Logging data for metrics in .so libraries
int
writeLogFile (char *metric, int code, char *operation, double value)
{
  FILE *logFile;
  if (code == STATUS_OK && value == -1)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Info] Operation: %s\n", operation);
      fclose (logFile);
    }
  if (code == BUCKET && value == -1)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Info] Analyzing Bucket: %s\n", operation);
      fclose (logFile);
    }
  if (code == ALARM && value == -1)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "\n[Alarm] %s", operation);
      fclose (logFile);
    }
  if (code == STATUS_OK && value != -1)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Info] %s : %f\n", operation, value);
      fclose (logFile);
    }
  if (code == INFO && value != -1)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Info] %s : %d\n", operation, (int) value);
      fclose (logFile);
    }
  if (code != STATUS_OK && code != ALARM && code != BUCKET && value == -1)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Error] Error: %s\n", operation);
      fclose (logFile);
    }
  return 0;
}

// Log the analyzer and its behaviour
int
writeLogFileAnalyzer (char *metric, int code, char *operation, double value,
		      char *parameter)
{
  char *date;
  time_t data = time (NULL);	//data salvata in data
  struct tm *tempo = localtime (&data);
  date = asctime (tempo);
  FILE *logFile;
  if (code == STATUS_OK && value == -1 && parameter == NULL)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Info] Date: %s", date);
      fprintf (logFile, "[Info] Operation: %s\n", operation);
      fclose (logFile);
    }
  if (code == STATUS_OK && value != -1 && parameter == NULL)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Info] %s : %f\n", operation, value);
      fclose (logFile);
    }
  if (code == INFO && value != -1 && parameter == NULL)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Info] %s : %d\n", operation, (int) value);
      fclose (logFile);
    }
  if (code == INFO && value == -1 && parameter != NULL)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Info] %s : %s\n", operation, parameter);
      fclose (logFile);
    }
  if (code != STATUS_OK && value == -1 && parameter == NULL)
    {
      logFile = fopen (metric, "a");
      fprintf (logFile, "[Error] Error: %s\n", operation);
      fclose (logFile);
    }
  return 0;
}

// Form a filename to name the file associated with the analyzer logging and metrics logging
char *
setFileName (char *metric, char *dirlog)
{
  char filename[FILENAME_MAX];

  struct timeval curTime;
  gettimeofday (&curTime, NULL);
  int milli = curTime.tv_usec / 1000;
  time_t now;
  struct tm *today;
  char date[30];
  //get current date  
  time (&now);
  today = localtime (&now);

  strftime (date, 20, "%d%m%Y%H%M%S", today);
  if (dirlog == NULL)
    sprintf (filename, "%s%s_%s%d.log", LOGDIR, metric, date, milli);
  else
    sprintf (filename, "%s/%s_%s%d.log", dirlog, metric, date, milli);
  return filename;
}

// Form a filename to name the file associated with the analyzer logging and metrics logging
char *
setFileNameResults (char *metric)
{
  char filename[FILENAME_MAX];

  struct timeval curTime;
  gettimeofday (&curTime, NULL);
  int milli = curTime.tv_usec / 1000;
  time_t now;
  struct tm *today;
  char date[30];
  //get current date  
  time (&now);
  today = localtime (&now);

  strftime (date, 20, "%d%m%Y%H%M%S", today);
  sprintf (filename, "%s%s_%s%d.csv", RESDIR, metric, date, milli);
  return filename;
}

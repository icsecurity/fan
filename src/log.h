#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>

// Possible Error or status
#define STATUS_OK	 (0)
#define INFO	 (1)
#define ALARM	 (2)
#define BUCKET	 (3)
#define ERR_OPEN_FILE	(-2)
#define MEMORY_ERROR	(-3)
#define GENERIC_ERROR	(-4)
#define ERR_OPEN_SO	(-5)
#define ERR_INTEGRITY_DEP (-6)
#define INCORRECT_XML (-7)

// Define the name of different metrics to form the name of the logging files
#define LOGDIR "../log/"
#define RESDIR "../results/"
#define SIZELOGDIR 8
#define ANALYZER "Analyzer"
#define ENTROPY "Entropy"
#define ENTROPYDEP "Entropydep"
#define KULLBACKLOGNAME "Kullback"
#define KULLBACKLOGNAMEDEP "Kullbackdep"
#define RENYILOGNAME "Renyi"
#define RENYILOGNAMEDEP "Renyidep"
#define SYNFLOODINGLOGNAME "Synflooding"
#define STOCKLOGNAME "Stockmarket"
#define FLOODINGINVESTIGATION "Floodinginvestigation"
#define STATEST "Ddosstatistical"
#define KMEANS "Kmeansanomalydetec"
#define FREQUENCYMOD "Frequencymod"
#define CONTA "Contabytes"
#define CONTAF "Contaflows"
#define LOSTFLOWS "Lostflows"
#define KMEANSNORMAL "Kmeansnormal"
#define MUL "Moltklsrcentsrc"

// Log the metrics results and behaviour
// Metric --> filename
// code --> Code for logging
// operation --> string that describe the operation
// value to write (if present)
int writeLogFile (char* metric,int code, char* operation,double value);

// Log the analyzer and its behaviour
// Metric --> filename
// code --> Code for logging
// operation --> string that describe the operation
// value to write (if present)
// parameter to write (if present)
int writeLogFileAnalyzer (char* metric,int code, char* operation,double value,char* parameter);
char* setFileName(char* metric, char* dirlog);
char* setFileNameResults (char *metric);

Fan - FAst Netﬂow analyser
=== 

Fan FAst Netﬂow analyser (Version 0.1)

please refer to "A. Cosentino, A. Spognardi, A. Villani, D. Vitali and 
L.V. Mancini, FAN: FAst Netﬂow analyser, 32st Annual IEEE International 
Conference on Computer Communications (IEEE INFOCOM 2013), Turin, Italy" 
for more details.


Install
===

./configure

make 

make install

Modules
===

Fan includes a lot of modules:

* bytes count 
* Ddos Statistical test
* Flooding investigation implementation
* Frequency 
* Shannon' Entropy
* Renyi
* Kullback Leibler
* Kmeans for anomaly detection
* Stock market implementation 
* Syn flooding 

Command line Parameter
===

* -h          get Help
* -M <input>	read from files or subdirectories of this directory.
* -r <input>	read from file.
* -R <input>	read from directory.
* -c <input>	number of flows to analyze.
* -m <input>	metric to compute
* -t <input>	timeslot to analyze
* -T <input>	active timeout of the router
* -x <input>	Config xml file
* -d <input>	log directory different from standard
* -e <input>	Execution Type: File or network
* -I <input>	Time interval between rotation of NetFlow file obtained by listening network
* -D <input>	Store directory of NetFlow file obtained by listening network
* -A <input>	Daemonize the collector
* -b host		bind socket to host/IP addr
* -p portnum	listen on port portnum
* -H <input>	Max number of threads for the analysis

Modules Configuration 
===

Fan can be easily configured using XML file. Below, an example about the configuration of
modules, and dependencies between modules.

    <Analysis>
        <Stats>

            <measure_lib>
            	<name>Entropy_modded.so</name>
        	    <measure_depend>
            	    <name>Frequency_mod.so</name>
        	    </measure_depend>
            </measure_lib>

            <measure_lib>
                <name>Kl_modded.so</name>
        	    <measure_depend>
		            <name>Frequency_mod.so</name>
        	    </measure_depend>
            </measure_lib>

            <measure_lib>
                <name>Renyi_modded.so</name>
	            <measure_depend>
		            <name>Frequency_mod.so</name>
	            </measure_depend>
            </measure_lib>

            <measure_lib>
	            <name>Frequency_mod.so</name>
            </measure_lib>

    </Stats>
    </Analysys>

In the example, Frequency_mod.so has no dependencies. In the XML declaration:

* name is the name of the module 
* measure depend lists the name of the modules which this module depends on.

Plugin concepts 
===

The file MethodManager.c and MethodManager.h implement the plugins management. The code
are runned in a multithread environmnet. The order in which each module is executed depends
on the configuration file.
Please refer to config.xml for a valid example


Example
===

Analyze one file of CISCO Netflows using a timeslot of 60 seconds and timeout of 900 seconds
and evaluate the entropy modules only.

- ./analyzer -e 'File' -r ../../12/nfcapd.201211120000 -t 60 -T 900 -m 'entropy.so'

Analyze all the flows' file included in a folder and using a configuration file.

- ./analyzer -e 'File' -R ../../12 -t 60 -T 900 -x '../config.xml'

Analyze a range of files. Please refer to nfdump software for a detailed description of the 
input parameter.

- ./analyzer -e 'File' -R ../../12/nfcapd.201211120000:nfcapd.201211120015 -t 60 -T 900 -x '../config.xml'


Analyze all the flows in a folder and uses 20 threds

- ./analyzer -e 'File' -R ../../12 -t 60 -T 900 -x '../config.xml' -H 20

Limit the evaluation to 10000000 flows 

- ./analyzer -e 'File' -R ../../12 -t 60 -T 900 -c 1000000 -x '../config.xml'

Enable network mode (listef for incoming connection on port UDP/9995. Save the received flows in a file
nfcapd.data (rotate the files each 300 seconds)

- ./analyzer -e 'Network' -I 300 -D ../../prova


Modules structure
===


Each modules may implement 4 functions:

* Initialization function. It is called where the software start : double so_init (int numflows)

* This function is called with each set of flows (the number of flows depend on the input parameter)
    double so_process (nf_record_t * r_current, int current_flows, char *bucket_id)

* This function is called when the software ends: double so_close (void)

* This function set the log dirctory: double so_log (char *logdir)

* This funciont allows other modules to get information about the result of a module
    void ** so_getResult (void)


Modules Example
===

In the following, the cose of a simple module that counts the number of bytes of the flows.

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <inttypes.h>
    #include <math.h>
    #include <dlfcn.h>
    #include "frequency.h"
    #include "log.h"

    / Global variables
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
    // bytes global
    float num_bytes = 0.0;

    // Function prototypes
    // init operation
    double so_init (int numflows);
    // Process data
    double so_process (nf_record_t * r_current, int current_flows,
            char *bucket_id);
    
    double so_close (void);// Close operations: free resources
   
    double so_log (char *logdir); // Specified the log directory

    /* With this function other modules can access the results of 
    this one and use them in their computation*/
    void **so_getResult (void);

    // Initialize the data struct entropy_data and its field
    double init_all (int numflows);

    // Process data from ip source point of view
    int process (nf_record_t * r_current, int current_flows);

    // so_init initializes the field of the entropy_data data structure
    // numflows --> number of current timeslot flows
    double so_init (int numflows)
    {
        iterations++;
        if (iterations == 1)
        {
            strncpy (filename, setFileName (CONTA, spec_logdir), FILENAME_MAX);
            strncpy (resultname, setFileNameResults (CONTA), FILENAME_MAX);
            writeLogFile (filename, STATUS_OK, "Start computing Contabytes.so module", -1);
        }
        if (spec_logdir != NULL)
            free (spec_logdir);
        return STATUS_OK;
    }

    // Process Data
    // r_current --> current timeslot flows
    // current_flows --> number of current timeslot flows
    double so_process (nf_record_t * r_current, int current_flows, char *bucket_id)
    {
        writeLogFile (filename, BUCKET, bucket_id, -1);
        // Analyze data by different entropy base
        // IP source
        int z = 0;
        float bytes_tot = 0.0;
        for (z = 1; z <= current_flows; z++)
        {
            bytes_tot += (float) r_current[z].dOctets;
        }
        num_bytes = bytes_tot;
        FILE *fs;
        fs = fopen(resultname, "a");
        if(fs == NULL){
            printf("Couldn't open file\n");
            return ERR_OPEN_FILE;
        }

        if (iterations == 1)
        {
	        fprintf(fs, "Timeslot Bucket,Total bytes \n");
        }
        fprintf(fs, "%s,%.6f \n", bucket_id,bytes_tot);
        fclose(fs);
        return STATUS_OK;
    }

    // Close operations, Free resources
    double so_close (void)
    {
        return STATUS_OK;
    }

    // Change default log directory
    double so_log (char *logdir)
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

   /*  With this function other modules can access the results of this 
   one and use them in their computation */
    void ** so_getResult (void)
    {
        void **pt = NULL;
        pt = (void **) malloc (1 * sizeof (void *));
        pt[0] = malloc (sizeof (void *));
        *(float *) pt[0] = num_bytes;
        return pt;
    }

Please notice: in so_close() we do not free since we do not allocate any resources.

In order to read data from other modules, we can refer to this code:

	typedef void** (*get_result)(void);
	
	char* error;
	void* module;
	// Open the .so
	get_result so_getResult;
	module = dlopen("../lib/Contabytes.so", RTLD_LAZY);
	if (!module) 
	{
		fprintf(stderr, "Couldn't open %s : %s\n",
		"Contabytes.so",dlerror());
		return ERR_OPEN_SO;
	}
	/* Get symbol */
	dlerror();
	// Function so_init
	so_getResult= dlsym(module, "so_getResult");
	if ((error = dlerror())) 
	{
		fprintf(stderr, "Couldn't find so_init: %s\n", error);
		return ERR_OPEN_SO;
	}
	void** pro = NULL;
	pro = (*so_getResult)();
	printf("Bytes analizzati %f \n", *(float*)pro[0]);



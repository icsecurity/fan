// This module is for the dependecies management and for the launch of the module in iterative way or multithreading way

#include "MethodManager.h"

// gestione_metriche is a Method Manager. In this function we receive the current timeslot flows, the number of this flows
// and the metrics we have to compute. For every metric we make the computation.
int
gestione_metriche (nf_record_t * vett_curr, int curr_flows, char *met,
		   char *logdir, char *bucket_id)
{

  int num;
  int ret_func;
  // num represents the number of metrics
  num = num_metrics (met);
  if (num == MEMORY_ERROR)
    {
      return MEMORY_ERROR;
    }
  // We prepare arguments to pass to thread
  struct arg_thread arguments[num];
  char *pch;
  char *word;
  char *metric_set = malloc (MAX_METRICSET_LENGTH * sizeof (char));
  if (metric_set == NULL)
    {
      return MEMORY_ERROR;
    }
  strncpy (metric_set, met, MAX_METRICSET_LENGTH);
  pch = metric_set;
  // Allocate the vector of strings
  char **ret = malloc (num * sizeof (char *));
  if (ret == NULL)
    {
      return MEMORY_ERROR;
    }
  int i = 0;
  // For each metric we allocate MET_MAX_LENGTH (defined in MethodManager.h) char
  for (i = 0; i < num; i++)
    {
      ret[i] = malloc (MET_MAX_LENGTH * sizeof (char));
      if (ret[i] == NULL)
	{
	  return MEMORY_ERROR;
	}
    }
  i = 0;
  // Copy the shared libraries name in our vector
  while ((word = strtok (pch, " ")) != NULL)
    {
      strncpy (ret[i], LIBDIR, 8);
      strcat (ret[i], word);
      i++;
      pch = NULL;
    }
  // Start computing metric
  for (i = 0; i < num; i++)
    {
      // Using dlopen we access the functions of the metric module in the .so shared library
      init init_comp;
      process process_comp;
      close close_comp;
      char *error;
      void *module;
      // Open the .so
      module = dlopen (ret[i], RTLD_LAZY);
      if (!module)
	{
	  fprintf (stderr, "Couldn't open %s : %s\n", ret[i], dlerror ());
	  return ERR_OPEN_SO;
	}
      /* Get symbol */
      dlerror ();
      // Function so_init
      arguments[i].so_init = dlsym (module, "so_init");
      if ((error = dlerror ()))
	{
	  fprintf (stderr, "Couldn't find so_init: %s\n", error);
	  return ERR_OPEN_SO;
	}
      dlerror ();
      // Function so_process
      arguments[i].so_process = dlsym (module, "so_process");
      if ((error = dlerror ()))
	{
	  fprintf (stderr, "Couldn't find so_process: %s\n", error);
	  return ERR_OPEN_SO;
	}
      dlerror ();
      // Function so_close
      arguments[i].so_close = dlsym (module, "so_close");
      if ((error = dlerror ()))
	{
	  fprintf (stderr, "Couldn't find so_close: %s\n", error);
	  return ERR_OPEN_SO;
	}
      dlerror ();
      // Function so_log
      arguments[i].so_log = dlsym (module, "so_log");
      if ((error = dlerror ()))
	{
	  fprintf (stderr, "Couldn't find so_log: %s\n", error);
	  return ERR_OPEN_SO;
	}
      // Save the data to analyze in the arguments for thread
      // Current timeslot flows
      arguments[i].vett_curr = vett_curr;
      // Current timeslot flows number
      arguments[i].curr_flows = curr_flows;
      arguments[i].bucket_id = malloc (MET_MAX_LENGTH * sizeof (char));
      strcpy (arguments[i].bucket_id, bucket_id);
      if (logdir != NULL)
	{
	  arguments[i].logdirectory = malloc (MET_MAX_LENGTH * sizeof (char));
	  strcpy (arguments[i].logdirectory, logdir);
	}
      else
	arguments[i].logdirectory = NULL;
    }
  // For every metric we execute function in the .so
  for (i = 0; i < num; i++)
    {
      if (logdir != NULL)
	{
	  ret_func = (*arguments[i].so_log) ((char *) logdir);
	  if (ret_func != STATUS_OK)
	    {
	      return ret_func;
	    }
	}
      ret_func = (*arguments[i].so_init) ((int) arguments[i].curr_flows);
      if (ret_func != STATUS_OK)
	{
	  return ret_func;
	}
      ret_func =
	(*arguments[i].so_process) ((nf_record_t *) arguments[i].vett_curr,
				    (int) arguments[i].curr_flows,
				    (char *) arguments[i].bucket_id);
      if (ret_func != STATUS_OK)
	{
	  return ret_func;
	}
      ret_func = (*arguments[i].so_close) ();
      if (ret_func != STATUS_OK)
	{
	  return ret_func;
	}
    }
  free (metric_set);
  for (i = 0; i < num; i++)
    free (ret[i]);
  free (ret);
  return STATUS_OK;
}

// In this function we receive the current timeslot flows, the number of this flows
// and the metrics we have to compute. For every metric we make the computation. In this case we read the metrics to compute in a xml file
int
gestione_metriche_xml (nf_record_t * vett_curr, int curr_flows,
		       struct metric_struct *metric_list, char *logdir,
		       char *bucket_id, char *xml_path, int max_thread)
{
  if (xml_path != NULL && max_thread != 0)
    {
      // If max_thread != 0 then we have to use multithreading and pass to other function
      gestione_metriche_multith (vett_curr, curr_flows, metric_list, logdir,
				 bucket_id, xml_path, max_thread);
    }
  else
    {
      // we copy the information of metric_list and a copy structure
      int ret_func;
      struct metric_struct *copy = NULL;
      struct metric_struct *met_pro, *tmp2;
      HASH_ITER (hh, metric_list, met_pro, tmp2)
      {
	struct metric_struct *curr;
	curr =
	  (struct metric_struct *) malloc (sizeof (struct metric_struct));
	if (curr == NULL)
	  {
	    return MEMORY_ERROR;
	  }
	memset (curr, 0, sizeof (struct metric_struct));
	strncpy (curr->metric, met_pro->metric, MET_MAX_LENGTH);
	curr->dep_elements = met_pro->dep_elements;
	curr->dep = malloc (curr->dep_elements * sizeof (char *));
	if (curr->dep == NULL)
	  {
	    return MEMORY_ERROR;
	  }
	int i = 0;
	for (i = 0; i < curr->dep_elements; i++)
	  {
	    curr->dep[i] = malloc (MET_MAX_LENGTH * sizeof (char));
	    if (curr->dep[i] == NULL)
	      {
		return MEMORY_ERROR;
	      }
	    strncpy (curr->dep[i], met_pro->dep[i], MET_MAX_LENGTH);
	  }
	HASH_ADD_STR (copy, metric, curr);
      }
      HASH_SORT (copy, dependencies_sort);
      ret_func = check_one_nodep (metric_list);
      if (ret_func == 1)
	{
	  return ERR_INTEGRITY_DEP;
	}
      // num represents the number of metrics
      int num;
      num = HASH_COUNT (copy);
      // We prepare arguments to pass to thread
      struct arg_thread arguments[num];
      // Allocate the vector of strings
      char **ret = malloc (num * sizeof (char *));
      if (ret == NULL)
	{
	  return MEMORY_ERROR;
	}
      int i = 0;
      // For each metric we allocate MET_MAX_LENGTH (defined in MethodManager.h) char
      for (i = 0; i < num; i++)
	{
	  ret[i] = malloc (MET_MAX_LENGTH * sizeof (char));
	  if (ret[i] == NULL)
	    {
	      return MEMORY_ERROR;
	    }
	}
      i = 0;
      // Copy the shared libraries name in our vector
      HASH_ITER (hh, copy, met_pro, tmp2)
      {
	strncpy (ret[i], LIBDIR, 8);
	strcat (ret[i], met_pro->metric);
	i++;
      }
      // Start computing metric
      for (i = 0; i < num; i++)
	{
	  // Using dlopen we access the functions of the metric module in the .so shared library
	  init init_comp;
	  process process_comp;
	  close close_comp;
	  char *error;
	  void *module;
	  // Open the .so
	  module = dlopen (ret[i], RTLD_LAZY);
	  if (!module)
	    {
	      fprintf (stderr, "Couldn't open %s : %s\n", ret[i], dlerror ());
	      return ERR_OPEN_SO;
	    }
	  /* Get symbol */
	  dlerror ();
	  // Function so_init
	  arguments[i].so_init = dlsym (module, "so_init");
	  if ((error = dlerror ()))
	    {
	      fprintf (stderr, "Couldn't find so_init: %s\n", error);
	      return ERR_OPEN_SO;
	    }
	  dlerror ();
	  // Function so_process
	  arguments[i].so_process = dlsym (module, "so_process");
	  if ((error = dlerror ()))
	    {
	      fprintf (stderr, "Couldn't find so_process: %s\n", error);
	      return ERR_OPEN_SO;
	    }
	  dlerror ();
	  // Function so_close
	  arguments[i].so_close = dlsym (module, "so_close");
	  if ((error = dlerror ()))
	    {
	      fprintf (stderr, "Couldn't find so_close: %s\n", error);
	      return ERR_OPEN_SO;
	    }
	  dlerror ();
	  // Function so_log
	  arguments[i].so_log = dlsym (module, "so_log");
	  if ((error = dlerror ()))
	    {
	      fprintf (stderr, "Couldn't find so_log: %s\n", error);
	      return ERR_OPEN_SO;
	    }
	  // Save the data to analyze in the arguments for thread
	  // Current timeslot flows
	  arguments[i].vett_curr = vett_curr;
	  // Current timeslot flows number
	  arguments[i].curr_flows = curr_flows;
	  arguments[i].bucket_id = malloc (MET_MAX_LENGTH * sizeof (char));
	  strcpy (arguments[i].bucket_id, bucket_id);
	  if (logdir != NULL)
	    {
	      arguments[i].logdirectory =
		malloc (MET_MAX_LENGTH * sizeof (char));
	      strcpy (arguments[i].logdirectory, logdir);
	    }
	  else
	    arguments[i].logdirectory = NULL;
	}
      // For every metric we execute function in the .so
      for (i = 0; i < num; i++)
	{
	  if (logdir != NULL)
	    {
	      ret_func = (*arguments[i].so_log) ((char *) logdir);
	      if (ret_func != STATUS_OK)
		{
		  return ret_func;
		}
	    }
	  ret_func = (*arguments[i].so_init) ((int) arguments[i].curr_flows);
	  if (ret_func != STATUS_OK)
	    {
	      return ret_func;
	    }
	  ret_func =
	    (*arguments[i].so_process) ((nf_record_t *) arguments[i].
					vett_curr,
					(int) arguments[i].curr_flows,
					(char *) arguments[i].bucket_id);
	  if (ret_func != STATUS_OK)
	    {
	      return ret_func;
	    }
	  ret_func = (*arguments[i].so_close) ();
	  if (ret_func != STATUS_OK)
	    {
	      return ret_func;
	    }
	}
      for (i = 0; i < num; i++)
	free (ret[i]);
      free (ret);
      HASH_ITER (hh, copy, met_pro, tmp2)
      {
	HASH_DEL (copy, met_pro);
	free (met_pro);
      }
      return STATUS_OK;
    }
}

// In this function we receive the current timeslot flows, the number of this flows
// and the metrics we have to compute. For every metric we make the computation in multithreading way
int
gestione_metriche_multith (nf_record_t * vett_curr, int curr_flows,
			   struct metric_struct *metric_list, char *logdir,
			   char *bucket_id, char *xml_path, int max_thread)
{
  // Copy the information in metric_list in a copy structure
  int ret_func;
  struct metric_struct *copy = NULL;
  struct metric_struct *met_pro, *tmp2;
  HASH_ITER (hh, metric_list, met_pro, tmp2)
  {
    struct metric_struct *curr;
    curr = (struct metric_struct *) malloc (sizeof (struct metric_struct));
    if (curr == NULL)
      {
	return MEMORY_ERROR;
      }
    memset (curr, 0, sizeof (struct metric_struct));
    strncpy (curr->metric, met_pro->metric, MET_MAX_LENGTH);
    curr->dep_elements = met_pro->dep_elements;
    curr->dep = malloc (curr->dep_elements * sizeof (char *));
    if (curr->dep == NULL)
      {
	return MEMORY_ERROR;
      }
    int i = 0;
    for (i = 0; i < curr->dep_elements; i++)
      {
	curr->dep[i] = malloc (MET_MAX_LENGTH * sizeof (char));
	if (curr->dep[i] == NULL)
	  {
	    return MEMORY_ERROR;
	  }
	strncpy (curr->dep[i], met_pro->dep[i], MET_MAX_LENGTH);
      }
    HASH_ADD_STR (copy, metric, curr);
  }
  HASH_SORT (copy, dependencies_sort);
  ret_func = check_one_nodep (metric_list);
  if (ret_func == 1)
    {
      return ERR_INTEGRITY_DEP;
    }
  // num represents the number of metrics
  int num;
  num = HASH_COUNT (copy);
  // We prepare num thread
  pthread_t thread_vett[num];
  // We prepare arguments to pass to thread
  struct arg_thread arguments[num];
  // Active Thread counter
  int act_thread = 0;
  // Allocate the vector of strings
  char **ret = malloc (num * sizeof (char *));
  if (ret == NULL)
    {
      return MEMORY_ERROR;
    }
  int i = 0;
  // For each metric we allocate MET_MAX_LENGTH (defined in MethodManager.h) char
  for (i = 0; i < num; i++)
    {
      ret[i] = malloc (MET_MAX_LENGTH * sizeof (char));
      if (ret[i] == NULL)
	{
	  return MEMORY_ERROR;
	}
    }
  i = 0;
  // Copy the shared libraries name in our vector
  HASH_ITER (hh, copy, met_pro, tmp2)
  {
    strncpy (ret[i], LIBDIR, 8);
    strcat (ret[i], met_pro->metric);
    i++;
  }
  // Start computing metric
  for (i = 0; i < num; i++)
    {
      // Using dlopen we access the functions of the metric module in the .so shared library
      init init_comp;
      process process_comp;
      close close_comp;
      char *error;
      void *module;
      // Open the .so
      module = dlopen (ret[i], RTLD_LAZY);
      if (!module)
	{
	  fprintf (stderr, "Couldn't open %s : %s\n", ret[i], dlerror ());
	  return ERR_OPEN_SO;
	}
      /* Get symbol */
      dlerror ();
      // Function so_init
      arguments[i].so_init = dlsym (module, "so_init");
      if ((error = dlerror ()))
	{
	  fprintf (stderr, "Couldn't find so_init: %s\n", error);
	  return ERR_OPEN_SO;
	}
      dlerror ();
      // Function so_process
      arguments[i].so_process = dlsym (module, "so_process");
      if ((error = dlerror ()))
	{
	  fprintf (stderr, "Couldn't find so_process: %s\n", error);
	  return ERR_OPEN_SO;
	}
      dlerror ();
      // Function so_close
      arguments[i].so_close = dlsym (module, "so_close");
      if ((error = dlerror ()))
	{
	  fprintf (stderr, "Couldn't find so_close: %s\n", error);
	  return ERR_OPEN_SO;
	}
      dlerror ();
      // Function so_log
      arguments[i].so_log = dlsym (module, "so_log");
      if ((error = dlerror ()))
	{
	  fprintf (stderr, "Couldn't find so_log: %s\n", error);
	  return ERR_OPEN_SO;
	}
      // Save the data to analyze in the arguments for thread
      // Current timeslot flows
      arguments[i].vett_curr = vett_curr;
      // Current timeslot flows number
      arguments[i].curr_flows = curr_flows;
      arguments[i].bucket_id = malloc (MET_MAX_LENGTH * sizeof (char));
      strcpy (arguments[i].bucket_id, bucket_id);
      if (logdir != NULL)
	{
	  arguments[i].logdirectory = malloc (MET_MAX_LENGTH * sizeof (char));
	  strcpy (arguments[i].logdirectory, logdir);
	}
      else
	arguments[i].logdirectory = NULL;
    }
  i = 0;
  // Pass the metric_list structure
  HASH_ITER (hh, copy, met_pro, tmp2)
  {
    strncpy (arguments[i].metric, LIBDIR, 8);
    strcat (arguments[i].metric, met_pro->metric);
    arguments[i].dep_elements = met_pro->dep_elements;
    arguments[i].dep = malloc (arguments[i].dep_elements * sizeof (char *));
    if (arguments[i].dep == NULL)
      {
	return MEMORY_ERROR;
      }
    int f = 0;
    for (f = 0; f < arguments[i].dep_elements; f++)
      {
	arguments[i].dep[f] = malloc (MET_MAX_LENGTH * sizeof (char));
	if (arguments[i].dep[f] == NULL)
	  {
	    return MEMORY_ERROR;
	  }
	strncpy (arguments[i].dep[f], LIBDIR, 8);
	strcat (arguments[i].dep[f], met_pro->dep[f]);
      }
    // If the module hasn't dependecies we can start it. So can_start = 1.
    if (arguments[i].dep_elements == 0)
      arguments[i].can_start = 1;
    else
      arguments[i].can_start = 0;
    arguments[i].ended = 0;
    i++;
  }
  // For every metric we execute function in the .so
  // Until every module ends we made this loop
  while (end_all (arguments, num) != 0)
    {
      // Start the modules with can_start = 1
      for (i = 0; i < num; i++)
	{
	  if (arguments[i].can_start == 1 && arguments[i].ended == 0)
	    {
	      printf ("[Thread] Start Thread associated to %s \n",
		      arguments[i].metric);
	      pthread_create (&thread_vett[i], NULL, thread_launcher,
			      (void *) &arguments[i]);
	    }
	}
      // Wait for their end
      for (i = 0; i < num; i++)
	{
	  if (arguments[i].can_start == 1 && arguments[i].ended != 1)
	    {
	      pthread_join (thread_vett[i], NULL);
	      printf ("[Thread] Thread associated to %s finished\n",
		      arguments[i].metric);
	      arguments[i].ended = 1;
	    }
	}
      // Update information and verify if the module with dependencies can start their execution
      int re = 0;
      int num_mod_dep = 0;
      int j = 0;
      int f = 0;
      for (j = 0; j < num; j++)
	{
	  for (f = 0; f < arguments[j].dep_elements; f++)
	    {
	      num_mod_dep = arguments[j].dep_elements;
	      for (i = 0; i < num; i++)
		{
		  if (strcmp (arguments[j].dep[f], arguments[i].metric) == 0)
		    {
		      if (arguments[i].ended == 1)
			{
			  re++;
			}
		    }
		}
	    }
	  if (re == num_mod_dep)
	    {
	      arguments[j].can_start = 1;
	      re = 0;
	    }
	}
    }
  for (i = 0; i < num; i++)
    free (ret[i]);
  free (ret);
  HASH_ITER (hh, copy, met_pro, tmp2)
  {
    HASH_DEL (copy, met_pro);
    free (met_pro);
  }
  return STATUS_OK;
}

// Verify if there is a module with no dependencies
int
check_one_nodep (struct metric_struct *metric_list)
{
  struct metric_struct *met_pro, *tmp2;
  int dependencies = 0;
  HASH_ITER (hh, metric_list, met_pro, tmp2)
  {
    if (met_pro->dep_elements == 0)
      return 0;
  }
  return 1;
}

// Sort the modules by dependencies in the hash table
int
dependencies_sort (struct metric_struct *a, struct metric_struct *b)
{
  if (a->dep_elements == 0 && b->dep_elements == 0)
    return 0;
  if (a->dep_elements == 0 && b->dep_elements != 0)
    return -1;
  if (b->dep_elements == 0 && a->dep_elements != 0)
    return 1;
  else
    {
      int i = 0;
      for (i = 0; i < a->dep_elements; i++)
	{
	  if (strcmp (a->dep[i], b->metric) == 0)
	    return 1;
	}
      i = 0;
      for (i = 0; i < b->dep_elements; i++)
	{
	  if (strcmp (b->dep[i], a->metric) == 0)
	    return -1;
	}
    }

}

// Thread for each metric. 
// arguments is a struct with input for the metric:
// current flows
// number of current flows
// function pointer to function of the .so shared library associated with the metric
void *
thread_launcher (void *arguments)
{
  if (((struct arg_thread *) arguments)->logdirectory != NULL)
    {
      (*((struct arg_thread *) arguments)->so_log) ((char
						     *) ((struct arg_thread *)
							 arguments)->logdirectory);
    }
  (*((struct arg_thread *) arguments)->so_init) ((int)
						 ((struct arg_thread *)
						  arguments)->curr_flows);
  (*((struct arg_thread *) arguments)->so_process) ((nf_record_t
						     *) ((struct arg_thread *)
							 arguments)->vett_curr,
						    (int) ((struct arg_thread
							    *)
							   arguments)->curr_flows,
						    (char
						     *) ((struct arg_thread *)
							 arguments)->bucket_id);
  (*((struct arg_thread *) arguments)->so_close) ();
  return;
}

// Verify if every module finished his computation
int
end_all (struct arg_thread arguments[], int num)
{
  int ret = 0;
  int i = 0;
  for (i = 0; i < num; i++)
    {
      if (arguments[i].ended == 0)
	ret = 1;
    }
  return ret;
}

// This function count the number of metric in the metric set. Similar to ret_metrics
int
num_metrics (char *metric_set)
{
  char *pch;
  char *word;
  char *metric = malloc (MAX_METRICSET_LENGTH * sizeof (char));
  if (metric == NULL)
    {
      return MEMORY_ERROR;
    }
  strncpy (metric, metric_set, MAX_METRICSET_LENGTH);
  pch = metric;
  int i = 0;
  while ((word = strtok (pch, " ")) != NULL)
    {
      i++;
      pch = NULL;
    }
  free (metric);
  return i;
}

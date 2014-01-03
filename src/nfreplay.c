/*
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: haag $
 *
 *  $Id: nfreplay.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <dirent.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "nf_common.h"
#include "rbtree.h"
#include "nftree.h"
#include "nfdump.h"
#include "nfnet.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"
#include "nfprof.h"
#include "flist.h"
#include "util.h"
#include "grammar.h"
#include "panonymizer.h"
#include "nfstatfile.h"
#include "rijndael.h"
#include "frequency.h"
#include "log.h"
#include "uthash.h"
#include "bucketization.h"
#include "randomization.h"
#include "ezxml.h"
#include "ipfix.h"

#define DEFAULTCISCOPORT "9995"
#define DEFAULTHOSTNAME "127.0.0.1"
#define SENDSOCK_BUFFSIZE (200000)

#undef	FPURGE
#ifdef	HAVE___FPURGE
#define	FPURGE	__fpurge
#endif
#ifdef	HAVE_FPURGE
#define	FPURGE	fpurge
#endif

//#define IP_STRING_LEN   40
#define STRINGSIZE     (20000)
#define IP_STRING_LEN (INET6_ADDRSTRLEN)
#define BLOCK_SIZE   	(32)
#define MAX_FLOWS_BLOCK (2000000)
#define MAXPATHLEN (20000)

/* Externals */
extern int yydebug;
extern uint32_t default_sampling;	// the default sampling rate when nothing else applies. set by -S
extern uint32_t overwrite_sampling;	// unconditionally overwrite sampling rate with given sampling rate -S

/* Global Variables */
FilterEngine_data_t *Engine;
int verbose;
caddr_t shmem;
int iter = 0;
char last_date_seen[64];

extension_map_list_t extension_map_list;

char filename[FILENAME_MAX];

// Define a generic type to get data from socket or pcap file
typedef ssize_t (*packet_function_t) (int, void *, size_t, int,
				      struct sockaddr *, socklen_t *);

/* module limited globals */
static FlowSource_t *FlowSource;

static int done, launcher_alive, periodic_trigger, launcher_pid;

static const char *nfdump_version = VERSION;

int send_data (char *rfile, time_t twin_start,
	       time_t twin_end, uint32_t count, unsigned int delay,
	       int confirm, int netflow_version, float timeslot, char *met,
	       struct metric_struct *metric_list, char *dirlog,
	       int active_timeout, char *xml_path, int max_thread);

int generate_data (char *gen_xml, char *met,
		   struct metric_struct *metric_list, char *dirlog,
		   char *xml_path, int max_thread);

void
record_conversion (void *record, nf_record_t * output_r, int anon, int tag);

static void String_Flags (master_record_t * r, char *string);

int compare_date (char *date_start, char *date_end, int timeslot);

static void kill_launcher (int pid);

static void IntHandler (int signal);

static inline FlowSource_t *GetFlowSource (struct sockaddr_storage *ss);

static void daemonize (void);

static void run (packet_function_t receive_packet, int socket,
		 send_peer_t peer, time_t twin, time_t t_begin,
		 int report_seq, int use_subdirs, int compress, int do_xstat);

struct data_block **manipulate_data (char *gen_xml);

int count_block (char *gen_xml);

/* Functions */

#include "nffile_inline.c"
#include "nfdump_inline.c"
#include "collector_inline.c"

// -------------------------------Nfcapd functions to collect flows and save in nfcapd.date file-----------------------------------

void
kill_launcher (int pid)
{
  int stat, i;
  pid_t ret;

  if (pid == 0)
    return;

  if (launcher_alive)
    {
      syslog (LOG_INFO, "Signal launcher[%i] to terminate.", pid);
      kill (pid, SIGTERM);

      // wait for launcher to teminate
      for (i = 0; i < LAUNCHER_TIMEOUT; i++)
	{
	  if (!launcher_alive)
	    break;
	  sleep (1);
	}
      if (i >= LAUNCHER_TIMEOUT)
	{
	  syslog (LOG_WARNING,
		  "Laucher does not want to terminate - signal again");
	  kill (pid, SIGTERM);
	  sleep (1);
	}
    }
  else
    {
      syslog (LOG_ERR, "launcher[%i] already dead.", pid);
    }

  if ((ret = waitpid (pid, &stat, 0)) == -1)
    {
      syslog (LOG_ERR, "wait for launcher failed: %s %i", strerror (errno),
	      ret);
    }
  else
    {
      if (WIFEXITED (stat))
	{
	  syslog (LOG_INFO, "launcher exit status: %i", WEXITSTATUS (stat));
	}
      if (WIFSIGNALED (stat))
	{
	  syslog (LOG_WARNING, "launcher terminated due to signal %i",
		  WTERMSIG (stat));
	}
    }

}				// End of kill_launcher

// Interrupt handler to stop the collector
static void
IntHandler (int signal)
{

  switch (signal)
    {
    case SIGALRM:
      periodic_trigger = 1;
      break;
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
      done = 1;
      break;
    case SIGCHLD:
      launcher_alive = 0;
      break;
    default:
      // ignore everything we don't know
      break;
    }

}				/* End of IntHandler */

// Daemonize the collector and make other tasks
static void
daemonize (void)
{
  int fd;
  switch (fork ())
    {
    case 0:
      // child
      break;
    case -1:
      // error
      fprintf (stderr, "fork() error: %s\n", strerror (errno));
      exit (0);
      break;
    default:
      // parent
      _exit (0);
    }

  if (setsid () < 0)
    {
      fprintf (stderr, "setsid() error: %s\n", strerror (errno));
      exit (0);
    }

  // Double fork
  switch (fork ())
    {
    case 0:
      // child
      break;
    case -1:
      // error
      fprintf (stderr, "fork() error: %s\n", strerror (errno));
      exit (0);
      break;
    default:
      // parent
      _exit (0);
    }

  fd = open ("/dev/null", O_RDONLY);
  if (fd != 0)
    {
      dup2 (fd, 0);
      close (fd);
    }
  fd = open ("/dev/null", O_WRONLY);
  if (fd != 1)
    {
      dup2 (fd, 1);
      close (fd);
    }
  fd = open ("/dev/null", O_WRONLY);
  if (fd != 2)
    {
      dup2 (fd, 2);
      close (fd);
    }

}				// End of daemonize

// Function to really collect the flows in file
static void
run (packet_function_t receive_packet, int socket, send_peer_t peer,
     time_t twin, time_t t_begin, int report_seq, int use_subdirs,
     int compress, int do_xstat)
{
  common_flow_header_t *nf_header;
  FlowSource_t *fs;
  struct sockaddr_storage nf_sender;
  socklen_t nf_sender_size = sizeof (nf_sender);
  time_t t_start, t_now;
  uint64_t export_packets;
  uint32_t blast_cnt, blast_failures, ignored_packets;
  uint16_t version;
  ssize_t cnt;
  void *in_buff;
  int err;
  char *string;
  srecord_t *commbuff;
  time_t t_start_saved;
  time_t t_confront_saved;

  if (!Init_v1 () || !Init_v5_v7_input () || !Init_v9 () || !Init_IPFIX ())
    return;

  in_buff = malloc (NETWORK_INPUT_BUFF_SIZE);
  if (!in_buff)
    {
      LogError ("malloc() allocation error in %s line %d: %s\n", __FILE__,
		__LINE__, strerror (errno));
      return;
    }

  // init vars
  commbuff = (srecord_t *) shmem;
  nf_header = (common_flow_header_t *) in_buff;

  // Init each netflow source output data buffer
  fs = FlowSource;
  while (fs)
    {

      // prepare file
      fs->nffile = OpenNewFile (fs->current, NULL, compress, 0, NULL);
      if (!fs->nffile)
	{
	  return;
	}
      if (do_xstat)
	{
	  fs->xstat = InitXStat (fs->nffile);
	  if (!fs->xstat)
	    return;
	}
      // init vars
      fs->bad_packets = 0;
      fs->first_seen = 0xffffffffffffLL;
      fs->last_seen = 0;

      // next source
      fs = fs->next;
    }

  export_packets = blast_cnt = blast_failures = 0;
  t_start = t_begin;
  t_start_saved = t_begin;

  cnt = 0;
  periodic_trigger = 0;
  ignored_packets = 0;

  // wake up at least at next time slot (twin) + some Overdue time
  alarm (t_start + twin + OVERDUE_TIME - time (NULL));
  /*
   * Main processing loop:
   * this loop, continues until done = 1, set by the signal handler
   * The while loop will be breaked by the periodic file renaming code
   * for proper cleanup 
   */
  t_confront_saved = time (NULL);
  while (1)
    {

      /* read next bunch of data into beginn of input buffer */
      if (!done)
	{

#ifdef PCAP
	  // Debug code to read from pcap file, or from socket 
	  cnt = receive_packet (socket, in_buff, NETWORK_INPUT_BUFF_SIZE, 0,
				(struct sockaddr *) &nf_sender,
				&nf_sender_size);

	  // in case of reading from file EOF => -2
	  if (cnt == -2)
	    done = 1;
#else
	  cnt = recvfrom (socket, in_buff, NETWORK_INPUT_BUFF_SIZE, 0,
			  (struct sockaddr *) &nf_sender, &nf_sender_size);
#endif

	  if (cnt == -1 && errno != EINTR)
	    {
	      syslog (LOG_ERR, "ERROR: recvfrom: %s", strerror (errno));
	      continue;
	    }

	  if (peer.hostname)
	    {
	      size_t len;
	      len =
		sendto (peer.sockfd, in_buff, cnt, 0,
			(struct sockaddr *) &(peer.addr), peer.addrlen);
	      if (len < 0)
		{
		  syslog (LOG_ERR, "ERROR: sendto(): %s", strerror (errno));
		}
	    }
	}

      /* Periodic file renaming, if time limit reached or if we are done.  */
      t_now = time (NULL);
      if (((t_now - t_start) >= twin) || done)
	{
	  char subfilename[64];
	  struct tm *now;
	  char *subdir;

	  alarm (0);
	  now = localtime (&t_start);

	  // prepare sub dir hierarchy
	  if (use_subdirs)
	    {
	      subdir = GetSubDir (now);
	      if (!subdir)
		{
		  // failed to generate subdir path - put flows into base directory
		  syslog (LOG_ERR, "Failed to create subdir path!");

		  // failed to generate subdir path - put flows into base directory
		  subdir = NULL;
		  snprintf (subfilename, 63, "nfcapd.%i%02i%02i%02i%02i",
			    now->tm_year + 1900, now->tm_mon + 1,
			    now->tm_mday, now->tm_hour, now->tm_min);
		}
	      else
		{
		  snprintf (subfilename, 63, "%s/nfcapd.%i%02i%02i%02i%02i",
			    subdir, now->tm_year + 1900, now->tm_mon + 1,
			    now->tm_mday, now->tm_hour, now->tm_min);
		}
	    }
	  else
	    {
	      subdir = NULL;
	      snprintf (subfilename, 63, "nfcapd.%i%02i%02i%02i%02i",
			now->tm_year + 1900, now->tm_mon + 1, now->tm_mday,
			now->tm_hour, now->tm_min);
	    }
	  subfilename[63] = '\0';

	  // for each flow source update the stats, close the file and re-initialize the new file
	  fs = FlowSource;
	  while (fs)
	    {
	      char nfcapd_filename[MAXPATHLEN];
	      char error[255];
	      nffile_t *nffile = fs->nffile;

	      if (verbose)
		{
		  // Dump to stdout
		  format_file_block_header (nffile->block_header, &string, 0);
		  printf ("%s\n", string);
		}

	      if (nffile->block_header->NumRecords)
		{
		  // flush current buffer to disc
		  if (WriteBlock (nffile) <= 0)
		    syslog (LOG_ERR,
			    "Ident: %s, failed to write output buffer to disk: '%s'",
			    fs->Ident, strerror (errno));

		}		// else - no new records in current block


	      // prepare filename
	      snprintf (nfcapd_filename, MAXPATHLEN - 1, "%s/%s", fs->datadir,
			subfilename);
	      nfcapd_filename[MAXPATHLEN - 1] = '\0';

	      // update stat record
	      // if no flows were collected, fs->last_seen is still 0
	      // set first_seen to start of this time slot, with twin window size.
	      if (fs->last_seen == 0)
		{
		  fs->first_seen = (uint64_t) 1000 *(uint64_t) t_start;
		  fs->last_seen =
		    (uint64_t) 1000 *(uint64_t) (t_start + twin);
		}
	      nffile->stat_record->first_seen = fs->first_seen / 1000;
	      nffile->stat_record->msec_first =
		fs->first_seen - nffile->stat_record->first_seen * 1000;
	      nffile->stat_record->last_seen = fs->last_seen / 1000;
	      nffile->stat_record->msec_last =
		fs->last_seen - nffile->stat_record->last_seen * 1000;

	      if (fs->xstat)
		{
		  if (WriteExtraBlock (nffile, fs->xstat->block_header) <= 0)
		    syslog (LOG_ERR,
			    "Ident: %s, failed to write xstat buffer to disk: '%s'",
			    fs->Ident, strerror (errno));

		  ResetPortHistogram (fs->xstat->port_histogram);
		  ResetBppHistogram (fs->xstat->bpp_histogram);
		}

	      // Close file
	      CloseUpdateFile (nffile, fs->Ident);

	      if (subdir && !SetupSubDir (fs->datadir, subdir, error, 255))
		{
		  // in this case the flows get lost! - the rename will fail
		  // but this should not happen anyway, unless i/o problems, inode problems etc.
		  syslog (LOG_ERR,
			  "Ident: %s, Failed to create sub hier directories: %s",
			  fs->Ident, error);
		}

	      // if rename fails, we are in big trouble, as we need to get rid of the old .current file
	      // otherwise, we will loose flows and can not continue collecting new flows
	      err = rename (fs->current, nfcapd_filename);
	      if (err)
		{
		  syslog (LOG_ERR, "Ident: %s, Can't rename dump file: %s",
			  fs->Ident, strerror (errno));
		  syslog (LOG_ERR, "Ident: %s, Serious Problem! Fix manually",
			  fs->Ident);
		  if (launcher_pid)
		    commbuff->failed = 1;

		  // we do not update the books here, as the file failed to rename properly
		  // otherwise the books may be wrong
		}
	      else
		{
		  struct stat fstat;
		  if (launcher_pid)
		    commbuff->failed = 0;

		  // Update books
		  stat (nfcapd_filename, &fstat);
		  UpdateBooks (fs->bookkeeper, t_start,
			       512 * fstat.st_blocks);
		}

	      // log stats
	      syslog (LOG_INFO,
		      "Ident: '%s' Flows: %llu, Packets: %llu, Bytes: %llu, Sequence Errors: %u, Bad Packets: %u",
		      fs->Ident,
		      (unsigned long long) nffile->stat_record->numflows,
		      (unsigned long long) nffile->stat_record->numpackets,
		      (unsigned long long) nffile->stat_record->numbytes,
		      nffile->stat_record->sequence_failure, fs->bad_packets);

	      // reset stats
	      fs->bad_packets = 0;
	      fs->first_seen = 0xffffffffffffLL;
	      fs->last_seen = 0;

	      if (!done)
		{
		  nffile =
		    OpenNewFile (fs->current, nffile, compress, 0, NULL);
		  if (!nffile)
		    {
		      LogError ("killed due to fatal error: ident: %s",
				fs->Ident);
		      break;
		    }
		  /* XXX needs fixing */
		  if (fs->xstat)
		    {
		      SetFlag (nffile->file_header->flags,
			       FLAG_EXTENDED_STATS);
		    }
		}

	      // Dump all extension maps to the buffer
	      FlushExtensionMaps (fs);

	      // next flow source
	      fs = fs->next;
	    }			// end of while (fs)

	  // All flow sources updated - signal launcher if required
	  if (launcher_pid)
	    {
	      // Signal launcher

	      // prepare filename for %f expansion
	      strncpy (commbuff->fname, subfilename, FNAME_SIZE - 1);
	      commbuff->fname[FNAME_SIZE - 1] = 0;
	      snprintf (commbuff->tstring, 16, "%i%02i%02i%02i%02i",
			now->tm_year + 1900, now->tm_mon + 1, now->tm_mday,
			now->tm_hour, now->tm_min);
	      commbuff->tstring[15] = 0;
	      commbuff->tstamp = t_start;
	      if (subdir)
		strncpy (commbuff->subdir, subdir, FNAME_SIZE);
	      else
		commbuff->subdir[0] = '\0';

	      if (launcher_alive)
		{
		  syslog (LOG_DEBUG, "Signal launcher");
		  kill (launcher_pid, SIGHUP);
		}
	      else
		syslog (LOG_ERR, "ERROR: Launcher did unexpectedly!");

	    }

	  syslog (LOG_INFO, "Total ignored packets: %u", ignored_packets);
	  ignored_packets = 0;

	  if (done)
	    break;

	  // update alarm for next cycle
	  t_start += twin;
	  /* t_start = filename time stamp: begin of slot
	   * + twin = end of next time interval
	   * + OVERDUE_TIME = if no data is collected, this is at latest to act
	   * - t_now = difference value to now
	   */
	  alarm (t_start + twin + OVERDUE_TIME - t_now);

	}

      /* check for error condition or done . errno may only be EINTR */
      if (cnt < 0)
	{
	  if (periodic_trigger)
	    {
	      // alarm triggered, no new flow data 
	      periodic_trigger = 0;
	      continue;
	    }
	  if (done)
	    // signaled to terminate - exit from loop
	    break;
	  else
	    {
	      /* this should never be executed as it should be caught in other places */
	      syslog (LOG_ERR, "error condition in '%s', line '%d', cnt: %i",
		      __FILE__, __LINE__, (int) cnt);
	      continue;
	    }
	}

      /* enough data? */
      if (cnt == 0)
	continue;

      // get flow source record for current packet, identified by sender IP address
      fs = GetFlowSource (&nf_sender);
      if (fs == NULL)
	{
	  syslog (LOG_WARNING,
		  "Skip UDP packet. Ignored packets so far %u packets",
		  ignored_packets);
	  ignored_packets++;
	  continue;
	}

      /* check for too little data - cnt must be > 0 at this point */
      if (cnt < sizeof (common_flow_header_t))
	{
	  syslog (LOG_WARNING,
		  "Ident: %s, Data length error: too little data for common netflow header. cnt: %i",
		  fs->Ident, (int) cnt);
	  fs->bad_packets++;
	  continue;
	}

      /* Process data - have a look at the common header */
      version = ntohs (nf_header->version);
      switch (version)
	{
	case 1:
	  Process_v1 (in_buff, cnt, fs);
	  break;
	case 5:		// fall through
	case 7:
	  Process_v5_v7 (in_buff, cnt, fs);
	  break;
	case 9:
	  Process_v9 (in_buff, cnt, fs);
	  break;
	case 10:
	  Process_IPFIX (in_buff, cnt, fs);
	  break;
	case 255:
	  // blast test header
	  if (verbose)
	    {
	      uint16_t count = ntohs (nf_header->count);
	      if (blast_cnt != count)
		{
		  // LogError("Missmatch blast check: Expected %u got %u\n", blast_cnt, count);
		  blast_cnt = count;
		  blast_failures++;
		}
	      else
		{
		  blast_cnt++;
		}
	      if (blast_cnt == 65535)
		{
		  fprintf (stderr, "Total missed packets: %u\n",
			   blast_failures);
		  done = 1;
		}
	      break;
	    }
	default:
	  // data error, while reading data from socket
	  syslog (LOG_ERR,
		  "Ident: %s, Error reading netflow header: Unexpected netflow version %i",
		  fs->Ident, version);
	  fs->bad_packets++;
	  continue;

	  // not reached
	  break;
	}
      // each Process_xx function has to process the entire input buffer, therefore it's empty now.
      export_packets++;

      // flush current buffer to disc
      if (fs->nffile->block_header->size > BUFFSIZE)
	{
	  // fishy! - we already wrote into someone elses memory! - I'm sorry
	  // reset output buffer - data may be lost, as we don not know, where it happen
	  fs->nffile->block_header->size = 0;
	  fs->nffile->block_header->NumRecords = 0;
	  fs->nffile->buff_ptr =
	    (void *) ((pointer_addr_t) fs->nffile->block_header +
		      sizeof (data_block_header_t));
	  syslog (LOG_ERR,
		  "### Software bug ### Ident: %s, output buffer overflow: expect memory inconsitency",
		  fs->Ident);
	}
    }

  if (verbose && blast_failures)
    {
      fprintf (stderr, "Total missed packets: %u\n", blast_failures);
    }
  free (in_buff);

  fs = FlowSource;
  while (fs)
    {
      DisposeFile (fs->nffile);
      fs = fs->next;
    }
  return;

}				/* End of run */



// --------------------------------------- End nfcapd functions ---------------------------------------------------------------

// --------------------------------------- Start Generator Functions ---------------------------------------------------------------

int
generate_data (char *gen_xml, char *met,
	       struct metric_struct *metric_list, char *dirlog,
	       char *xml_path, int max_thread)
{
  int ret_func;
  struct bucket_struct *bucket_list = NULL;
  struct data_block **data;
  int num_block;
  data = manipulate_data (gen_xml);
  num_block = count_block (gen_xml);
  int r = 0;
  for (r = 0; r < num_block; r++)
    {
      struct bucket_struct *t;
      HASH_FIND_STR (bucket_list, data[r]->date, t);
      if (t == NULL)
	{
	  t = (struct bucket_struct *) malloc (sizeof (struct bucket_struct));
	  if (t == NULL)
	    {
	      printf
		("[Info] Problem in memory allocation in send data malloc \n");
	      writeLogFileAnalyzer (filename,
				    MEMORY_ERROR,
				    "Problem in memory allocation in send data",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  memset (t, 0, sizeof (struct bucket_struct));
	  strncpy (t->date, data[r]->date, 64);
	  t->elements = (data[r]->elements_num);
	  t->vett =
	    (nf_record_t *) malloc ((((t->elements) + 1) * sizeof (nf_record_t)));
	  if (t->vett == NULL)
	    {
	      printf
		("[Info] Problem in memory allocation in send data malloc \n");
	      writeLogFileAnalyzer (filename,
				    MEMORY_ERROR,
				    "Problem in memory allocation in send data",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  int i = 0;
	  srand(time(NULL));
	  if (strcmp(data[r]->mode,"build") == 0)
	  {
	  for (i = 1; i <= t->elements; i++)
	    {
	      t->vett[i].ip_union._v4_2.srcaddr = data[r]->source_ip;
	      t->vett[i].ip_union._v4_2.dstaddr = data[r]->destination_ip;
	      t->vett[i].dPkts = (uint64_t) random_in_range (data[r]->pkts_down,data[r]->pkts_up);
	      t->vett[i].dOctets = (uint64_t) random_in_range (data[r]->bytes_down,data[r]->bytes_up);
	      t->vett[i].tos = (uint8_t) random_in_range (data[r]->tos_down,data[r]->tos_up);
	      t->vett[i].srcport = data[r]->srcport;
	      t->vett[i].dstport = data[r]->dstport;
	      t->vett[i].prot = data[r]->prot;
	      strncpy(t->vett[i].src_addr_str,data[r]->src_addr_str,40);
	      strncpy(t->vett[i].dst_addr_str,data[r]->dst_addr_str,40);
	      strncpy(t->vett[i].tcp_flags_str,data[r]->flags_str,16);
	    }
	  }
	  else if (strcmp(data[r]->mode,"random") == 0)
	  {
	  for (i = 1; i <= t->elements; i++)
	    {
	      t->vett[i].ip_union._v4_2.srcaddr = (uint32_t) random_in_range (data[r]->source_ip_down,data[r]->source_ip_up);
	      t->vett[i].ip_union._v4_2.dstaddr = (uint32_t) random_in_range (data[r]->dst_ip_down,data[r]->dst_ip_up);
	      t->vett[i].dPkts = (uint64_t) random_in_range (data[r]->pkts_down,data[r]->pkts_up);
	      t->vett[i].dOctets = (uint64_t) random_in_range (data[r]->bytes_down,data[r]->bytes_up);
	      t->vett[i].tos = (uint8_t) random_in_range (data[r]->tos_down,data[r]->tos_up);
	      t->vett[i].srcport = (uint16_t) random_in_range (data[r]->srcport_down,data[r]->srcport_up);
	      t->vett[i].dstport = (uint16_t) random_in_range (data[r]->dstport_down,data[r]->dstport_up);
	      t->vett[i].prot = (uint8_t) random_in_range (data[r]->prot_down,data[r]->prot_up);
	      strncpy(t->vett[i].src_addr_str,data[r]->src_addr_str,40);
	      strncpy(t->vett[i].dst_addr_str,data[r]->dst_addr_str,40);
	      strncpy(t->vett[i].tcp_flags_str,data[r]->flags_str,16);
	    }
	  }
	  HASH_ADD_STR (bucket_list, date, t);
	}
      else
	{
	  int i = t->elements + 1;
	  t->elements += data[r]->elements_num;
	  t->vett =
	    (nf_record_t *) realloc (t->vett,
				     ((t->elements +
				       1) * sizeof (nf_record_t)));
	  if (t->vett == NULL)
	    {
	      printf
		("[Info] Problem in memory allocation in send data realloc \n");
	      writeLogFileAnalyzer (filename, MEMORY_ERROR,
				    "Problem in memory allocation in send data",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  srand(time(NULL));
	  if (strcmp(data[r]->mode,"build") == 0)
	  {
	  for (; i <= t->elements; i++)
	    {
	      t->vett[i].ip_union._v4_2.srcaddr = data[r]->source_ip;
	      t->vett[i].ip_union._v4_2.dstaddr = data[r]->destination_ip;
	      t->vett[i].dPkts = (uint64_t) random_in_range (data[r]->pkts_down,data[r]->pkts_up);
	      t->vett[i].dOctets = (uint64_t) random_in_range (data[r]->bytes_down,data[r]->bytes_up);
	      t->vett[i].tos = (uint8_t) random_in_range (data[r]->tos_down,data[r]->tos_up);
	      t->vett[i].srcport = data[r]->srcport;
	      t->vett[i].dstport = data[r]->dstport;
	      t->vett[i].prot = data[r]->prot;
	      strncpy(t->vett[i].src_addr_str,data[r]->src_addr_str,40);
	      strncpy(t->vett[i].dst_addr_str,data[r]->dst_addr_str,40);
	      strncpy(t->vett[i].tcp_flags_str,data[r]->flags_str,16);
	    }
	  }
	  else if (strcmp(data[r]->mode,"build") == 0)
	  {
	  for (; i <= t->elements; i++)
	    {
	      t->vett[i].ip_union._v4_2.srcaddr = (uint32_t) random_in_range (data[r]->source_ip_down,data[r]->source_ip_up);
	      t->vett[i].ip_union._v4_2.dstaddr = (uint32_t) random_in_range (data[r]->dst_ip_down,data[r]->dst_ip_up);
	      t->vett[i].dPkts = (uint64_t) random_in_range (data[r]->pkts_down,data[r]->pkts_up);
	      t->vett[i].dOctets = (uint64_t) random_in_range (data[r]->bytes_down,data[r]->bytes_up);
	      t->vett[i].tos = (uint8_t) random_in_range (data[r]->tos_down,data[r]->tos_up);
	      t->vett[i].srcport = (uint16_t) random_in_range (data[r]->srcport_down,data[r]->srcport_up);
	      t->vett[i].dstport = (uint16_t) random_in_range (data[r]->dstport_down,data[r]->dstport_up);
	      t->vett[i].prot = (uint8_t) random_in_range (data[r]->prot_down,data[r]->prot_up);
	      strncpy(t->vett[i].src_addr_str,data[r]->src_addr_str,40);
	      strncpy(t->vett[i].dst_addr_str,data[r]->dst_addr_str,40);
	      strncpy(t->vett[i].tcp_flags_str,data[r]->flags_str,16);
	    }
	  }
	}
    }
  struct bucket_struct *s;
  int f = 0;
  // if the timeout is elapsed we know that the first list in the hash table is ready to be analyzed
  // so we order the hash table
  HASH_SORT (bucket_list, date_sort);
  for (s = bucket_list; s != NULL; s = s->hh.next)
    {
      if (met != NULL)
	ret_func =
	  gestione_metriche (s->vett, s->elements, met, dirlog, s->date);
      else
	ret_func =
	  gestione_metriche_xml (s->vett, s->elements,
				 metric_list, dirlog,
				 s->date, xml_path, max_thread);
      if (ret_func != STATUS_OK)
	{
	  if (ret_func == MEMORY_ERROR)
	    {
	      writeLogFileAnalyzer (filename,
				    MEMORY_ERROR,
				    "Problem in memory allocation returned by gestione_metriche in send_data function",
				    -1, NULL);
	      return MEMORY_ERROR;
	    }
	  else if (ret_func == ERR_OPEN_SO)
	    {
	      writeLogFileAnalyzer (filename,
				    ERR_OPEN_SO,
				    "Problem in opening shared object returned by gestione_metriche in send_data function",
				    -1, NULL);
	      return ERR_OPEN_SO;
	    }
	  else if (ret_func == ERR_INTEGRITY_DEP)
	    {
	      writeLogFileAnalyzer (filename,
				    ERR_OPEN_SO,
				    "Problem in Integrity of Dependencies in send_data function",
				    -1, NULL);
	      return ERR_INTEGRITY_DEP;
	    }
	}
    }
  // we delete the first element in the hash table since it's been analyzed
  struct bucket_struct *spcp, *tmp5;
  f = 0;
  HASH_ITER (hh, bucket_list, spcp, tmp5)
  {
    HASH_DEL (bucket_list, spcp);
    free (spcp->vett);
    free (spcp);
  }
  return STATUS_OK;
}

// Read from XML file and form data to fill the timeslot flows container
struct data_block **
manipulate_data (char *gen_xml)
{
  struct data_block **data_reading;
  if (gen_xml != NULL)
    {
      // Collect the modules name in the XML file and their dependencies
      ezxml_t stats =
	ezxml_parse_file (gen_xml), data,mode, timeslot, block, ip_src, ip_dst, packets, bytes, srcport, dstport, prot, flags, tos;
      const char *teamname;
      for (data = ezxml_child (stats, "Data"); data; data = data->next)
	{
	  mode = ezxml_child (data, "mode");
	  if (strcmp(ezxml_child (mode, "type")->txt,"build") == 0)
	  {
	  printf("in \n");
	  int i = 0;
	  for (timeslot = ezxml_child (data, "timeslot");
	       timeslot; timeslot = timeslot->next)
	    {
	      for (block = ezxml_child (timeslot, "block");
		   block; block = block->next)
		{
		  if (i == 0)
		    {
		      i++;
		      data_reading = malloc (sizeof (struct data_block *));
		      data_reading[i - 1] =
			malloc (sizeof (struct data_block));
		    }
		  else
		    {
		      i++;
		      data_reading =
			realloc (data_reading,
				 i * sizeof (struct data_block *));
		      data_reading[i - 1] =
			malloc (sizeof (struct data_block));
		    }
		  memset (data_reading[i - 1]->date, 0, 64);
		  strncpy(data_reading[i - 1]->mode,ezxml_child (mode, "type")->txt,64);
		  data_reading[i - 1]->elements_num =
		    atoi (ezxml_child (block, "number")->txt);
		  strncpy (data_reading[i - 1]->date,
			   ezxml_child (timeslot, "id")->txt, 64);
		  ip_src = ezxml_child (block, "ip_src");
		  data_reading[i - 1]->source_ip =
		    (uint32_t) atoi (ezxml_child (ip_src, "value")->txt);
		  ip_dst = ezxml_child (block, "ip_dst");
		  data_reading[i - 1]->destination_ip =
		    (uint32_t) atoi (ezxml_child (ip_dst, "value")->txt);
		  packets = ezxml_child (block, "packets");
		  strncpy(data_reading[i - 1]->src_addr_str,(ezxml_child (ip_src, "string")->txt),40);
		  strncpy(data_reading[i - 1]->dst_addr_str,(ezxml_child (ip_dst, "string")->txt),40);
                  char packets_range[64];
			strncpy(packets_range,(ezxml_child (packets, "value")->txt),64);
		  char * pch;
		  pch = strtok (packets_range,"-");
		  data_reading[i - 1]->pkts_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->pkts_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		  bytes = ezxml_child (block, "bytes");
                  char bytes_range[64];
			strncpy(bytes_range,(ezxml_child (bytes, "value")->txt),64);
		  pch = strtok (bytes_range,"-");
		  data_reading[i - 1]->bytes_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->bytes_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		  srcport = ezxml_child (block, "srcport");
		  data_reading[i - 1]->srcport =
		    (uint16_t) atoi (ezxml_child (srcport, "value")->txt);
		  dstport = ezxml_child (block, "dstport");
		  data_reading[i - 1]->dstport =
		    (uint16_t) atoi (ezxml_child (dstport, "value")->txt);
		  prot = ezxml_child (block, "protocol");
		  data_reading[i - 1]->prot = atoi (ezxml_child (prot, "value")->txt);
		  flags = ezxml_child (block, "flagstring");
		  char flags_str[16];
	          strncpy(flags_str,(ezxml_child (flags, "value")->txt),16);
		  tos = ezxml_child (block, "tos");
                  char tos_range[64];
			strncpy(tos_range,(ezxml_child (tos, "value")->txt),64);
		  pch = strtok (tos_range,"-");
		  data_reading[i - 1]->tos_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->tos_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		}
	    }
	}
	else
	{
	  if (strcmp((ezxml_child (mode, "type")->txt),"random") == 0)
	  {	
	  int i = 0;
	  for (timeslot = ezxml_child (data, "timeslot");
	       timeslot; timeslot = timeslot->next)
	    {
	      for (block = ezxml_child (timeslot, "block");
		   block; block = block->next)
		{
		  if (i == 0)
		    {
		      i++;
		      data_reading = malloc (sizeof (struct data_block *));
		      data_reading[i - 1] =
			malloc (sizeof (struct data_block));
		    }
		  else
		    {
		      i++;
		      data_reading =
			realloc (data_reading,
				 i * sizeof (struct data_block *));
		      data_reading[i - 1] =
			malloc (sizeof (struct data_block));
		    }
		  strncpy(data_reading[i - 1]->mode,ezxml_child (mode, "type")->txt,64);
		  memset (data_reading[i - 1]->date, 0, 64);
		  data_reading[i - 1]->elements_num =
		    atoi (ezxml_child (block, "number")->txt);
		  strncpy (data_reading[i - 1]->date,
			   ezxml_child (timeslot, "id")->txt, 64);
		  ip_src = ezxml_child (block, "ip_src");
		  char ip_src_range[128];
		  strncpy(ip_src_range,ezxml_child (ip_src, "value")->txt,128);
		  char * pch;
		  pch = strtok (ip_src_range,"-");
		  data_reading[i - 1]->source_ip_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->source_ip_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		  ip_dst = ezxml_child (block, "ip_dst");
		  char ip_dst_range[128];
		  strncpy(ip_dst_range,ezxml_child (ip_dst, "value")->txt,128);
		  pch = strtok (ip_dst_range,"-");
		  data_reading[i - 1]->dst_ip_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->dst_ip_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		  strncpy(data_reading[i - 1]->src_addr_str,"\0",40);
		  strncpy(data_reading[i - 1]->dst_addr_str,"\0",40);
		  packets = ezxml_child (block, "packets");
                  char packets_range[64];
			strncpy(packets_range,(ezxml_child (packets, "value")->txt),64);
		  pch = strtok (packets_range,"-");
		  data_reading[i - 1]->pkts_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->pkts_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		  bytes = ezxml_child (block, "bytes");
                  char bytes_range[64];
			strncpy(bytes_range,(ezxml_child (bytes, "value")->txt),64);
		  pch = strtok (bytes_range,"-");
		  data_reading[i - 1]->bytes_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->bytes_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		  srcport = ezxml_child (block, "srcport");
                  char srcport_range[64];
			strncpy(srcport_range,(ezxml_child (srcport, "value")->txt),64);
		  pch = strtok (srcport_range,"-");
		  data_reading[i - 1]->srcport_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->srcport_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		  dstport = ezxml_child (block, "dstport");
                  char dstport_range[64];
			strncpy(dstport_range,(ezxml_child (dstport, "value")->txt),64);
		  pch = strtok (dstport_range,"-");
		  data_reading[i - 1]->dstport_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->dstport_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		  prot = ezxml_child (block, "protocol");
                  char prot_range[64];
			strncpy(prot_range,(ezxml_child (prot, "value")->txt),64);
		  pch = strtok (prot_range,"-");
		  data_reading[i - 1]->prot_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->prot_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		  flags = ezxml_child (block, "flagstring");
		  char flags_str[16];
	          strncpy(flags_str,(ezxml_child (flags, "value")->txt),16);
		  tos = ezxml_child (block, "tos");
                  char tos_range[64];
			strncpy(tos_range,(ezxml_child (tos, "value")->txt),64);
		  pch = strtok (tos_range,"-");
		  data_reading[i - 1]->tos_down = atoi(pch);
		  while (pch != NULL)
		  {
		    data_reading[i - 1]->tos_up = atoi(pch);
		    pch = strtok (NULL, "-");
		  }
		}
	    }
	   }
	}
	}
	// Free the ezxml element
	ezxml_free (stats);
    }
  return data_reading;
}

// Count the blocks number
int
count_block (char *gen_xml)
{
  int block_num = 0;
  if (gen_xml != NULL)
    {
      // Collect the modules name in the XML file and their dependencies
      ezxml_t stats =
	ezxml_parse_file (gen_xml), data, timeslot, block, ip_src, ip_dst;
      const char *teamname;
      for (data = ezxml_child (stats, "Data"); data; data = data->next)
	{
	  for (timeslot = ezxml_child (data, "timeslot");
	       timeslot; timeslot = timeslot->next)
	    {
	      int i = 0;
	      for (block = ezxml_child (timeslot, "block");
		   block; block = block->next)
		{
		  block_num++;

		}
	    }
	}
	// Free the ezxml element
	ezxml_free (stats);
    }
  return block_num;
}

// --------------------------------------- End Generator Functions ---------------------------------------------------------------


// ---------------------------------------- Reading functions to pass data to plugin manager ----------------------------------

// Open a file, directory ecc. and read the files in it. Collect the flows in the files, convert in nf_record_t structure and pass to plugin manager (MethodManager)
int
send_data (char *rfile, time_t twin_start,
	   time_t twin_end, uint32_t count, unsigned int delay, int confirm,
	   int netflow_version, float timeslot, char *met,
	   struct metric_struct *metric_list, char *dirlog,
	   int active_timeout, char *xml_path, int max_thread)
{
  master_record_t master_record;
  common_record_t *flow_record;
  nffile_t *nffile;
  int i, done, ret, again;
  uint32_t numflows;
  struct bucket_struct *bucket_list = NULL;
  clock_t begin, end;
  char date_first_str_start[64];
  char date_str_start[64];
  char date_first_flow[64];
  char date_first_flow_sens[64];
  char date_str_start_sens[64];
  char date_first_str_start_sens[64];
  int timeslot_end = 0;
  int timeout_end = 0;
  int timeslot_sensibility = 0;
  int ret_func = 0;
  int sum = 0;
  timeslot_sensibility = ret_timeslot_sens (timeslot);
#ifdef COMPAT15
  int v1_map_done = 0;
#endif
// Analyzer file in input
// Get the first file handle
  nffile = GetNextFile (NULL, twin_start, twin_end);
  if (!nffile)
    {
      LogError ("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__,
		strerror (errno));
      return -1;
    }
  if (nffile == EMPTY_LIST)
    {
      LogError ("Empty file list. No files to process\n");
      return -1;
    }
// Initializes local variables
  numflows = 0;
  done = 0;
  int num_local_flows = 0;
  int timeout_flows = 0;

// setup Filter Engine to point to master_record, as any record read from file
// is expanded into this record
  Engine->nfrecord = (uint64_t *) & master_record;

  while (!done)
    {
      // get next data block from file
      ret = ReadBlock (nffile);

      switch (ret)
	{
	case NF_CORRUPT:
	case NF_ERROR:
	  if (ret == NF_CORRUPT)
	    LogError ("Skip corrupt data file '%s'\n", GetCurrentFilename ());
	  else
	    LogError ("Read error in file '%s': %s\n", GetCurrentFilename (),
		      strerror (errno));
	  // fall through - get next file in chain
	case NF_EOF:
	  {
	    nffile_t *next = GetNextFile (nffile, twin_start, twin_end);
	    if (next == EMPTY_LIST)
	      {
		done = 1;
	      }
	    if (next == NULL)
	      {
		done = 1;
		LogError ("Unexpected end of file list\n");
	      }
	    // else continue with next file
	    continue;

	  }
	  break;		// not really needed
	}

#ifdef COMPAT15
      if (nffile->block_header->id == DATA_BLOCK_TYPE_1)
	{
	  common_record_v1_t *v1_record =
	    (common_record_v1_t *) nffile->buff_ptr;
	  // create an extension map for v1 blocks
	  if (v1_map_done == 0)
	    {
	      extension_map_t *map =
		malloc (sizeof (extension_map_t) + 2 * sizeof (uint16_t));

	      if (!map)
		{
		  perror ("Memory allocation error");
		  exit (255);
		}
	      map->type = ExtensionMapttType;
	      map->size = sizeof (extension_map_t) + 2 * sizeof (uint16_t);
	      map->map_id = INIT_ID;
	      map->ex_id[0] = EX_IO_SNMP_2;
	      map->ex_id[1] = EX_AS_2;
	      map->ex_id[2] = 0;

	      Insert_Extension_Map (&extension_map_list, map);
	      v1_map_done = 1;
	    }

	  // convert the records to v2
	  for (i = 0; i < nffile->block_header->NumRecords; i++)
	    {
	      common_record_t *v2_record = (common_record_t *) v1_record;
	      Convert_v1_to_v2 ((void *) v1_record);
	      // now we have a v2 record -> use size of v2_record->size
	      v1_record =
		(common_record_v1_t *) ((pointer_addr_t) v1_record +
					v2_record->size);
	    }
	  nffile->block_header->id = DATA_BLOCK_TYPE_2;
	}
#endif

      if (nffile->block_header->id != DATA_BLOCK_TYPE_2)
	{
	  LogError ("Can't process block type %u. Skip block.\n",
		    nffile->block_header->id);
	  continue;
	}

      // and added to the output buffer
      flow_record = nffile->buff_ptr;

      // At this point we start to read the data
      // if count is not defined we send all the data in the netflow  
      if (count == -1)
	{
	  for (i = 0; i < nffile->block_header->NumRecords; i++)
	    {
	      // if timeslot is not elapsed we read flows
	      if (timeslot_end != 1)
		{
		  // Filtering flow_record by type
		  int match;
		  if (flow_record->type == CommonRecordType)
		    {
		      if (extension_map_list.slot[flow_record->ext_map] ==
			  NULL)
			{
			  LogError
			    ("Corrupt data file. Missing extension map %u. Skip record.\n",
			     flow_record->ext_map);
			  flow_record =
			    (common_record_t *) ((pointer_addr_t) flow_record
						 + flow_record->size);
			  continue;
			}

		      // if no filter is given, the result is always true
		      ExpandRecord_v2 (flow_record,
				       extension_map_list.slot[flow_record->
							       ext_map],
				       &master_record);

		      match = twin_start && (master_record.first < twin_start
					     || master_record.last >
					     twin_end) ? 0 : 1;

		      // filter netflow record with user supplied filter
		      if (match)
			match = (*Engine->FilterEngine) (Engine);

		      if (match == 0)
			{	// record failed to pass all filters
			  // increment pointer by number of bytes for netflow record
			  printf ("No Match \n");
			  flow_record =
			    (common_record_t *) ((pointer_addr_t) flow_record
						 + flow_record->size);
			  // go to next record
			  continue;
			}
		      // Records passed filter -> continue record processing
		      // We are able to convert the record at this point
		      // Increment local variables
		      numflows++;
		      num_local_flows++;
		      nf_record_t add_element;

		      // Convert record in nfrecord_t type
		      record_conversion (&master_record, &add_element, 0, 0);
		      //if the active timeout is not elapsed, we save the date of the first flows in two format
		      // First: long date
		      // Second: date according to timeslot sensibility
		      if (timeout_flows == 0)
			{
			  memset (date_first_str_start, 0, 64);
			  memset (date_first_str_start_sens, 0, 64);
			  strncpy (date_first_str_start, add_element.datestr1,
				   64);
			  strncpy (date_first_str_start_sens,
				   add_element.datestr1,
				   timeslot_sensibility);
			  date_first_str_start_sens[timeslot_sensibility +
						    1] = '\0';
			  timeout_flows = 1;
			}
		      // We save the date of the first flow of the timeslot in the same two formats
		      if (num_local_flows == 1)
			{
			  memset (date_first_flow, 0, 64);
			  memset (date_first_flow_sens, 0, 64);
			  strncpy (date_first_flow, add_element.datestr1, 64);
			  strncpy (date_first_flow_sens, add_element.datestr1,
				   timeslot_sensibility);
			  date_first_flow_sens[timeslot_sensibility + 1] =
			    '\0';
			}
		      // And we save the date in the same two formats for comparing purpose
		      memset (date_str_start, 0, 64);
		      memset (date_str_start_sens, 0, 64);
		      strncpy (date_str_start, add_element.datestr1, 64);
		      strncpy (date_str_start_sens, add_element.datestr1,
			       timeslot_sensibility);
		      date_str_start_sens[timeslot_sensibility + 1] = '\0';
		      // We search the current date in the hash table (bucket_list)
		      struct bucket_struct *t;
		      HASH_FIND_STR (bucket_list, date_str_start_sens, t);
		      // if the current date is not in the hash table we add the date and add the nf_record_t element to the 
		      // array of nf_record_t elements (vett)
		      if (t == NULL)
			{
			  t =
			    (struct bucket_struct *)
			    malloc (sizeof (struct bucket_struct));
			  if (t == NULL)
			    {
			      printf
				("[Info] Problem in memory allocation in send data malloc \n");
			      writeLogFileAnalyzer (filename, MEMORY_ERROR,
						    "Problem in memory allocation in send data",
						    -1, NULL);
			      return MEMORY_ERROR;
			    }
			  memset (t, 0, sizeof (struct bucket_struct));
			  strncpy (t->date, date_str_start_sens, 64);
			  t->elements = 1;
			  t->vett =
			    (nf_record_t *)
			    malloc (((t->elements +
				      1) * sizeof (nf_record_t)));
			  if (t->vett == NULL)
			    {
			      printf
				("[Info] Problem in memory allocation in send data malloc \n");
			      writeLogFileAnalyzer (filename, MEMORY_ERROR,
						    "Problem in memory allocation in send data",
						    -1, NULL);
			      return MEMORY_ERROR;
			    }
			  t->vett[t->elements] = add_element;
			  HASH_ADD_STR (bucket_list, date, t);
			}
		      // else we we increment the number of flows in the list and add the new elements to the existent 
		      // element in the hash table
		      else
			{
			  t->elements = t->elements + 1;
			  t->vett =
			    (nf_record_t *) realloc (t->vett,
						     ((t->elements +
						       1) *
						      sizeof (nf_record_t)));
			  if (t->vett == NULL)
			    {
			      printf
				("[Info] Problem in memory allocation in send data realloc \n");
			      writeLogFileAnalyzer (filename, MEMORY_ERROR,
						    "Problem in memory allocation in send data",
						    -1, NULL);
			      return MEMORY_ERROR;
			    }
			  t->vett[t->elements] = add_element;
			}
		      // if we have almost to flows, we compare the date to verify if timeslot is elapsed and active timeout
		      // is elapsed
		      if (num_local_flows >= 2)
			{
			  if (compare_date
			      (date_first_flow, date_str_start,
			       timeslot) == 1)
			    timeslot_end = 1;
			  if (compare_date
			      (date_first_str_start, date_str_start,
			       active_timeout) == 1)
			    timeout_end = 1;
			  //if (block_flows == MAX_FLOWS_BLOCK) timeout_end = 1;
			}

		    }
		  else if (flow_record->type == ExtensionMapType)
		    {
		      extension_map_t *map = (extension_map_t *) flow_record;

		      if (Insert_Extension_Map (&extension_map_list, map))
			{
			  // flush new map

			}	// else map already known and flushed
		    }
		  else
		    {
		      LogError ("Skip unknown record type %i\n",
				flow_record->type);
		    }
		  // Advance pointer by number of bytes for netflow record
		  flow_record =
		    (common_record_t *) ((pointer_addr_t) flow_record +
					 flow_record->size);
		}
	      // If timeslot is elapsed we pass to analyze
	      else
		{
		  writeLogFileAnalyzer (filename, INFO, "Timeslot flows",
					num_local_flows, NULL);
		  writeLogFileAnalyzer (filename, INFO, "Total flows read",
					numflows, NULL);
		  printf ("[Info] Total flows: %d Timeslot flows: %d \n",
			  numflows, num_local_flows);
		  // The timeslot is elapsed and we have a block of flow records converted, so we analyze them
		  // Free the memory
		  struct bucket_struct *s;
		  int f = 0;
		  // if the timeout is elapsed we know that the first list in the hash table is ready to be analyzed
		  if (timeslot_end == 1 && timeout_end == 1)
		    {
		      // so we order the hash table
		      HASH_SORT (bucket_list, date_sort);
		      for (s = bucket_list; s != NULL; s = s->hh.next)
			{
			  // we analyze only the first element in order in the hash table
			  f++;
			  iter++;
			  if (iter == 1)
			    {
			      strncpy (last_date_seen, s->date, 64);
			      if (met != NULL)
				ret_func =
				  gestione_metriche (s->vett, s->elements,
						     met, dirlog, s->date);
			      else
				ret_func =
				  gestione_metriche_xml (s->vett, s->elements,
							 metric_list, dirlog,
							 s->date, xml_path,
							 max_thread);
			      if (ret_func != STATUS_OK)
				{
				  if (ret_func == MEMORY_ERROR)
				    {
				      writeLogFileAnalyzer (filename,
							    MEMORY_ERROR,
							    "Problem in memory allocation returned by gestione_metriche in send_data function",
							    -1, NULL);
				      return MEMORY_ERROR;
				    }
				  else if (ret_func == ERR_OPEN_SO)
				    {
				      writeLogFileAnalyzer (filename,
							    ERR_OPEN_SO,
							    "Problem in opening shared object returned by gestione_metriche in send_data function",
							    -1, NULL);
				      return ERR_OPEN_SO;
				    }
				  else if (ret_func == ERR_INTEGRITY_DEP)
				    {
				      writeLogFileAnalyzer (filename,
							    ERR_OPEN_SO,
							    "Problem in Integrity of Dependencies in send_data function",
							    -1, NULL);
				      return ERR_INTEGRITY_DEP;
				    }
				}
			      if (f == 1)
				break;
			    }
			  else
			    {
			      // If we've already seen this timeslot in analisys we skip it and delete
			      if (strcmp (s->date, last_date_seen) > 0)
				{
				  strncpy (last_date_seen, s->date, 64);
				  if (met != NULL)
				    ret_func =
				      gestione_metriche (s->vett, s->elements,
							 met, dirlog,
							 s->date);
				  else
				    ret_func =
				      gestione_metriche_xml (s->vett,
							     s->elements,
							     metric_list,
							     dirlog, s->date,
							     xml_path,
							     max_thread);
				  if (ret_func != STATUS_OK)
				    {
				      if (ret_func == MEMORY_ERROR)
					{
					  writeLogFileAnalyzer (filename,
								MEMORY_ERROR,
								"Problem in memory allocation returned by gestione_metriche in send_data function",
								-1, NULL);
					  return MEMORY_ERROR;
					}
				      else if (ret_func == ERR_OPEN_SO)
					{
					  writeLogFileAnalyzer (filename,
								ERR_OPEN_SO,
								"Problem in opening shared object returned by gestione_metriche in send_data function",
								-1, NULL);
					  return ERR_OPEN_SO;
					}
				      else if (ret_func == ERR_INTEGRITY_DEP)
					{
					  writeLogFileAnalyzer (filename,
								ERR_OPEN_SO,
								"Problem in Integrity of Dependencies in send_data function",
								-1, NULL);
					  return ERR_INTEGRITY_DEP;
					}
				    }
				  if (f == 1)
				    break;
				}
			      else
				{
				  printf
				    ("[Info] Timeslot already seen. Skipped flows: %d \n",
				     s->elements);
				  writeLogFileAnalyzer (filename, INFO,
							"Timeslot already seen. Skipped flows",
							s->elements, NULL);
				  if (f == 1)
				    break;
				}
			    }
			}
		      // we delete the first element in the hash table since it's been analyzed
		      struct bucket_struct *spcp, *tmp5;
		      f = 0;
		      HASH_ITER (hh, bucket_list, spcp, tmp5)
		      {
			f++;
			HASH_DEL (bucket_list, spcp);
			free (spcp->vett);
			free (spcp);
			if (f == 1)
			  break;
		      }
		      timeout_flows = 0;
		    }
		  // Compute the total sum of flows (for statistical purposes)
		  sum += num_local_flows;
		  // Define 0 the counter of the flows for the next block
		  num_local_flows = 0;
		  // The flows counter must be to i-1, otherwise we lose a flow for every block except the first
		  i = i - 1;
		  // Restart the timeslot counter
		  timeslot_end = 0;
		}
	    }			// for
	}
      // else if count is defined we send count number of flow record in the netflow file
      // The operation is the same, but we add another control
      else
	{
	  for (i = 0; i < nffile->block_header->NumRecords; i++)
	    {
	      int match;
	      // Until we have converted count flows we continue to add flows to the structure
	      if (numflows < count)
		{
		  if (timeslot_end != 1)
		    {
		      if (flow_record->type == CommonRecordType)
			{
			  if (extension_map_list.slot[flow_record->ext_map] ==
			      NULL)
			    {
			      LogError
				("Corrupt data file. Missing extension map %u. Skip record.\n",
				 flow_record->ext_map);
			      flow_record =
				(common_record_t *) ((pointer_addr_t)
						     flow_record +
						     flow_record->size);
			      continue;
			    }

			  // if no filter is given, the result is always true
			  ExpandRecord_v2 (flow_record,
					   extension_map_list.slot
					   [flow_record->ext_map],
					   &master_record);

			  match = twin_start
			    && (master_record.first < twin_start
				|| master_record.last > twin_end) ? 0 : 1;

			  // filter netflow record with user supplied filter
			  if (match)
			    match = (*Engine->FilterEngine) (Engine);

			  if (match == 0)
			    {
			      // record failed to pass all filters
			      // increment pointer by number of bytes for netflow record
			      flow_record =
				(common_record_t *) ((pointer_addr_t)
						     flow_record +
						     flow_record->size);
			      // go to next record
			      continue;
			    }
			  // Records passed filter -> continue record processing

			  // Records passed filter -> continue record processing
			  numflows++;
			  num_local_flows++;
			  nf_record_t add_element;
			  // Allocate memory in our data structures

			  // Convert record in nfrecord_t type
			  record_conversion (&master_record, &add_element, 0,
					     0);
			  if (timeout_flows == 0)
			    {
			      memset (date_first_str_start, 0, 64);
			      memset (date_first_str_start_sens, 0, 64);
			      strncpy (date_first_str_start,
				       add_element.datestr1, 64);
			      strncpy (date_first_str_start_sens,
				       add_element.datestr1,
				       timeslot_sensibility);
			      date_first_str_start_sens[timeslot_sensibility +
							1] = '\0';
			      timeout_flows = 1;
			    }
			  if (num_local_flows == 1)
			    {
			      memset (date_first_flow, 0, 64);
			      memset (date_first_flow_sens, 0, 64);
			      strncpy (date_first_flow, add_element.datestr1,
				       64);
			      strncpy (date_first_flow_sens,
				       add_element.datestr1,
				       timeslot_sensibility);
			      date_first_flow_sens[timeslot_sensibility + 1] =
				'\0';
			    }
			  memset (date_str_start, 0, 64);
			  memset (date_str_start_sens, 0, 64);
			  strncpy (date_str_start, add_element.datestr1, 64);
			  strncpy (date_str_start_sens, add_element.datestr1,
				   timeslot_sensibility);
			  date_str_start_sens[timeslot_sensibility + 1] =
			    '\0';
			  struct bucket_struct *t;
			  HASH_FIND_STR (bucket_list, date_str_start_sens, t);
			  if (t == NULL)
			    {
			      t =
				(struct bucket_struct *)
				malloc (sizeof (struct bucket_struct));
			      if (t == NULL)
				{
				  printf
				    ("[Info] Problem in memory allocation in send data malloc \n");
				  writeLogFileAnalyzer (filename,
							MEMORY_ERROR,
							"Problem in memory allocation in send data",
							-1, NULL);
				  return MEMORY_ERROR;
				}
			      memset (t, 0, sizeof (struct bucket_struct));
			      strncpy (t->date, date_str_start_sens, 64);
			      t->elements = 1;
			      t->vett =
				(nf_record_t *)
				malloc (((t->elements +
					  1) * sizeof (nf_record_t)));
			      if (t->vett == NULL)
				{
				  printf
				    ("[Info] Problem in memory allocation in send data malloc \n");
				  writeLogFileAnalyzer (filename,
							MEMORY_ERROR,
							"Problem in memory allocation in send data",
							-1, NULL);
				  return MEMORY_ERROR;
				}
			      t->vett[t->elements] = add_element;
			      HASH_ADD_STR (bucket_list, date, t);
			    }
			  else
			    {
			      t->elements = t->elements + 1;
			      t->vett =
				(nf_record_t *) realloc (t->vett,
							 ((t->elements +
							   1) *
							  sizeof
							  (nf_record_t)));
			      if (t->vett == NULL)
				{
				  printf
				    ("[Info] Problem in memory allocation in send data realloc \n");
				  writeLogFileAnalyzer (filename,
							MEMORY_ERROR,
							"Problem in memory allocation in send data",
							-1, NULL);
				  return MEMORY_ERROR;
				}
			      t->vett[t->elements] = add_element;
			    }

			  if (num_local_flows >= 2)
			    {
			      if (compare_date
				  (date_first_flow, date_str_start,
				   timeslot) == 1)
				timeslot_end = 1;
			      if (compare_date
				  (date_first_str_start, date_str_start,
				   active_timeout) == 1)
				timeout_end = 1;
			      //if (block_flows == MAX_FLOWS_BLOCK) timeout_end = 1;
			    }


			}
		      else if (flow_record->type == ExtensionMapType)
			{
			  extension_map_t *map =
			    (extension_map_t *) flow_record;

			  if (Insert_Extension_Map (&extension_map_list, map))
			    {
			      // flush new map

			    }	// else map already known and flushed

			}
		      else
			{
			  LogError ("Skip unknown record type %i\n",
				    flow_record->type);
			}
		      // Advance pointer by number of bytes for netflow record
		      flow_record =
			(common_record_t *) ((pointer_addr_t) flow_record +
					     flow_record->size);
		    }
		  else
		    {
		      writeLogFileAnalyzer (filename, INFO, "Timeslot flows",
					    num_local_flows, NULL);
		      writeLogFileAnalyzer (filename, INFO,
					    "Total flows read", numflows,
					    NULL);
		      printf ("[Info] Total flows: %d Timeslot flows: %d \n",
			      numflows, num_local_flows);
		      struct bucket_struct *s;
		      int f = 0;
		      if (timeslot_end == 1 && timeout_end == 1)
			{
			  HASH_SORT (bucket_list, date_sort);
			  for (s = bucket_list; s != NULL; s = s->hh.next)
			    {
			      f++;
			      iter++;
			      if (iter == 1)
				{
				  strncpy (last_date_seen, s->date, 64);
				  if (met != NULL)
				    ret_func =
				      gestione_metriche (s->vett, s->elements,
							 met, dirlog,
							 s->date);
				  else
				    ret_func =
				      gestione_metriche_xml (s->vett,
							     s->elements,
							     metric_list,
							     dirlog, s->date,
							     xml_path,
							     max_thread);
				  if (ret_func != STATUS_OK)
				    {
				      if (ret_func == MEMORY_ERROR)
					{
					  writeLogFileAnalyzer (filename,
								MEMORY_ERROR,
								"Problem in memory allocation returned by gestione_metriche in send_data function",
								-1, NULL);
					  return MEMORY_ERROR;
					}
				      else if (ret_func == ERR_OPEN_SO)
					{
					  writeLogFileAnalyzer (filename,
								ERR_OPEN_SO,
								"Problem in opening shared object returned by gestione_metriche in send_data function",
								-1, NULL);
					  return ERR_OPEN_SO;
					}
				      else if (ret_func == ERR_INTEGRITY_DEP)
					{
					  writeLogFileAnalyzer (filename,
								ERR_OPEN_SO,
								"Problem in Integrity of Dependencies in send_data function",
								-1, NULL);
					  return ERR_INTEGRITY_DEP;
					}
				    }
				  if (f == 1)
				    break;
				}
			      else
				{
				  if (strcmp (s->date, last_date_seen) > 0)
				    {
				      strncpy (last_date_seen, s->date, 64);
				      if (met != NULL)
					ret_func =
					  gestione_metriche (s->vett,
							     s->elements, met,
							     dirlog, s->date);
				      else
					ret_func =
					  gestione_metriche_xml (s->vett,
								 s->elements,
								 metric_list,
								 dirlog,
								 s->date,
								 xml_path,
								 max_thread);
				      if (ret_func != STATUS_OK)
					{
					  if (ret_func == MEMORY_ERROR)
					    {
					      writeLogFileAnalyzer (filename,
								    MEMORY_ERROR,
								    "Problem in memory allocation returned by gestione_metriche in send_data function",
								    -1, NULL);
					      return MEMORY_ERROR;
					    }
					  else if (ret_func == ERR_OPEN_SO)
					    {
					      writeLogFileAnalyzer (filename,
								    ERR_OPEN_SO,
								    "Problem in opening shared object returned by gestione_metriche in send_data function",
								    -1, NULL);
					      return ERR_OPEN_SO;
					    }
					  else if (ret_func ==
						   ERR_INTEGRITY_DEP)
					    {
					      writeLogFileAnalyzer (filename,
								    ERR_OPEN_SO,
								    "Problem in Integrity of Dependencies in send_data function",
								    -1, NULL);
					      return ERR_INTEGRITY_DEP;
					    }
					}
				      if (f == 1)
					break;
				    }
				  else
				    {
				      printf
					("[Info] Timeslot already seen. Skipped flows: %d \n",
					 s->elements);
				      writeLogFileAnalyzer (filename, INFO,
							    "Timeslot already seen. Skipped flows",
							    s->elements,
							    NULL);
				      if (f == 1)
					break;
				    }
				}
			    }
			  struct bucket_struct *spcp, *tmp5;
			  f = 0;
			  HASH_ITER (hh, bucket_list, spcp, tmp5)
			  {
			    f++;
			    HASH_DEL (bucket_list, spcp);
			    free (spcp->vett);
			    free (spcp);
			    if (f == 1)
			      break;
			  }
			  timeout_flows = 0;
			}
		      // Compute the total sum of flows (for statistical purposes)
		      sum += num_local_flows;
		      // Define 0 the counter of the flows for the next block
		      num_local_flows = 0;
		      // The flows counter must be to i-1, otherwise we lose a flows for every block except the first
		      i = i - 1;
		      timeslot_end = 0;
		    }
		}
	      else
		break;
	    }			// for
	}
      if (numflows == count)
	break;
    }				//while
//close file
  if (nffile)
    {
      CloseFile (nffile);
      DisposeFile (nffile);
    }
// At this point it can be possible that we have a group of data not analyzed (the timeslot is not elapsed and we have finish to read data)
// So we analyze the remaining data
  sum += num_local_flows;
  writeLogFileAnalyzer (filename, INFO, "Timeslot flows", num_local_flows,
			NULL);
  writeLogFileAnalyzer (filename, INFO, "Total flows read", numflows, NULL);
  printf ("[Info] Total flows: %d Timeslot flows: %d \n", numflows,
	  num_local_flows);
  struct bucket_struct *s;
  HASH_SORT (bucket_list, date_sort);
  for (s = bucket_list; s != NULL; s = s->hh.next)
    {
      if (strcmp (s->date, last_date_seen) > 0)
	{
	  strncpy (last_date_seen, s->date, 64);
	  if (met != NULL)
	    ret_func =
	      gestione_metriche (s->vett, s->elements, met, dirlog, s->date);
	  else
	    ret_func =
	      gestione_metriche_xml (s->vett, s->elements, metric_list,
				     dirlog, s->date, xml_path, max_thread);
	  if (ret_func != STATUS_OK)
	    {
	      if (ret_func == MEMORY_ERROR)
		{
		  writeLogFileAnalyzer (filename, MEMORY_ERROR,
					"Problem in memory allocation returned by gestione_metriche in send_data function",
					-1, NULL);
		  return MEMORY_ERROR;
		}
	      else if (ret_func == ERR_OPEN_SO)
		{
		  writeLogFileAnalyzer (filename, ERR_OPEN_SO,
					"Problem in opening shared object returned by gestione_metriche in send_data function",
					-1, NULL);
		  return ERR_OPEN_SO;
		}
	      else if (ret_func == ERR_INTEGRITY_DEP)
		{
		  writeLogFileAnalyzer (filename, ERR_OPEN_SO,
					"Problem in Integrity of Dependencies in send_data function",
					-1, NULL);
		  return ERR_INTEGRITY_DEP;
		}
	    }
	}
      else
	{
	  printf ("[Info] Timeslot already seen. Skipped flows: %d \n",
		  s->elements);
	  writeLogFileAnalyzer (filename, INFO,
				"Timeslot already seen. Skipped flows",
				s->elements, NULL);
	}

    }
// and free the hash table and the array of flows
  struct bucket_struct *spcp, *tmp5;
  HASH_ITER (hh, bucket_list, spcp, tmp5)
  {
    HASH_DEL (bucket_list, spcp);	/* delete; users advances to next */
    free (spcp->vett);
    free (spcp);
  }
// back to main
  return STATUS_OK;
}				// End of send_data



/******************Netflow block conversion*********************/
//record sent by collector will be copied in a different struct
//nf_record_t is the struct converted for workers
void
record_conversion (void *record, nf_record_t * output_r, int anon, int tag)
{
  uint64_t anon_ip[2];
  char *s, *_s, as[IP_STRING_LEN], ds[IP_STRING_LEN], datestr1[64],
    datestr2[64], flags_str[16];
  char s_snet[IP_STRING_LEN], s_dnet[IP_STRING_LEN];
  int i, id;
  ssize_t slen, _slen;
  time_t when;
  int curr_data_block = 0;
  struct tm *ts;
  char data_string[STRINGSIZE];
  master_record_t *r = (master_record_t *) record;
  extension_map_t *extension_map = r->map_ref;
  as[0] = 0;
  ds[0] = 0;
  if ((r->flags & FLAG_IPV6_ADDR) != 0)
    {				// IPv6
      uint64_t snet[2];
      uint64_t dnet[2];

      if (anon)
	{
	  anonymize_v6 (r->v6.srcaddr, anon_ip);
	  r->v6.srcaddr[0] = anon_ip[0];
	  r->v6.srcaddr[1] = anon_ip[1];

	  anonymize_v6 (r->v6.dstaddr, anon_ip);
	  r->v6.dstaddr[0] = anon_ip[0];
	  r->v6.dstaddr[1] = anon_ip[1];
	}
      // remember IPs for network 
      snet[0] = r->v6.srcaddr[0];
      snet[1] = r->v6.srcaddr[1];
      dnet[0] = r->v6.dstaddr[0];
      dnet[1] = r->v6.dstaddr[1];
      r->v6.srcaddr[0] = htonll (r->v6.srcaddr[0]);
      r->v6.srcaddr[1] = htonll (r->v6.srcaddr[1]);
      r->v6.dstaddr[0] = htonll (r->v6.dstaddr[0]);
      r->v6.dstaddr[1] = htonll (r->v6.dstaddr[1]);
      inet_ntop (AF_INET6, r->v6.srcaddr, as, sizeof (as));
      inet_ntop (AF_INET6, r->v6.dstaddr, ds, sizeof (ds));
      if (!Getv6Mode ())
	{
	  condense_v6 (as);
	  condense_v6 (ds);
	}
      if (r->src_mask || r->dst_mask)
	{
	  if (r->src_mask > 64)
	    snet[1] &= 0xffffffffffffffffLL << (128 - r->src_mask);
	  else
	    {
	      snet[1] &= 0xffffffffffffffffLL << (64 - r->src_mask);
	      snet[1] = 0;
	    }
	  snet[0] = htonll (snet[0]);
	  snet[1] = htonll (snet[1]);
	  inet_ntop (AF_INET6, &snet, s_snet, sizeof (s_snet));

	  if (r->dst_mask > 64)
	    dnet[1] &= 0xffffffffffffffffLL << (128 - r->dst_mask);
	  else
	    {
	      dnet[1] &= 0xffffffffffffffffLL << (64 - r->dst_mask);
	      dnet[1] = 0;
	    }
	  dnet[0] = htonll (dnet[0]);
	  dnet[1] = htonll (dnet[1]);
	  inet_ntop (AF_INET6, &dnet, s_dnet, sizeof (s_dnet));
	  if (!Getv6Mode ())
	    {
	      condense_v6 (s_snet);
	      condense_v6 (s_dnet);
	    }

	}
      else
	{
	  s_snet[0] = '\0';
	  s_dnet[0] = '\0';
	}

    }
  else
    {				// IPv4
      uint32_t snet, dnet;
      if (anon)
	{
	  r->v4.srcaddr = anonymize (r->v4.srcaddr);
	  r->v4.dstaddr = anonymize (r->v4.dstaddr);
	}
      snet = r->v4.srcaddr;
      dnet = r->v4.dstaddr;
      r->v4.srcaddr = htonl (r->v4.srcaddr);
      r->v4.dstaddr = htonl (r->v4.dstaddr);
      output_r->ip_union._v4_2.srcaddr = r->v4.srcaddr;
      output_r->ip_union._v4_2.dstaddr = r->v4.dstaddr;
      inet_ntop (AF_INET, &r->v4.srcaddr, as, sizeof (as));
      inet_ntop (AF_INET, &r->v4.dstaddr, ds, sizeof (ds));
      if (r->src_mask || r->dst_mask)
	{
	  snet &= 0xffffffffL << (32 - r->src_mask);
	  snet = htonl (snet);
	  inet_ntop (AF_INET, &snet, s_snet, sizeof (s_snet));

	  dnet &= 0xffffffffL << (32 - r->dst_mask);
	  dnet = htonl (dnet);
	  inet_ntop (AF_INET, &dnet, s_dnet, sizeof (s_dnet));
	}
      else
	{
	  s_snet[0] = '\0';
	  s_dnet[0] = '\0';
	}
    }
  as[IP_STRING_LEN - 1] = 0;
  ds[IP_STRING_LEN - 1] = 0;

  when = r->first;
  ts = localtime (&when);
  strftime (datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

  when = r->last;
  ts = localtime (&when);
  strftime (datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

  String_Flags (record, flags_str);

  _s = data_string;
  slen = STRINGSIZE;
  snprintf (_s, slen - 1, "\n");
  _slen = strlen (data_string);
  _s += _slen;
  slen -= _slen;
  //Copy converted blocks in a struct prepared for workers
  output_r->netflow_n = curr_data_block;

  output_r->flags = r->flags;
  output_r->size = r->size;
  output_r->first = r->first;
  strncpy (output_r->datestr1, datestr1, 63);
  strncpy (output_r->datestr2, datestr2, 63);
  output_r->msec_first = r->msec_first;
  output_r->msec_last = r->msec_last;
  strncpy (output_r->src_addr_str, as, 39);
  strncpy (output_r->dst_addr_str, ds, 39);
  output_r->srcport = r->srcport;
  output_r->dstport = r->dstport;
  output_r->fwd_status = r->fwd_status;
  output_r->tcp_flags = r->tcp_flags;
  strncpy (output_r->tcp_flags_str, flags_str, 15);
  output_r->prot = r->prot;
  output_r->tos = r->tos;
  output_r->dPkts = r->dPkts;
  output_r->dOctets = r->dOctets;


  if (TestFlag (r->flags, FLAG_SAMPLED))
    {
      strncpy (output_r->sampled, "Sampled", 7);
      output_r->sampled[7] = '\0';
    }
  else
    {
      strncpy (output_r->sampled, "Unsampled", 9);
      output_r->sampled[9] = '\0';
    }
  //Copy all supported extension
  i = 0;
  while ((id = extension_map->ex_id[i]) != 0)
    {
      if (slen <= 20)
	{
	  fprintf (stderr, "String too short! Missing record data!\n");
	  data_string[STRINGSIZE - 1] = 0;
	  s = data_string;
	}
      switch (id)
	{
	case EX_IO_SNMP_2:
	case EX_IO_SNMP_4:
	  snprintf (_s, slen - 1,
		    "  input        =             %5u\n"
		    "  output       =             %5u\n", r->input,
		    r->output);
	  output_r->input = r->input;
	  output_r->output = r->output;

	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;
	  break;
	case EX_AS_2:
	case EX_AS_4:
	  snprintf (_s, slen - 1,
		    "  src as       =             %5u\n"
		    "  dst as       =             %5u\n", r->srcas, r->dstas);
	  output_r->srcas = r->srcas;
	  output_r->dstas = r->dstas;

	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;
	  break;
	case EX_MULIPLE:
	  snprintf (_s, slen - 1,
		    "  src mask     =             %5u %s/%u\n"
		    "  dst mask     =             %5u %s/%u\n"
		    "  dst tos      =               %3u\n"
		    "  direction    =               %3u\n",
		    r->src_mask, s_snet, r->src_mask, r->dst_mask,
		    s_dnet, r->dst_mask, r->dst_tos, r->dir);

	  output_r->src_mask = r->src_mask;
	  strncpy (output_r->s_snet, s_snet, 39);
	  strncpy (output_r->s_dnet, s_dnet, 39);
	  output_r->s_dnet[39] = output_r->s_snet[39] = '\0';
	  output_r->dst_mask = r->dst_mask;
	  output_r->dst_tos = r->dst_tos;
	  output_r->dir = r->dir;

	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;
	  break;
	case EX_NEXT_HOP_v4:
	  as[0] = 0;
	  if (anon)
	    {
	      r->ip_nexthop.v4 = anonymize (r->ip_nexthop.v4);
	    }
	  r->ip_nexthop.v4 = htonl (r->ip_nexthop.v4);
	  inet_ntop (AF_INET, &r->ip_nexthop.v4, as, sizeof (as));
	  as[IP_STRING_LEN - 1] = 0;

	  snprintf (_s, slen - 1, "  ip next hop  =  %16s\n", as);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->ip_nexthop.v4 = r->ip_nexthop.v4;
	  strncpy (output_r->ip_nexthop_str, as, 39);
	  output_r->ip_nexthop_str[39] = '\0';

	  break;
	case EX_NEXT_HOP_v6:
	  as[0] = 0;
	  if (anon)
	    {
	      anonymize_v6 (r->ip_nexthop.v6, anon_ip);
	      r->ip_nexthop.v6[0] = anon_ip[0];
	      r->ip_nexthop.v6[1] = anon_ip[1];
	    }
	  r->ip_nexthop.v6[0] = htonll (r->ip_nexthop.v6[0]);
	  r->ip_nexthop.v6[1] = htonll (r->ip_nexthop.v6[1]);
	  inet_ntop (AF_INET6, r->ip_nexthop.v6, as, sizeof (as));
	  if (!Getv6Mode ())
	    {
	      condense_v6 (as);
	      condense_v6 (ds);
	    }
	  as[IP_STRING_LEN - 1] = 0;

	  snprintf (_s, slen - 1, "  ip next hop  =  %16s\n", as);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->ip_nexthop.v6[0] = r->ip_nexthop.v6[0];
	  output_r->ip_nexthop.v6[1] = r->ip_nexthop.v6[1];

	  break;
	case EX_NEXT_HOP_BGP_v4:
	  as[0] = 0;
	  if (anon)
	    {
	      r->bgp_nexthop.v4 = anonymize (r->bgp_nexthop.v4);
	    }
	  r->bgp_nexthop.v4 = htonl (r->bgp_nexthop.v4);
	  inet_ntop (AF_INET, &r->bgp_nexthop.v4, as, sizeof (as));
	  as[IP_STRING_LEN - 1] = 0;

	  snprintf (_s, slen - 1, "  bgp next hop =  %16s\n", as);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->bgp_nexthop.v4 = r->bgp_nexthop.v4;
	  strncpy (output_r->bgp_nexthop_str, as, 39);
	  output_r->bgp_nexthop_str[39] = '\0';

	  break;
	case EX_NEXT_HOP_BGP_v6:
	  as[0] = 0;
	  if (anon)
	    {
	      anonymize_v6 (r->bgp_nexthop.v6, anon_ip);
	      r->bgp_nexthop.v6[0] = anon_ip[0];
	      r->bgp_nexthop.v6[1] = anon_ip[1];
	    }
	  r->bgp_nexthop.v6[0] = htonll (r->bgp_nexthop.v6[0]);
	  r->bgp_nexthop.v6[1] = htonll (r->bgp_nexthop.v6[1]);
	  inet_ntop (AF_INET6, r->ip_nexthop.v6, as, sizeof (as));
	  if (!Getv6Mode ())
	    {
	      condense_v6 (as);
	      condense_v6 (ds);
	    }
	  as[IP_STRING_LEN - 1] = 0;

	  snprintf (_s, slen - 1, "  bgp next hop =  %16s\n", as);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->bgp_nexthop.v6[0] = r->bgp_nexthop.v6[0];
	  output_r->bgp_nexthop.v6[1] = r->bgp_nexthop.v6[1];
	  strncpy (output_r->bgp_nexthop_str, as, 39);
	  output_r->bgp_nexthop_str[39] = '\0';

	  break;
	case EX_VLAN:
	  snprintf (_s, slen - 1,
		    "  src vlan     =             %5u\n"
		    "  dst vlan     =             %5u\n", r->src_vlan,
		    r->dst_vlan);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->src_vlan = r->src_vlan;
	  output_r->dst_vlan = r->dst_vlan;

	  break;
	case EX_OUT_PKG_4:
	case EX_OUT_PKG_8:
	  snprintf (_s, slen - 1,
		    "  out packets  =        %10llu\n",
		    (long long unsigned) r->out_pkts);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->out_pkts = r->out_pkts;

	  break;
	case EX_OUT_BYTES_4:
	case EX_OUT_BYTES_8:
	  snprintf (_s, slen - 1,
		    "  out bytes    =        %10llu\n",
		    (long long unsigned) r->out_bytes);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->out_bytes = r->out_bytes;

	  break;
	case EX_AGGR_FLOWS_4:
	case EX_AGGR_FLOWS_8:
	  snprintf (_s, slen - 1,
		    "  aggr flows   =        %10llu\n",
		    (long long unsigned) r->aggr_flows);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->aggr_flows = r->aggr_flows;
	  break;
	case EX_MAC_1:
	  {
	    int i;
	    uint8_t mac1[6], mac2[6];

	    for (i = 0; i < 6; i++)
	      {
		mac1[i] = (r->in_src_mac >> (i * 8)) & 0xFF;
	      }
	    for (i = 0; i < 6; i++)
	      {
		mac2[i] = (r->out_dst_mac >> (i * 8)) & 0xFF;
	      }

	    snprintf (_s, slen - 1,
		      "  in src mac   = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
		      "  out dst mac  = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		      mac1[5], mac1[4], mac1[3], mac1[2], mac1[1],
		      mac1[0], mac2[5], mac2[4], mac2[3], mac2[2],
		      mac2[1], mac2[0]);
	    _slen = strlen (data_string);
	    _s = data_string + _slen;
	    slen = STRINGSIZE - _slen;
	  }
	  output_r->in_src_mac = r->in_src_mac;
	  output_r->out_dst_mac = r->out_dst_mac;

	  break;
	case EX_MAC_2:
	  {
	    int i;
	    uint8_t mac1[6], mac2[6];

	    for (i = 0; i < 6; i++)
	      {
		mac1[i] = (r->in_dst_mac >> (i * 8)) & 0xFF;
	      }
	    for (i = 0; i < 6; i++)
	      {
		mac2[i] = (r->out_src_mac >> (i * 8)) & 0xFF;
	      }

	    snprintf (_s, slen - 1,
		      "  in dst mac   = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
		      "  out src mac  = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		      mac1[5], mac1[4], mac1[3], mac1[2], mac1[1],
		      mac1[0], mac2[5], mac2[4], mac2[3], mac2[2],
		      mac2[1], mac2[0]);
	    _slen = strlen (data_string);
	    _s = data_string + _slen;
	    slen = STRINGSIZE - _slen;
	  }
	  output_r->in_src_mac = r->in_src_mac;
	  output_r->out_dst_mac = r->out_dst_mac;
	  break;
	case EX_MPLS:
	  {
	    unsigned int i;

	    for (i = 0; i < 10; i++)
	      {
		snprintf (_s, slen - 1,
			  "  MPLS Lbl %2u  =      %8u-%1u-%1u\n",
			  i + 1, r->mpls_label[i] >> 4,
			  (r->mpls_label[i] & 0xF) >> 1,
			  r->mpls_label[i] & 1);
		_slen = strlen (data_string);
		_s = data_string + _slen;
		slen = STRINGSIZE - _slen;

		output_r->mpls_label[i] = r->mpls_label[i];

	      }
	  }

	  break;
	case EX_ROUTER_IP_v4:
	  as[0] = 0;
	  if (anon)
	    {
	      r->ip_router.v4 = anonymize (r->ip_router.v4);
	    }
	  r->ip_router.v4 = htonl (r->ip_router.v4);
	  inet_ntop (AF_INET, &r->ip_router.v4, as, sizeof (as));
	  as[IP_STRING_LEN - 1] = 0;

	  snprintf (_s, slen - 1, "  ip router    =  %16s\n", as);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->ip_router.v4 = r->ip_router.v4;
	  strncpy (output_r->ip_router_str, as, 39);
	  output_r->ip_router_str[39] = '\0';

	  break;
	case EX_ROUTER_IP_v6:
	  as[0] = 0;
	  if (anon)
	    {
	      anonymize_v6 (r->ip_router.v6, anon_ip);
	      r->ip_router.v6[0] = anon_ip[0];
	      r->ip_router.v6[1] = anon_ip[1];
	    }
	  r->ip_router.v6[0] = htonll (r->ip_router.v6[0]);
	  r->ip_router.v6[1] = htonll (r->ip_router.v6[1]);
	  inet_ntop (AF_INET6, &r->ip_router.v6, as, sizeof (as));
	  if (!Getv6Mode ())
	    {
	      condense_v6 (as);
	      condense_v6 (ds);
	    }
	  as[IP_STRING_LEN - 1] = 0;

	  snprintf (_s, slen - 1, "  ip router    =  %16s\n", as);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->ip_router.v6[0] = r->ip_router.v6[0];
	  output_r->ip_router.v6[1] = r->ip_router.v6[1];
	  strncpy (output_r->ip_router_str, as, 39);
	  output_r->ip_router_str[39] = '\0';

	  break;
	case EX_ROUTER_ID:
	  snprintf (_s, slen - 1,
		    "  engine type  =             %5u\n"
		    "  engine ID    =             %5u\n",
		    r->engine_type, r->engine_id);
	  _slen = strlen (data_string);
	  _s = data_string + _slen;
	  slen = STRINGSIZE - _slen;

	  output_r->engine_type = r->engine_type;
	  output_r->engine_id = r->engine_id;
	  break;

	default:
	  snprintf (_s, slen - 1, "Type %u not implemented\n", id);

	}
      i++;
    }				//end while

  data_string[STRINGSIZE - 1] = 0;
  s = data_string;

}

// Convert the string flags of flows
static void
String_Flags (master_record_t * r, char *string)
{

  // if record contains unusuall flags, print the flags in hex as 0x.. number
  if (r->tcp_flags > 63)
    {
      snprintf (string, 7, "  0x%2x\n", r->tcp_flags);
    }
  else
    {
      string[0] = r->tcp_flags & 32 ? 'U' : '.';
      string[1] = r->tcp_flags & 16 ? 'A' : '.';
      string[2] = r->tcp_flags & 8 ? 'P' : '.';
      string[3] = r->tcp_flags & 4 ? 'R' : '.';
      string[4] = r->tcp_flags & 2 ? 'S' : '.';
      string[5] = r->tcp_flags & 1 ? 'F' : '.';
    }
  string[6] = '\0';

}				// End of String_Flags

// ---------------------------------------- End Reading functions to pass data to plugin manager ----------------------------------

// ---------------------------------------- Main ----------------------------------------------------------------------------------

static void
usage (char *name)
{
  printf ("usage %s [options] [\"filter\"]\n"
	  "-h\t\tthis text you see right here\n"
	  "-M <input>\tread from files or subdirectories of this directory.\n"
	  "-r <input>\tread from file.\n"
	  "-R <input>\tread from directory.\n"
	  "-c <input>\tnumber of flows to analyze.\n"
	  "-m <input>\tmetric to compute\n"
	  "-t <input>\ttimeslot to analyze\n"
	  "-T <input>\tactive timeout of the router\n"
	  "-x <input>\tConfig xml file\n"
	  "-d <input>\tlog directory different from standard\n"
	  "-e <input>\tExecution Type: File or network\n"
	  "-I <input>\tTime interval between rotation of NetFlow file obtained by listening network\n"
	  "-D <input>\tStore directory of NetFlow file obtained by listening network\n"
	  "-A <input>\tDaemonize the collector\n"
	  "-b host\t\tbind socket to host/IP addr\n"
	  "-p portnum\tlisten on port portnum\n"
	  "-g portnum\tspecify an xml file to generate flows to pass to analyzer\n"
	  "-H <input>\tMax number of threads for the analysis\n", name);
}				/* usage */


int
main (int argc, char **argv)
{
  struct stat stat_buff;
  char *rfile, *ffile, *rdir, *mdir, *filter, *tstring, *dirlog, *mode;
  int c, confirm, ffd, ret, netflow_version;
  char *metric = NULL;
  char *xml_path = NULL;
  char *gen_xml = NULL;
  float timeslot = 0;
  unsigned int delay, count;
  time_t t_start, t_end, twin;
  clock_t begin, end;
  double time_spent;
  int i = 0;
  int ret_func = 0;
  int active_timeout = 1;

  char *bindhost, *savedir, pidstr[32], *launch_process;
  char *userid, *groupid, *checkptr, *listenport, *mcastgroup,
    *extension_tags;
  char *Ident, *pcap_file, pidfile[MAXPATHLEN];
  struct stat fstat;
  srecord_t *commbuff;
  packet_function_t receive_packet;
  send_peer_t peer;
  FlowSource_t *fs;
  struct sigaction act;
  int family, bufflen;
  int sock, err, synctime, do_daemonize, expire, report_sequence, do_xstat;
  int subdir_index, sampling_rate, compress;

  receive_packet = recvfrom;
  verbose = synctime = do_daemonize = 0;
  bufflen = 0;
  family = AF_UNSPEC;
  launcher_pid = 0;
  launcher_alive = 0;
  report_sequence = 0;
  listenport = DEFAULTCISCOPORT;
  bindhost = NULL;
  mcastgroup = NULL;
  pidfile[0] = 0;
  filter = NULL;
  launch_process = NULL;
  userid = groupid = NULL;
  twin = TIME_WINDOW;
  savedir = NULL;
  subdir_index = 0;
  expire = 0;
  sampling_rate = 1;
  compress = 0;
  do_xstat = 0;
  memset ((void *) &peer, 0, sizeof (send_peer_t));
  peer.family = AF_UNSPEC;
  Ident = "none";
  FlowSource = NULL;
  extension_tags = DefaultExtensions;
  pcap_file = NULL;

  rfile = rdir = mdir = ffile = filter = tstring = dirlog = NULL;
  t_start = t_end = 0;
  delay = 1;
  count = 0xFFFFFFFF;
  netflow_version = 5;
  verbose = 0;
  confirm = 0;
  receive_packet = recvfrom;
  verbose = synctime = do_daemonize = 0;
  launcher_pid = 0;
  launcher_alive = 0;
  report_sequence = 0;
  listenport = DEFAULTCISCOPORT;
  bindhost = NULL;
  launch_process = NULL;
  time_t obs = 0;
  int max_thread = 0;

  while ((c =
	  getopt (argc, argv, "h:M:r:R:c:t:m:e:I:D:d:T:x:A:H:b:p:g:")) != EOF)
    {
      switch (c)
	{
	case 'h':
	  usage (argv[0]);
	  exit (0);
	  break;
	case 'M':
	  mdir = optarg;
	  break;
	case 'r':
	  rfile = optarg;
	  break;
	case 'R':
	  rdir = optarg;
	  break;
	case 'c':
	  count = atoi (optarg);
	  break;
	case 't':
	  timeslot = atof (optarg);
	  break;
	case 'm':
	  metric = optarg;
	  break;
	case 'd':
	  dirlog = optarg;
	  break;
	case 'T':
	  active_timeout = atoi (optarg);
	  break;
	case 'x':
	  xml_path = optarg;
	  break;
	case 'e':
	  mode = optarg;
	  break;
	case 'I':
	  twin = atoi (optarg);
	  if (twin <= 0)
	    {
	      fprintf (stderr, "ERROR: time frame <= 0\n");
	      exit (255);
	    }
	  if (twin < 60)
	    {
	      fprintf (stderr, "WARNING, Very small time frame - < 60s!\n");
	    }
	  break;
	case 'D':
	  savedir = optarg;
	  if (strlen (savedir) > MAXPATHLEN)
	    {
	      fprintf (stderr, "ERROR: Path too long!\n");
	      exit (255);
	    }
	  err = stat (savedir, &fstat);
	  if (!(fstat.st_mode & S_IFDIR))
	    {
	      fprintf (stderr, "No such directory: %s\n", savedir);
	      break;
	    }
	  break;
	case 'A':
	  do_daemonize = 1;
	  break;
	case 'H':
	  max_thread = atoi (optarg);
	  break;
	case 'b':
	  bindhost = optarg;
	  break;
	case 'p':
	  listenport = optarg;
	  break;
	case 'g':
	  gen_xml = optarg;
	  break;
	default:
	  usage (argv[0]);
	  exit (0);
	}
    }
  if (argc - optind > 1)
    {
      usage (argv[0]);
      exit (255);
    }
  else
    {
      /* user specified a pcap filter */
      filter = argv[optind];
    }

  if (!filter && ffile)
    {
      if (stat (ffile, &stat_buff))
	{
	  perror ("Can't stat file");
	  exit (255);
	}
      filter = (char *) malloc (stat_buff.st_size);
      if (!filter)
	{
	  perror ("Memory error");
	  exit (255);
	}
      ffd = open (ffile, O_RDONLY);
      if (ffd < 0)
	{
	  perror ("Can't open file");
	  exit (255);
	}
      ret = read (ffd, (void *) filter, stat_buff.st_size);
      if (ret < 0)
	{
	  perror ("Error reading file");
	  close (ffd);
	  exit (255);
	}
      close (ffd);
    }
  if (mode == NULL)
    {
      LogError ("-e execution mode must be specified\n");
      exit (255);
    }
  if (strcmp (mode, "File") != 0 && strcmp (mode, "Network") != 0
      && strcmp (mode, "Generator"))
    {
      LogError ("-e execution mode must be File, Network or Generator\n");
      exit (255);
    }
  if (strcmp (mode, "File") == 0)
    {
      strncpy (filename, setFileName (ANALYZER, dirlog), FILENAME_MAX);
      writeLogFileAnalyzer (filename, STATUS_OK, "Starting Analyzer", -1,
			    NULL);
      if (!filter)
	filter = "any";

      Engine = CompileFilter (filter);
      if (!Engine)
	exit (254);

      InitExtensionMaps (&extension_map_list);

      if (rfile && rdir)
	{
	  LogError
	    ("-r and -R are mutually exclusive. Plase specify either -r or -R\n");
	  exit (255);
	}
      if (mdir && !(rfile || rdir))
	{
	  LogError
	    ("-M needs either -r or -R to specify the file or file list. Add '-R .' for all files in the directories.\n");
	  exit (255);
	}
      if (metric != NULL && xml_path != NULL)
	{
	  LogError
	    ("Only -m or -x is possible. In the first case you can specify the module by command-line otherwise with a file XML\n");
	  exit (255);
	}
      if (metric == NULL && xml_path == NULL)
	{
	  LogError
	    ("-m needs almost one metric to compute and -x need one file xml to read\n");
	  exit (255);
	}
      if (timeslot == 0)
	{
	  LogError ("-t timeslot is needed\n");
	  exit (255);
	}
      if ((rdir != NULL || rfile != NULL) && timeslot < 10)
	{
	  LogError ("-t timeslot must be almost of 10 seconds\n");
	  exit (255);
	}
      if ((rdir != NULL || rfile != NULL) && active_timeout > 3600)
	{
	  LogError ("-T active timeout must be under 3600 seconds\n");
	  exit (255);
	}

      if (rfile)
	writeLogFileAnalyzer (filename, INFO, "Selected File", -1, rfile);
      if (rdir)
	writeLogFileAnalyzer (filename, INFO, "Selected Directory", -1, rdir);
      if (mdir && rfile)
	{
	  writeLogFileAnalyzer (filename, INFO, "Selected Directory", -1,
				mdir);
	  writeLogFileAnalyzer (filename, INFO, "Selected File/Files", -1,
				rfile);
	}
      if (mdir && rdir)
	{
	  writeLogFileAnalyzer (filename, INFO, "Selected Directory", -1,
				mdir);
	  writeLogFileAnalyzer (filename, INFO, "Selected Subdirectory", -1,
				rdir);
	}
      if (timeslot != 0)
	{
	  writeLogFileAnalyzer (filename, STATUS_OK, "Selected Timeslot",
				timeslot, NULL);
	}
      if (active_timeout != 1)
	{
	  writeLogFileAnalyzer (filename, STATUS_OK,
				"Selected Active Timeout", active_timeout,
				NULL);
	}
      if (count != -1)
	{
	  writeLogFileAnalyzer (filename, INFO,
				"Number of flows to analyze limited to",
				count, NULL);
	}
      else
	{
	  writeLogFileAnalyzer (filename, INFO,
				"Number of flows to analyze limited to", -1,
				"all");
	}
      if (metric)
	{
	  writeLogFileAnalyzer (filename, INFO, "Selected Method", -1,
				metric);
	}
      if (xml_path)
	{
	  writeLogFileAnalyzer (filename, INFO, "XML config file", -1,
				xml_path);
	}
      if (tstring)
	{
	  if (!ScanTimeFrame (tstring, &t_start, &t_end))
	    exit (255);
	}

      SetupInputFileSequence (mdir, rfile, rdir);
      // if xml_path is specified we start to read its content
      struct metric_struct *metric_list = NULL;
      if (xml_path != NULL)
	{
	  // Collect the modules name in the XML file and their dependencies
	  ezxml_t stats =
	    ezxml_parse_file (xml_path), measure, measure_dep, dep;
	  const char *teamname;
	  for (measure = ezxml_child (stats, "Stats"); measure;
	       measure = measure->next)
	    {
	      for (measure_dep = ezxml_child (measure, "measure_lib");
		   measure_dep; measure_dep = measure_dep->next)
		{
		  struct metric_struct *t;
		  HASH_FIND_STR (metric_list,
				 ezxml_child (measure_dep, "name")->txt, t);
		  if (t == NULL)
		    {
		      t =
			(struct metric_struct *)
			malloc (sizeof (struct metric_struct));
		      if (t == NULL)
			{
			  printf
			    ("[Info] Problem in memory allocation in send data malloc \n");
			  writeLogFileAnalyzer (filename, MEMORY_ERROR,
						"Problem in memory allocation in send data",
						-1, NULL);
			  return MEMORY_ERROR;
			}
		      memset (t, 0, sizeof (struct metric_struct));
		      strncpy (t->metric,
			       ezxml_child (measure_dep, "name")->txt, 64);
		      t->dep_elements = 0;
		      for (dep = ezxml_child (measure_dep, "measure_depend");
			   dep; dep = dep->next)
			{
			  t->dep_elements = t->dep_elements++;
			}
		      int f = 0;
		      if (t->dep_elements > 0)
			t->dep = malloc (t->dep_elements * sizeof (char *));
		      for (dep = ezxml_child (measure_dep, "measure_depend");
			   dep; dep = dep->next)
			{
			  t->dep[f] = malloc (64 * sizeof (char));
			  strncpy (t->dep[f], ezxml_child (dep, "name")->txt,
				   64);
			  f++;
			}
		      HASH_ADD_STR (metric_list, metric, t);
		    }
		}
	    }
	  // Free the ezxml element
	  ezxml_free (stats);
	}
      begin = clock ();
      ret_func =
	send_data (rfile, t_start, t_end, count, delay, confirm,
		   netflow_version, (float) timeslot, metric, metric_list,
		   dirlog, active_timeout, xml_path, max_thread);
      end = clock ();
      time_spent = (double) (end - begin) / CLOCKS_PER_SEC;
      if (ret_func == MEMORY_ERROR)
	{
	  writeLogFileAnalyzer (filename, MEMORY_ERROR,
				"Problem in memory allocation returned by send_data function",
				-1, NULL);
	}
      if (ret_func == ERR_OPEN_SO)
	{
	  writeLogFileAnalyzer (filename, ERR_OPEN_SO,
				"Problem in opening shared object returned by send_data function",
				-1, NULL);
	}
      if (ret_func == ERR_INTEGRITY_DEP)
	{
	  writeLogFileAnalyzer (filename, ERR_OPEN_SO,
				"Problem in Integrity of Dependencies returned by send_data function",
				-1, NULL);
	}
      writeLogFileAnalyzer (filename, STATUS_OK, "Total execution time",
			    time_spent, NULL);
      writeLogFileAnalyzer (filename, STATUS_OK, "Ending Analyzer", -1, NULL);
      printf ("[Info] Total Execution Time: %f \n", time_spent);
      struct metric_struct *met_pro, *tmp;
      HASH_ITER (hh, metric_list, met_pro, tmp)
      {
	HASH_DEL (metric_list, met_pro);
	free (met_pro);
      }
    }
  if (strcmp (mode, "Network") == 0)
    {
      printf ("Here\n");
      if (FlowSource == NULL && savedir == NULL)
	{
	  fprintf (stderr, "ERROR, Missing -n (-l/-I) source definitions\n");
	  exit (255);
	}
      if (FlowSource == NULL
	  && !AddDefaultFlowSource (&FlowSource, Ident, savedir))
	exit (255);

      if (bindhost && mcastgroup)
	{
	  fprintf (stderr, "ERROR, -b and -j are mutually exclusive!!\n");
	  exit (255);
	}

      if (!InitLog (argv[0], SYSLOG_FACILITY))
	{
	  exit (255);
	}

      SetupExtensionDescriptors (strdup (extension_tags));

      // Debug code to read from pcap file
#ifdef PCAP
      sock = 0;
      if (pcap_file)
	{
	  printf ("Setup pcap reader\n");
	  setup_packethandler (pcap_file, NULL);
	  receive_packet = NextPacket;
	}
      else
#endif
      if (mcastgroup)
	sock =
	  Multicast_receive_socket (mcastgroup, listenport, family, bufflen);
      else
	sock = Unicast_receive_socket (bindhost, listenport, family, bufflen);

      if (sock == -1)
	{
	  fprintf (stderr, "Terminated due to errors.\n");
	  exit (255);
	}

      if (peer.hostname)
	{
	  peer.sockfd =
	    Unicast_send_socket (peer.hostname, peer.port, peer.family,
				 bufflen, &peer.addr, &peer.addrlen);
	  if (peer.sockfd <= 0)
	    exit (255);
	  syslog (LOG_DEBUG, "Replay flows to host: %s port: %s",
		  peer.hostname, peer.port);
	}

      if (sampling_rate < 0)
	{
	  default_sampling = -sampling_rate;
	  overwrite_sampling = default_sampling;
	}
      else
	{
	  default_sampling = sampling_rate;
	}

      if (subdir_index && !InitHierPath (subdir_index))
	{
	  close (sock);
	  exit (255);
	}

      // check if pid file exists and if so, if a process with registered pid is running
      if (strlen (pidfile))
	{
	  int pidf;
	  pidf = open (pidfile, O_RDONLY, 0);
	  if (pidf > 0)
	    {
	      // pid file exists
	      char s[32];
	      ssize_t len;
	      len = read (pidf, (void *) s, 31);
	      close (pidf);
	      s[31] = '\0';
	      if (len < 0)
		{
		  fprintf (stderr, "read() error existing pid file: %s\n",
			   strerror (errno));
		  exit (255);
		}
	      else
		{
		  unsigned long pid = atol (s);
		  if (pid == 0)
		    {
		      // garbage - use this file
		      unlink (pidfile);
		    }
		  else
		    {
		      if (kill (pid, 0) == 0)
			{
			  // process exists
			  fprintf (stderr,
				   "A process with pid %lu registered in pidfile %s is already running!\n",
				   pid, strerror (errno));
			  exit (255);
			}
		      else
			{
			  // no such process - use this file
			  unlink (pidfile);
			}
		    }
		}
	    }
	  else
	    {
	      if (errno != ENOENT)
		{
		  fprintf (stderr, "open() error existing pid file: %s\n",
			   strerror (errno));
		  exit (255);
		}		// else errno == ENOENT - no file - this is fine
	    }
	}

      if (argc - optind > 1)
	{
	  usage (argv[0]);
	  close (sock);
	  exit (255);
	}
      else
	{
	  /* user specified a pcap filter */
	  filter = argv[optind];
	}


      t_start = time (NULL);
      if (synctime)
	t_start = t_start - (t_start % twin);

      if (do_daemonize)
	{
	  verbose = 0;
	  daemonize ();
	}
      if (strlen (pidfile))
	{
	  pid_t pid = getpid ();
	  int pidf = open (pidfile, O_RDWR | O_TRUNC | O_CREAT,
			   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	  if (pidf == -1)
	    {
	      syslog (LOG_ERR, "Error opening pid file: '%s' %s", pidfile,
		      strerror (errno));
	      close (sock);
	      exit (255);
	    }
	  snprintf (pidstr, 31, "%lu\n", (unsigned long) pid);
	  if (write (pidf, pidstr, strlen (pidstr)) <= 0)
	    {
	      syslog (LOG_ERR, "Error write pid file: '%s' %s", pidfile,
		      strerror (errno));
	    }
	  close (pidf);
	}

      done = 0;
      if (launch_process || expire)
	{
	  // for efficiency reason, the process collecting the data
	  // and the process launching processes, when a new file becomes
	  // available are separated. Communication is done using signals
	  // as well as shared memory
	  // prepare shared memory
	  shmem =
	    mmap (0, sizeof (srecord_t), PROT_READ | PROT_WRITE,
		  MAP_ANON | MAP_SHARED, -1, 0);
	  if (shmem == (caddr_t) - 1)
	    {
	      syslog (LOG_ERR, "mmap() error: %s", strerror (errno));
	      close (sock);
	      exit (255);
	    }

	  commbuff = (srecord_t *) shmem;

	  launcher_pid = fork ();
	  switch (launcher_pid)
	    {
	    case 0:
	      // child
	      close (sock);
	      launcher ((char *) shmem, FlowSource, launch_process, expire);
	      _exit (0);
	      break;
	    case -1:
	      syslog (LOG_ERR, "fork() error: %s", strerror (errno));
	      if (strlen (pidfile))
		unlink (pidfile);
	      exit (255);
	      break;
	    default:
	      // parent
	      launcher_alive = 1;
	      syslog (LOG_DEBUG, "Launcher[%i] forked", launcher_pid);
	    }
	}

      fs = FlowSource;
      while (fs)
	{
	  if (InitBookkeeper
	      (&fs->bookkeeper, fs->datadir, getpid (),
	       launcher_pid) != BOOKKEEPER_OK)
	    {
	      syslog (LOG_ERR, "initialize bookkeeper failed.");

	      // release all already allocated bookkeepers
	      fs = FlowSource;
	      while (fs && fs->bookkeeper)
		{
		  ReleaseBookkeeper (fs->bookkeeper, DESTROY_BOOKKEEPER);
		  fs = fs->next;
		}
	      close (sock);
	      if (launcher_pid)
		kill_launcher (launcher_pid);
	      if (strlen (pidfile))
		unlink (pidfile);
	      exit (255);
	    }

	  // Init the extension map list
	  if (!InitExtensionMapList (fs))
	    {
	      // error message goes to syslog
	      exit (255);
	    }

	  fs = fs->next;
	}
      /* Signal handling */
      memset ((void *) &act, 0, sizeof (struct sigaction));
      act.sa_handler = IntHandler;
      sigemptyset (&act.sa_mask);
      act.sa_flags = 0;
      sigaction (SIGTERM, &act, NULL);
      sigaction (SIGINT, &act, NULL);
      sigaction (SIGHUP, &act, NULL);
      sigaction (SIGALRM, &act, NULL);
      sigaction (SIGCHLD, &act, NULL);

      syslog (LOG_INFO, "Startup.");
      run (receive_packet, sock, peer, twin, t_start, report_sequence,
	   subdir_index, compress, do_xstat);
      close (sock);
      kill_launcher (launcher_pid);

      fs = FlowSource;
      while (fs && fs->bookkeeper)
	{
	  dirstat_t *dirstat;
	  // if we do not auto expire and there is a stat file, update the stats before we leave
	  if (expire == 0
	      && ReadStatInfo (fs->datadir, &dirstat,
			       LOCK_IF_EXISTS) == STATFILE_OK)
	    {
	      UpdateBookStat (dirstat, fs->bookkeeper);
	      WriteStatInfo (dirstat);
	      syslog (LOG_INFO, "Updating statinfo in directory '%s'",
		      savedir);
	    }

	  ReleaseBookkeeper (fs->bookkeeper, DESTROY_BOOKKEEPER);
	  fs = fs->next;
	}

      syslog (LOG_INFO, "Terminating nfcapd.");
      closelog ();

      if (strlen (pidfile))
	unlink (pidfile);
    }
  if (strcmp (mode, "Generator") == 0)
    {
      strncpy (filename, setFileName (ANALYZER, dirlog), FILENAME_MAX);
      writeLogFileAnalyzer (filename, STATUS_OK, "Starting Analyzer", -1,
			    NULL);
      struct metric_struct *metric_list = NULL;
      if (xml_path != NULL)
	{
	  // Collect the modules name in the XML file and their dependencies
	  ezxml_t stats =
	    ezxml_parse_file (xml_path), measure, measure_dep, dep;
	  const char *teamname;
	  for (measure = ezxml_child (stats, "Stats"); measure;
	       measure = measure->next)
	    {
	      for (measure_dep = ezxml_child (measure, "measure_lib");
		   measure_dep; measure_dep = measure_dep->next)
		{
		  struct metric_struct *t;
		  HASH_FIND_STR (metric_list,
				 ezxml_child (measure_dep, "name")->txt, t);
		  if (t == NULL)
		    {
		      t =
			(struct metric_struct *)
			malloc (sizeof (struct metric_struct));
		      if (t == NULL)
			{
			  printf
			    ("[Info] Problem in memory allocation in send data malloc \n");
			  writeLogFileAnalyzer (filename, MEMORY_ERROR,
						"Problem in memory allocation in send data",
						-1, NULL);
			  return MEMORY_ERROR;
			}
		      memset (t, 0, sizeof (struct metric_struct));
		      strncpy (t->metric,
			       ezxml_child (measure_dep, "name")->txt, 64);
		      t->dep_elements = 0;
		      for (dep = ezxml_child (measure_dep, "measure_depend");
			   dep; dep = dep->next)
			{
			  t->dep_elements = t->dep_elements++;
			}
		      int f = 0;
		      if (t->dep_elements > 0)
			t->dep = malloc (t->dep_elements * sizeof (char *));
		      for (dep = ezxml_child (measure_dep, "measure_depend");
			   dep; dep = dep->next)
			{
			  t->dep[f] = malloc (64 * sizeof (char));
			  strncpy (t->dep[f], ezxml_child (dep, "name")->txt,
				   64);
			  f++;
			}
		      HASH_ADD_STR (metric_list, metric, t);
		    }
		}
	    }
	  // Free the ezxml element
	  ezxml_free (stats);
	}
      begin = clock ();
      ret_func =
	generate_data (gen_xml, metric, metric_list,
		       dirlog, xml_path, max_thread);
      end = clock ();
      time_spent = (double) (end - begin) / CLOCKS_PER_SEC;
      if (ret_func == MEMORY_ERROR)
	{
	  writeLogFileAnalyzer (filename, MEMORY_ERROR,
				"Problem in memory allocation returned by send_data function",
				-1, NULL);
	}
      if (ret_func == ERR_OPEN_SO)
	{
	  writeLogFileAnalyzer (filename, ERR_OPEN_SO,
				"Problem in opening shared object returned by send_data function",
				-1, NULL);
	}
      if (ret_func == ERR_INTEGRITY_DEP)
	{
	  writeLogFileAnalyzer (filename, ERR_OPEN_SO,
				"Problem in Integrity of Dependencies returned by send_data function",
				-1, NULL);
	}
      writeLogFileAnalyzer (filename, STATUS_OK, "Total execution time",
			    time_spent, NULL);
      writeLogFileAnalyzer (filename, STATUS_OK, "Ending Analyzer", -1, NULL);
      printf ("[Info] Total Execution Time: %f \n", time_spent);
      struct metric_struct *met_pro, *tmp;
      HASH_ITER (hh, metric_list, met_pro, tmp)
      {
	HASH_DEL (metric_list, met_pro);
	free (met_pro);
      }
    }
  return 0;
}

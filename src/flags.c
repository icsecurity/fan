#include <stdlib.h>
#include <math.h>
#include "flags.h"

// Computing unusual handshakes (syn,d) occurrences
// data struct flags_info
// count number of flows
// delay a detection delay
int
count_unusual_handshakes_syn (struct flags_info *data, int count, int delay)
{
  uint32_t srcaddress_andata;
  uint32_t dstaddress_andata;
  uint32_t srcaddress_ritorno;
  uint32_t dstaddress_ritorno;
  uint32_t first;
  int found = 0;
  int un_syn = 0;
  int i = 0;
  int j = 0;
  for (i = 0; i < count; i++)
    {
      srcaddress_andata = data[i].ip_src;
      dstaddress_andata = data[i].ip_dst;
      if (data[i].str_flag[4] == 'S' && data[i].str_flag[1] == '.')
	{
	  for (j = 0; j < count; j++)
	    {
	      srcaddress_ritorno = data[j].ip_src;
	      dstaddress_ritorno = data[j].ip_dst;
	      first = data[j].first;
	      if (srcaddress_ritorno == dstaddress_andata
		  && dstaddress_ritorno == srcaddress_andata)
		{
		  if ((data[j].str_flag[4] == 'S')
		      && (data[j].str_flag[1] == 'A') && (first > delay))
		    {
		      found = 1;
		    }
		}
	    }
	  if (found == 0)
	    un_syn++;
	}
      found = 0;
    }
  return un_syn;
}

// Computing unusual handshakes (syn(client,server),rst(server,client)) occurrences
// data struct flags_info
// count number of flows
int
count_unusual_handshakes_un_syn_rst_sc (struct flags_info *data, int count)
{
  uint32_t srcaddress_andata;
  uint32_t dstaddress_andata;
  uint32_t srcaddress_ritorno;
  uint32_t dstaddress_ritorno;
  int un_syn_rst_sc = 0;
  int i = 0;
  int j = 0;
  for (i = 0; i < count; i++)
    {
      srcaddress_andata = data[i].ip_src;
      dstaddress_andata = data[i].ip_dst;
      if (data[i].str_flag[4] == 'S' && data[i].str_flag[1] == '.')
	{
	  for (j = 0; j < count; j++)
	    {
	      srcaddress_ritorno = data[j].ip_src;
	      dstaddress_ritorno = data[j].ip_dst;
	      if (srcaddress_ritorno == dstaddress_andata
		  && dstaddress_ritorno == srcaddress_andata)
		{
		  if ((data[j].str_flag[3] == 'R'))
		    {
		      un_syn_rst_sc++;
		      break;
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
count_unusual_handshakes_un_syn_synack (struct flags_info *data, int count,
					int delay)
{
  uint32_t srcaddress_andata;
  uint32_t dstaddress_andata;
  uint32_t srcaddress_ritorno;
  uint32_t dstaddress_ritorno;
  uint32_t first;
  int un_syn_synack = 0;
  int i = 0;
  int j = 0;
  for (i = 0; i < count; i++)
    {
      srcaddress_andata = data[i].ip_src;
      dstaddress_andata = data[i].ip_dst;
      if (data[i].str_flag[4] == 'S' && data[i].str_flag[1] == '.')
	{
	  for (j = 0; j < count; j++)
	    {
	      srcaddress_ritorno = data[j].ip_src;
	      dstaddress_ritorno = data[j].ip_dst;
	      first = data[j].first;
	      if (srcaddress_ritorno == dstaddress_andata
		  && dstaddress_ritorno == srcaddress_andata)
		{
		  if ((data[j].str_flag[4] == 'S')
		      && (data[j].str_flag[1] == 'A') && (first > delay))
		    {
		      un_syn_synack++;
		      break;
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
count_unusual_handshakes_un_syn_synack_rst_cs (struct flags_info *data,
					       int count)
{
  uint32_t srcaddress_andata;
  uint32_t dstaddress_andata;
  uint32_t srcaddress_ritorno;
  uint32_t dstaddress_ritorno;
  uint32_t srcaddress_andata_1;
  uint32_t dstaddress_ritorno_1;
  int un_syn_synack_rst_cs = 0;
  int i = 0;
  int j = 0;
  int z = 0;
  for (i = 0; i < count; i++)
    {
      srcaddress_andata = data[i].ip_src;
      dstaddress_andata = data[i].ip_dst;
      if (data[i].str_flag[4] == 'S' && data[i].str_flag[1] == '.')
	{
	  for (j = 0; j < count; j++)
	    {
	      srcaddress_ritorno = data[j].ip_src;
	      dstaddress_ritorno = data[j].ip_dst;
	      if (srcaddress_ritorno == dstaddress_andata
		  && dstaddress_ritorno == srcaddress_andata)
		{
		  if ((data[j].str_flag[4] == 'S')
		      && (data[j].str_flag[1] == 'A'))
		    {
		      for (z = 0; z < count; z++)
			{
			  if (z != i && z != j)
			    {
			      srcaddress_andata_1 = data[z].ip_src;
			      dstaddress_ritorno_1 = data[z].ip_dst;
			      if (srcaddress_andata_1 == srcaddress_andata &&
				  dstaddress_ritorno_1 == dstaddress_andata)
				{
				  if ((data[z].str_flag[3] == 'R'))
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
    }
  return un_syn_synack_rst_cs;
}

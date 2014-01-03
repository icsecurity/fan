#include "frequency.h"
#include <stdlib.h>
#include <math.h>

// Compute the entropy using the frequency of data
// data --> frequency array of the symbols
// cnt_unique --> number of unique symbols
// cnt --> total number of symbols
float
compute_entropy (int *data, int cnt_unique, int cnt)
{
  float entropy_normal = 0.0;
  float probability = 0.0;
  int i = 0;
  for (i = 0; i < cnt_unique; i++)
    {
      probability = (float) data[i] / cnt;
      if (probability > 0.0)
	{
	  entropy_normal -=
	    probability * (float) (log ((double) probability) / log (2.0));
	}
    }
  return entropy_normal;
}

// Compare two IP Addresses
int
is_equal_ip (uint32_t s1, uint32_t s2)
{
  if (s1 == s2)
    return 1;
  else
    return 0;
}

// Compare two couple of IP Address and ports
int
is_equal_couple (uint32_t s1, uint32_t s2, uint16_t p1, uint16_t p2)
{
  if ((s1 == s2) && (p1 == p2))
    return 1;
  else
    return 0;
}

// Compare two couple of packets number and bytes number
int
is_equal_couple_64 (uint64_t s1, uint64_t s2, uint64_t p1, uint64_t p2)
{
  if ((s1 == s2) && (p1 == p2))
    return 1;
  else
    return 0;
}

// Compare two quadruple of source and destination address, source and destination ports
int
is_equal_quadruple (uint32_t s1, uint32_t s2, uint32_t d1, uint32_t d2,
		    uint16_t ps1, uint16_t ps2, uint16_t pd1, uint16_t pd2)
{
  if ((s1 == s2) && (d1 == d2) && (ps1 == ps2) && (pd1 == pd2))
    return 1;
  else
    return 0;
}

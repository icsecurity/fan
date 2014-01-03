//INCLUDE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#define MAX_NUM_SLOT 60
#define TIMESLOT_FLOWS_DIMENSION 20000000

#include "../config.h"

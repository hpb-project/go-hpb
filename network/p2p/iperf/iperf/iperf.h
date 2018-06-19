#ifndef        __IPERF_H
#define        __IPERF_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <iperf_api.h>

#ifdef __cplusplus
extern "C" { /* open extern "C" */
#endif

#define  IPERF_OK  0x00
#define  IPERF_ERR 0x10


int iperf_server(int port);
int iperf_test(char* host, int port);


#ifdef __cplusplus
} /* close extern "C" */
#endif

#endif /* !__IPERF_H */


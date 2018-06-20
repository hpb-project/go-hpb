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

#define  IPERF_TRUE        0x01
#define  IPERF_FALSE       0x00

#define  IPERF_OK          0x00
#define  IPERF_ERR         0x10
#define  IPERF_ERR_RUNNING 0x11
#define  IPERF_ERR_NEWTEST 0x10


int iperf_server_init(int port);
int iperf_server_start();
int iperf_server_stop();
int iperf_server_kill();


int iperf_test(char* host, int port);


#ifdef __cplusplus
} /* close extern "C" */
#endif

#endif /* !__IPERF_H */


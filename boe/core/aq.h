// Last Update:2018-06-20 19:59:06
/**
 * @file aq.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-20
 */

#ifndef AQ_H
#define AQ_H

#include <stdint.h>
typedef struct AQData{
    uint8_t *buf;
    int len;
}AQData;

typedef struct AtomicQ{
    AQData ** queue;
    uint64_t r_idx;
    uint64_t w_idx;
    uint64_t q_len;
}AtomicQ;


#endif  /*AQ_H*/

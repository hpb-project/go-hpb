// Last Update:2018-06-20 17:40:54
/**
 * @file wq.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-18
 */

#ifndef WQ_H
#define WQ_H

#include <stdint.h>

typedef int (*check_response)(uint8_t *res, int len, uint32_t uid);
typedef struct WMessage WMessage;
typedef void* Context_t;

WMessage* WMessageNew(uint32_t uid, check_response cfunc, uint32_t timeout);
uint8_t* WMessageWait(WMessage *m);
int WMessageFree(WMessage *m);

int wq_init(Context_t *ctx);
int wq_push(Context_t ctx, WMessage *m);
int wq_final(Context_t *ctx);


#endif  /*WQ_H*/

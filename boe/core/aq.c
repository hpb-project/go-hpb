#include <stdio.h>
#include <stdlib.h>
#include "aq.h"

AtomicQ* aq_new(uint64_t qlen)
{
    AtomicQ *q = (AtomicQ*)malloc(sizeof(AtomicQ));
    q->queue = (AQData**)malloc(qlen*sizeof(AQData*));
    q->q_len = qlen;
    q->w_idx = 0;
    q->r_idx = 0;
    return q;
}
int aq_empty(AtomicQ *q)
{
    return q->r_idx == q->w_idx ? 1 : 0;
}
int aq_full(AtomicQ *q)
{
    if(1 == ((q->r_idx + q->q_len - q->w_idx)%q->q_len))
        return 1;
    else 
        return 0;
}
int aq_push(AtomicQ *q, AQData *data)
{
    if(!aq_full(q))
    {
        uint64_t widx = q->w_idx;
        q->w_idx = (q->w_idx + 1) % q->q_len;
        q->queue[widx] = data;
        return 0;
    }
    else
    {
        return 1; // queue is full.
    }
}

AQData* aq_pop(AtomicQ *q)
{
    AQData *d = NULL;
    if(!aq_empty(q))
    {
        uint64_t r_idx = q->r_idx; 
        q->r_idx = (q->r_idx + 1) % q->q_len;
        d = q->queue[r_idx];
        q->queue[r_idx] = NULL;
    }
    return d;
}

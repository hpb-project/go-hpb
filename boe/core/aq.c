// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

#include <stdio.h>
#include <stdlib.h>
#include "aq.h"

AQData* aqd_new(int len)
{
    AQData *d = (AQData*)malloc(sizeof(AQData));
    if(d)
    {
        d->buf = (uint8_t*)malloc(len);
        d->len = len;
        if(! (d->buf))
        {
            free(d);
            d = NULL;
        }
    }
    return d;
}

int aqd_free(AQData *d)
{
    if(d)
    {
        if(d->buf)
            free(d->buf);
        free(d);
    }
    return 0;
}

int aq_init(AtomicQ *q, uint64_t qlen)
{
    q->queue = (AQData**)malloc(qlen*sizeof(AQData*));
    q->q_len = qlen;
    q->w_idx = 0;
    q->r_idx = 0;
    if(q->queue == NULL)
        return 1;

    return 0;
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

int aq_free(AtomicQ *q)
{
    AQData *d = NULL;
    while(d=aq_pop(q))
    {
        if(d->buf)
            free(d->buf);
        free(d);
    }
    return 0;
}

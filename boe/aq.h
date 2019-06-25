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
    uint64_t cycle;
}AtomicQ;

AQData* aqd_new(int len);
int aqd_free(AQData *d);
int aq_init(AtomicQ *q, uint64_t qlen);
int aq_free(AtomicQ *q);
int aq_empty(AtomicQ *q);
int aq_full(AtomicQ *q);
int aq_len(AtomicQ *q);
int aq_push(AtomicQ *q, AQData *data);
AQData* aq_pop(AtomicQ *q);
#endif  /*AQ_H*/

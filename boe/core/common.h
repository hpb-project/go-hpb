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


#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

typedef uint8_t TVersion;

typedef struct SignResult_t{
    uint8_t *r;
    uint8_t *s;
    uint8_t *v;
}SignResult_t;

typedef struct PublicKey_t{
    uint8_t* x;
    uint8_t* y;
}PublicKey_t;

PublicKey_t* new_pubkey(void);
void delete_pubkey(PublicKey_t *pub);
SignResult_t* new_signresult(void);
void delete_signresult(SignResult_t *result);
TVersion get_version_major(TVersion version);
TVersion get_version_min(TVersion version);
uint32_t checksum(uint8_t *data, uint32_t len);


#endif  /*COMMON_H*/

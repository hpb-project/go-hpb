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
#include <stdlib.h>
#include "type.h"


typedef struct SignResult_t{
    uint8_t *r;
    uint8_t *s;
    uint8_t *v;
}SignResult_t;

typedef struct PublicKey_t{
    uint8_t* x;
    uint8_t* y;
}PublicKey_t;

typedef enum UPGRADE_FLAG {
    UPGRADE_NONE = 0,
	UPGRADE_RECVING,
    UPGRADE_RECV_FIN,
    UPGRADE_ERASEING_FLASH,
    UPGRADE_WRITEING_FLASH,
	UPGRADE_WRITE_FLASH_FIN,
    UPGRADE_REBOOT = 0xA,
    UPGRADE_ABORT = 0xF,
}UPGRADE_FLAG;

typedef enum BlockDataUsage{
    BD_USE_START,
    BD_USE_UPGRADE_GOLDEN,
    BD_USE_UPGRADE_FW,
    BD_USE_END,
}BlockDataUsage;

#define vMajor(ver)	(ver&0xFF>>0x4)
#define vMinor(ver)	(ver&0xF)

PublicKey_t* new_pubkey(void);
void delete_pubkey(PublicKey_t *pub);
SignResult_t* new_signresult(void);
void delete_signresult(SignResult_t *result);
TVersion get_version_major(TVersion version);
TVersion get_version_min(TVersion version);
uint32_t checksum(uint8_t *data, uint32_t len);
uint64_t get_timestamp_us();


#endif  /*COMMON_H*/

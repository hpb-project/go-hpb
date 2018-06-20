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
#include <string.h>
#include <stdlib.h>
#include "tsu_connector.h"
#include "community.h"
#include "common.h"
#include "atomic.h"
#define TRACE() printf("func:%s,line:%d\n", __FUNCTION__, __LINE__)

typedef struct T_PACKAGE{
    uint32_t    sequence;           // package sequence id.
    uint8_t     version;            // protocol version.
    uint8_t     is_response;        // the package is request(0) or responsed(1).
    uint8_t     fragment_flag;      // 0: no fragment; 1: first fragment; 
                                    // 2: middle fragment; 3:last fragment.
    uint8_t     function_id;        // task type.
    uint16_t    reserved;           // reserved.
    uint16_t    length;             // payload data length.
    uint32_t    checksum;           // payload data checksum.
    uint8_t     payload[];          // payload data pointor.
}T_Package;

#define FUNCTION_ECSDA_SIGN 0x1 
#define FUNCTION_ECSDA_CHECK 0x2 
#define FUNCTION_SHA3_256 0x3 
#define FUNCTION_SHA3_512 0x4 
#define FUNCTION_AES256 0x5 
#define FUNCTION_RLP 0x6

static uint32_t  g_sequence = 0;
static const TVersion g_tsu_version = 0x10;

#define fetch_tsu_package_sequence() atomic_fetch_and_add(&g_sequence,1)

#define TSU_PAYLOAD_MAX_SIZE (65535)

static void tsu_init_package(T_Package *pack)
{
    pack->sequence = fetch_tsu_package_sequence();
    pack->version = g_tsu_version;
    pack->is_response = 0;
    pack->fragment_flag = 0;
}

int tsu_validate_sign(uint8_t *hash, uint8_t *r, uint8_t *s, uint8_t v, uint8_t *result)
{
    T_Package *pack = (T_Package*)malloc(sizeof(T_Package) + 32*3+ 1);
    if(pack == NULL)
        return -2;

    tsu_init_package(pack);
    pack->function_id = FUNCTION_ECSDA_CHECK;

    memcpy(pack->payload, hash, 32);
    pack->length = 32;

    memcpy(pack->payload + 32, r, 32);
    pack->length += 32;

    memcpy(pack->payload+64, s, 32);
    pack->length += 32;

    memcpy(pack->payload+3*32, &v, 1);
    pack->length += 1;
    pack->checksum = checksum(pack->payload, pack->length);

    // Todo: send request.
    if(pcie_write((uint8_t*)pack, pack->length + sizeof(T_Package)) < 0)
    {
        free(pack);
        return -3;
    }


    T_Package *res = (T_Package*)malloc(sizeof(T_Package) + 2*32);
    // Todo: get response.
    if(pcie_read((uint8_t*)res, sizeof(T_Package) + 2*32) < 0)
    {
        free(res);
        return -4;
    }
    memcpy(result, res->payload, 64);

    free(res);
    return 0;
}


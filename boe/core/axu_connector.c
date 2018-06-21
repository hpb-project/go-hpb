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
#include "axu_connector.h"
#include "community.h"
#include "atomic.h"

static uint16_t  g_sequence_id = 0;

#define fetch_axu_package_sequence() atomic_fetch_and_add(&g_sequence_id,1)

A_Package* axu_package_new(uint32_t len)
{
    if(len > PACKAGE_MAX_SIZE)
        return NULL;

    A_Package * pack = (A_Package*)malloc(len + sizeof(A_Package));
    if(pack != NULL)
        pack->header.body_length = len;

    return pack;
}

int axu_package_free(A_Package *pack)
{
	if(pack != NULL)
		free(pack);
	return 0;
}

int axu_package_len(A_Package *pack)
{
    return pack->header.body_length + sizeof(A_Package_Header);
}

void axu_package_init(A_Package *pack, A_Package* req, ACmd cmd)
{
    pack->header.magic_aacc = 0xaacc;
    pack->header.magic_ccaa = 0xccaa;
    pack->header.acmd = cmd;
    pack->checksum = 0;
    memset(pack->data, 0, pack->header.body_length);

    if(req){
        // is a response package.
        pack->header.package_id = req->header.package_id;
        pack->header.q_or_r = AP_RESPONSE;
    }else{
        pack->header.package_id = fetch_axu_package_sequence();
        pack->header.q_or_r = AP_QUERY;
    }
}

int axu_set_data(A_Package *pack, int offset, uint8_t *data, int len)
{
    if((offset + len) > pack->header.body_length){
        return 1;
    }
    memcpy(pack->data + offset, data, len);
    return 0;
}

void axu_finish_package(A_Package *pack)
{
    pack->checksum = checksum(pack->data, pack->header.body_length);
}


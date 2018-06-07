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


#include "common.h"
#include <stdio.h>
#include <stdlib.h>

#define get_major(version) (version>>0x4)
#define get_minor(version) (version&0x0f)

PublicKey_t* new_pubkey(void)
{
    PublicKey_t *pub = (PublicKey_t*)malloc(sizeof(PublicKey_t));
    return pub;
}
void delete_pubkey(PublicKey_t *pub)
{
    if(pub)
        free(pub);
}
SignResult_t* new_signresult(void)
{
    SignResult_t *result = (SignResult_t*)malloc(sizeof(SignResult_t));
    return result;
}
void delete_signresult(SignResult_t *result)
{
    if(result)
        free(result);
}

TVersion get_version_major(TVersion version)
{
    return get_major(version);
}
TVersion get_version_min(TVersion version)
{
    return get_minor(version);
}

uint32_t checksum(uint8_t *data, uint32_t len)
{
    uint32_t chk = 0;
    if(data != NULL && len > 0)
    {
        for(uint32_t i = 0;i < len; i++)
        {
            chk += data[i];
        }
    }
    return chk;
}

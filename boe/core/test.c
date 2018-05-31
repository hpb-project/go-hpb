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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef struct T_PACKAGE{
    uint32_t sequence;
    uint8_t version;
    uint8_t ask_or_request;
    uint8_t fragment_flag;
    uint8_t function_id;
    uint16_t reserved;
    uint16_t length;
    uint32_t checksum;
    uint8_t payload[];
}T_Package;


int main(int argc, char *argv[])
{
    printf("sizeof(T_Package)=%d\n", sizeof(T_Package));
    T_Package *p = (T_Package*)malloc(sizeof(T_Package)+100);

    return 0;
}

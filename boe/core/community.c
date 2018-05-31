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
#include "community.h"
/*
 * Just a empty function
 */

int pcie_read(uint8_t *p_buf, uint32_t len)
{
    memset(p_buf, 0xa1, len); 
    return 0;
}
int pcie_write(uint8_t *p_data, uint32_t len)
{
    return 0;
}
int pcie_reg_read(uint32_t reg_offset)
{
    return 0;
}
int pcie_reg_write(uint32_t reg_offset, RegWidth width, RegVal val)
{
    switch(width){
        case REG_WIDTH_8:
            val.b_val;
            break;
        case REG_WIDTH_16:
            val.h_val;
            break;
        case REG_WIDTH_32:
            val.w_val;
            break;
    }
    return 0;
}

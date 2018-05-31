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


#ifndef COMMUNITY_H
#define COMMUNITY_H

#include <stdint.h>

typedef enum RegWidth {
    REG_WIDTH_8,
    REG_WIDTH_16,
    REG_WIDTH_32
}RegWidth;

typedef union RegVal {
    uint32_t w_val;
    uint16_t h_val;
    uint8_t  b_val;
}RegVal;

int pcie_read(uint8_t *p_buf, uint32_t len);
int pcie_write(uint8_t *p_data, uint32_t len);
int pcie_reg_read(uint32_t reg_offset);
int pcie_reg_write(uint32_t reg_offset, RegWidth width, RegVal val);

#endif  /*COMMUNITY_H*/

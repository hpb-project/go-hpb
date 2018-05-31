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


#ifndef TSU_CONNECTOR_H
#define TSU_CONNECTOR_H

#include "common.h"

int tsu_validate_sign(uint8_t *hash, uint8_t *r, uint8_t *s, uint8_t v, uint8_t *result);
int tsu_hw_sign(uint8_t *info, int info_len, uint8_t *result);

#endif  /*TSU_CONNECTOR_H*/

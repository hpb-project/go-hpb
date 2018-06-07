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

#ifndef AXU_CONNECTOR_H
#define AXU_CONNECTOR_H
#include "common.h"

TVersion axu_get_hw_version(void);
TVersion axu_get_fw_version(void);
TVersion axu_get_axu_version(void);
uint32_t axu_get_random();
int      axu_get_boeid(uint32_t *p_id);
int      axu_set_boeid(uint32_t boeid);
int      axu_update(void);
int      axu_update_abort(void);

#endif  /*AXU_CONNECTOR_H*/

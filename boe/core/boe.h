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


#ifndef BOE_H
#define BOE_H

#include "common.h"

typedef enum BOE_ERR_ENUM{
    BOE_OK = 0,
}BOE_ERR_CODE;

int BOEInit(void);
int BOERelease(void);
int BOEBind(void);
TVersion GetBOEHWVersion(void);
TVersion GetBOEFWVersion(void);
TVersion GetBOEAXUVersion(void);
int BOEFWUpdate(void);
int BOEFWUpdateAbort(void);
int GetBOEID(void);
int SetBOEID(uint32_t id);
int BOEValidSign(uint8_t* hash, uint8_t* r, uint8_t* s, uint8_t v, uint8_t *result);
int GetRand(void);
int BOEHWSign(uint8_t *p_data, int datalen, uint8_t *result);
int BOESubscribeEvent(void);// go api.


#endif  /*BOE_H*/

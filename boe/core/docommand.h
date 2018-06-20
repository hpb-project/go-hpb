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

#ifndef DOCOMMAND_H
#define DOCOMMAND_H
#include "boe.h"
#include "axu_connector.h"

typedef int (*MsgHandle)(uint8_t *data, int len, void *userdata);
int doc_init(MsgHandle func, void *userdata);
int doc_release();
int doGetVersionInfo(TVersion *hw, TVersion *fw, TVersion *axu);
int doReset(void);
int doGetRandom(uint32_t *val);
int doGetBOEID(uint32_t *id);
int doGetHWVer(TVersion *hw);
int doGetFWVer(TVersion *fw);
int doGetAXUVer(TVersion *axu);
int doSetBoeID(uint32_t id);
int doBindAccount(uint8_t *baccount);
int doGetBindAccount(uint8_t *account_256);
int doHWSign(uint8_t *data, int len, uint8_t *result);
int doTransport(ImageHeader *info, uint8_t *data);
int doTransportStart(ImageHeader *info);
int doTransportMid(uint32_t fid, uint32_t offset, int len, uint8_t *data);
int doTransportFin(uint32_t fid, uint32_t offset, int len, uint8_t *data);
int doUpgradeStart(uint32_t fid);
int doUpgradeAbort(uint32_t fid);


#endif  /*DOCOMMAND_H*/

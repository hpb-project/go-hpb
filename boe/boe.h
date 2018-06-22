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
#include <stdint.h>


typedef struct BoeErr{
    int ecode;
    char emsg[100];
    uint8_t bfree;
}BoeErr;

BoeErr *BOE_OK;
typedef int (*BoeUpgradeCallback)(int,char*);
typedef int (*BoeRecoverPubCallback)(int,uint8_t*);
typedef uint8_t TVersion;

void boe_err_free(BoeErr *e);

BoeErr* boe_init(void);
BoeErr* boe_release(void);
BoeErr* boe_reg_update_callback(BoeUpgradeCallback func);
BoeErr* boe_reg_resign_callback(BoeRecoverPubCallback func);
BoeErr* boe_get_all_version(TVersion *hw, TVersion *fw, TVersion *axu);
BoeErr* boe_get_hw_version(TVersion *hw);
BoeErr* boe_get_fw_version(TVersion *fw);
BoeErr* boe_get_axu_version(TVersion *axu);
BoeErr* boe_upgrade(uint8_t *image, int imagelen);
BoeErr* boe_upgrade_abort(void);
BoeErr* boe_reset(void);
BoeErr* boe_set_boeid(uint32_t id);
BoeErr* boe_set_bind_account(uint8_t *baccount);
BoeErr* boe_get_random(uint32_t *val);
BoeErr* boe_get_boeid(uint32_t *id);
BoeErr* boe_get_bind_account(uint8_t *baccount);
BoeErr* boe_hw_sign(char *p_data, uint8_t *sig);
BoeErr* boe_get_s_random(uint8_t *hash, uint8_t *nexthash);
BoeErr* boe_valid_sign(uint8_t *sig, uint8_t *pub);

#endif  /*BOE_H*/

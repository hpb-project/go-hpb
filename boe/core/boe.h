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

typedef uint8_t TVersion;

typedef enum BOE_ERR_ENUM{
    BOE_OK = 0,
}BOE_ERR_CODE;

typedef int (*BoeUpgradeCallback)(int,char*);
typedef int (*BoeRecoverPubCallback)(int,uint8_t*);

int boe_init(void);
int boe_release(void);
int boe_reg_update_callback(BoeUpgradeCallback func);
int boe_reg_resign_callback(BoeRecoverPubCallback func);
int boe_get_all_version(TVersion *hw, TVersion *fw, TVersion *axu);
int boe_get_hw_version(TVersion *hw);
int boe_get_fw_version(TVersion *fw);
int boe_get_axu_version(TVersion *axu);
int boe_upgrade(uint8_t *image, int imagelen);
int boe_upgrade_abort(void);
int boe_reset(void);
int boe_set_boeid(uint32_t id);
int boe_set_bind_account(uint8_t *baccount);
int boe_get_random(uint32_t *val);
int boe_get_boeid(uint32_t *id);
int boe_get_bind_account(uint8_t *baccount);
int boe_hw_sign(char *p_data, uint8_t *sig);
int boe_get_s_random(uint8_t *hash, uint8_t *nexthash);
int boe_valid_sign(uint8_t *hash, uint8_t *r, uint8_t *s, uint8_t v);
int boe_valid_sign_sync(uint8_t* hash, uint8_t* r, uint8_t* s, uint8_t v, uint8_t *result);

#endif  /*BOE_H*/

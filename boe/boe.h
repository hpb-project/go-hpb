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
    unsigned char bfree;
}BoeErr;

BoeErr *BOE_OK;
typedef int (*BoeUpgradeCallback)(int,char*);
typedef int (*BoeValidSignCallback)(unsigned char *pub, unsigned char *sig, void *param, int param_len);

void boe_err_free(BoeErr *e);

BoeErr* boe_init(void);
BoeErr* boe_release(void);
BoeErr* boe_reg_update_callback(BoeUpgradeCallback func);
BoeErr* boe_get_hw_version(unsigned char *H);
BoeErr* boe_get_m_version(unsigned char *M);
BoeErr* boe_get_version(unsigned char *H, unsigned char *M, unsigned char *F, unsigned char *D);
BoeErr* boe_upgrade(unsigned char *image, int imagelen);
BoeErr* boe_upgrade_abort(void);
/*
 * check board is connected.
 */
BoeErr* boe_hw_check(void);
BoeErr* boe_hw_connect(void);
/*
 * let board reboot.
 */
BoeErr* boe_reboot(void);
/*
 * bind serial number to board.
 * in: 20 bytes serial number.
 */
BoeErr* boe_set_boesn(unsigned char *sn);
/*
 *
 * bind account to board.
 * in: 42 bytes account address.
 */
BoeErr* boe_set_bind_account(unsigned char *baccount);


/*
 * get random from board.
 * out: r, 32 bytes random.
 */
BoeErr* boe_get_random(unsigned char *r);

/*
 * get sn from board.
 * out: sn, 20 bytes sn.
 */
BoeErr* boe_get_boesn(unsigned char *sn);

/*
 * get account info from board.
 * out: account, 42 bytes account address.
 */
BoeErr* boe_get_bind_account(unsigned char *account);

/*
 * do signature for hardware authentication.
 * in: p_random, 32 bytes random
 * out: sig,    64 bytes signature.
 * return :
 *  BOE_OK is sign successed.
 *
 */
BoeErr* boe_hw_sign(unsigned char *p_random, unsigned char *sig);
/*
 * do signature verify.
 * p_random:    32 bytes random.
 * hid     :    string.
 * pubkey  :    64 bytes pubkey.
 * sig     :    64 bytes signature.
 *
 * return:
 *  BOE_OK is verify passed.
 *
 */
BoeErr* boe_p256_verify(unsigned char *p_random, unsigned char *hid, unsigned char *pubkey, unsigned char *sig);
/*
 * get a random for consensus.
 * in: hash, 32 bytes hash.
 * out: nexthash. 32 bytes hash.
 */
BoeErr* boe_get_s_random(unsigned char *hash, unsigned char *nexthash);
/*
 * The new version random hash, instead of boe_get_s_random.
 */ 
BoeErr* boe_get_n_random(unsigned char *hash, unsigned char *nexthash);
/*
 * recover pubkey. if boe board is working, use hardware to do it. else will use soft alghorim.
 */
BoeErr* boe_valid_sign(unsigned char *sig, unsigned char *pub);
BoeErr* boe_valid_sign_recover_pub_async(unsigned char *sig, unsigned char *param, int paramlen);
BoeErr* boe_valid_sign_callback(BoeValidSignCallback func);

#endif  /*BOE_H*/

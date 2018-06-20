// Last Update:2018-06-20 17:34:23
/**
 * @file nboe.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-19
 */
#include <stdio.h>
#include <string.h>
#include "genid.h"
#include "boe.h"
#include "common.h"
#include "wq.h"
#include "docommand.h"

struct BoeInstance {
    TVersion hw;
    TVersion fw;
    TVersion axu;
    uint8_t  bConnect;
    uint32_t updateFid;
    BoeUpgradeCallback updateCallback;
    BoeRecoverPubCallback revocerCallback;
};

static struct BoeInstance gIns;


static int msg_handle(uint8_t *data, int len, void *userdata)
{
    return 0;
}

static int connected(void)
{
    if(doGetVersionInfo(&gIns.hw, &gIns.fw, &gIns.axu) == 0)
    {
        gIns.bConnect = 1;
    }else
    {
        gIns.bConnect = 0;
    }
    return gIns.bConnect;
}

int boe_init(void)
{
    // pcie , init community.
    // create wq and init.
    // axu/tsu
    doc_init(msg_handle, (void*)&gIns);
    if(!connected())
    {
        return 1;
    }

    return BOE_OK;
}
int boe_release(void)
{
    // pcie, release pcie.
    doc_release();
    return BOE_OK;
}
int boe_reg_update_callback(BoeUpgradeCallback func)
{
    gIns.updateCallback = func;
    return BOE_OK;
}
int boe_reg_resign_callback(BoeRecoverPubCallback func)
{
    gIns.revocerCallback = func;
    return BOE_OK;
}

int boe_get_all_version(TVersion *hw, TVersion *fw, TVersion *axu)
{
    return doGetVersionInfo(hw, fw, axu);
}

int boe_get_hw_version(TVersion *hw)
{
    return doGetHWVer(hw);
}
int boe_get_fw_version(TVersion *fw)
{
    return doGetFWVer(fw);
}
int boe_get_axu_version(TVersion *axu)
{
    return doGetAXUVer(axu);
}

int boe_upgrade(uint8_t *image, int imagelen)
{
    ImageHeader header;
    int ret = 0;
    memcpy(&header, image, sizeof(header));
    if((memcmp(header.vendor, "hpb", 3) == 0)
            && (imagelen - sizeof(header) == header.len))
    {
        uint32_t chk = checksum(image+sizeof(header), header.len);
        if(chk != header.chk)
            return 1;
        
        ret = doTransport(&header, image+sizeof(header));
        if(ret != 0)
            return ret;
        ret = doUpgradeStart(header.chk);
        if(ret == 0)
        {
            gIns.updateFid = header.chk;
        }
    }
    else
    {
        return 1;
    }
    return ret;
}

int boe_upgrade_abort(void)
{
    return doUpgradeAbort(gIns.updateFid);
}
int boe_reset(void)
{
    return doReset();
}
int boe_set_boeid(uint32_t id)
{
    return doSetBoeID(id);
}
int boe_set_bind_account(uint8_t *baccount)
{
    return doBindAccount(baccount);
}

int boe_get_random(uint32_t *val)
{
    return doGetRandom(val);
}
int boe_get_boeid(uint32_t *id)
{
    return doGetBOEID(id);
}
int boe_get_bind_account(uint8_t *baccount)
{
    return doGetBindAccount(baccount);
}

int boe_hw_sign(char *p_data, uint8_t *sig)
{
    int len = strlen(p_data) + 2*32 + 1;
    char *p_buf = (char*)malloc(len);
    memset(p_buf, 0, len);
    if(0 == general_id(p_buf))
    {
        strcat(p_buf, p_data);
        return doHWSign((uint8_t*)p_buf, len, sig);
    }

    return 1;
}
/* -------------------  tsu command -------------------------*/
int boe_get_s_random(uint8_t *hash, uint8_t *nexthash)
{
    return BOE_OK;
}
int boe_valid_sign(uint8_t *hash, uint8_t *r, uint8_t *s, uint8_t v)
{
    return BOE_OK;
}
int boe_valid_sign_sync(uint8_t* hash, uint8_t* r, uint8_t* s, uint8_t v, uint8_t *result)
{
    return BOE_OK;
}

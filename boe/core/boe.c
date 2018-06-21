// Last Update:2018-06-21 16:27:17
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
#include "error.h"
#include "common.h"
#include "doAXU.h"

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

#define GetProgress(p)   (p->data[0])
#define GetProgressMsg(p) (p->data+1)
static int axu_msg_handle(uint8_t *data, int len, void *userdata)
{
    A_Package *p = (A_Package*)data;
    struct BoeInstance *ins = (struct BoeInstance*)userdata;
    if(p->header.magic_aacc == AXU_MAGIC_START &&
            p->header.magic_ccaa == AXU_MAGIC_END)
    {
        switch(p->header.acmd)
        {
            case ACMD_BP_RES_UPGRADE_PROGRESS:
                {
                    int progress = GetProgress(p);
                    char *msg    = GetProgressMsg(p);
                    if(ins->updateCallback != NULL)
                    {
                        ins->updateCallback(progress, msg);
                    }
                    break;
                }
            default:
                break;
        }
    }

    return 0;
}

static int connected(struct BoeInstance *ins)
{
    if(doAXU_GetVersionInfo(&ins->hw, &ins->fw, &ins->axu) == BOE_OK)
    {
        ins->bConnect = 1;
    }else
    {
        ins->bConnect = 0;
    }
    return ins->bConnect;
}

BoeErr* boe_init(void)
{
    // pcie , init community.
    // axu/tsu
    //doAXU_init(msg_handle, (void*)&gIns);
    if(!connected(&gIns))
    {
        return &e_init_fail;
    }

    return BOE_OK;
}
BoeErr* boe_release(void)
{
    doAXU_Release();
    // pcie, release pcie.
    return BOE_OK;
}
BoeErr* boe_reg_update_callback(BoeUpgradeCallback func)
{
    gIns.updateCallback = func;
    return BOE_OK;
}
BoeErr* boe_reg_resign_callback(BoeRecoverPubCallback func)
{
    gIns.revocerCallback = func;
    return BOE_OK;
}

BoeErr* boe_get_all_version(TVersion *hw, TVersion *fw, TVersion *axu)
{
    return doAXU_GetVersionInfo(hw, fw, axu);
}

BoeErr* boe_get_hw_version(TVersion *hw)
{
    return doAXU_GetHWVer(hw);
}
BoeErr* boe_get_fw_version(TVersion *fw)
{
    return doAXU_GetFWVer(fw);
}
BoeErr* boe_get_axu_version(TVersion *axu)
{
    return doAXU_GetAXUVer(axu);
}

BoeErr* boe_upgrade(uint8_t *image, int imagelen)
{
    ImageHeader header;
    BoeErr* ret = NULL;
    memcpy(&header, image, sizeof(header));
    if((memcmp(header.vendor, "hpb", 3) == 0)
            && (imagelen - sizeof(header) == header.len))
    {
        uint32_t chk = checksum(image+sizeof(header), header.len);
        if(chk != header.chk)
            return &e_image_chk_error;
        
        ret = doAXU_Transport(&header, image+sizeof(header));
        if(ret != BOE_OK)
            return ret;
        ret = doAXU_UpgradeStart(header.chk);
        if(ret == BOE_OK)
        {
            gIns.updateFid = header.chk;
        }
    }
    else
    {
        return &e_image_header_error;
    }
}

BoeErr* boe_upgrade_abort(void)
{
    return doAXU_UpgradeAbort(gIns.updateFid);
}
BoeErr* boe_reset(void)
{
    return doAXU_Reset();
}
BoeErr* boe_set_boeid(uint32_t id)
{
    return doAXU_SetBoeID(id);
}
BoeErr* boe_set_bind_account(uint8_t *baccount)
{
    return doAXU_BindAccount(baccount);
}

BoeErr* boe_get_random(uint32_t *val)
{
    return doAXU_GetRandom(val);
}
BoeErr* boe_get_boeid(uint32_t *id)
{
    return doAXU_GetBOEID(id);
}
BoeErr* boe_get_bind_account(uint8_t *baccount)
{
    return doAXU_GetBindAccount(baccount);
}

BoeErr* boe_hw_sign(char *p_data, uint8_t *sig)
{
    int len = strlen(p_data) + 2*32 + 1;
    char *p_buf = (char*)malloc(len);
    memset(p_buf, 0, len);
    if(0 == general_id(p_buf))
    {
        strcat(p_buf, p_data);
        return doAXU_HWSign((uint8_t*)p_buf, len, sig);
    }
    return &e_gen_host_id_failed;
}
/* -------------------  tsu command -------------------------*/
BoeErr* boe_get_s_random(uint8_t *hash, uint8_t *nexthash)
{
    return BOE_OK;
}
BoeErr* boe_valid_sign(uint8_t *hash, uint8_t *r, uint8_t *s, uint8_t v)
{
    return BOE_OK;
}
BoeErr* boe_valid_sign_sync(uint8_t* hash, uint8_t* r, uint8_t* s, uint8_t v, uint8_t *result)
{
    return BOE_OK;
}

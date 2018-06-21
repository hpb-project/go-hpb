#include <string.h>
#include "docommand.h"
#include "common.h"
#include "msgc.h"
#include "axu_connector.h"
#include "community.h"
#include "error.h"

static int gShortTimeout = 100000; // 100ms
static int gLongTimeout = 5000000; // 5s

static MsgContext wqc;
#define PSetData(p, o, v) \
    {\
        axu_set_data(p, o, (uint8_t*)&(v), sizeof(v));\
        o += sizeof(v);\
    }

#define PSetDataLen(p, o, v, l) \
    {\
        axu_set_data(p, o, (uint8_t*)&(v), l);\
        o += l;\
    }

static int axu_check_response(uint8_t* data, int plen, uint32_t uid);

static inline int isAck(A_Package *p)
{
    return p->header.acmd == ACMD_BP_RES_ACK;
}
static inline int isErr(A_Package *p)
{
    return p->header.acmd == ACMD_BP_RES_ERR;
}

static BoeErr* get_error(A_Package *p)
{
    int ecode = p->data[0];
    BoeErr *ret = NULL;
    if(ecode < MAX_AXU_ERRNUM)
    {
        ret = &e_axu_inner[ecode];
        ret->bfree = 0;
    }
    else
    {
        ret = (BoeErr*)malloc(sizeof(BoeErr));
        ret->bfree = 1;
    }
    ret->ecode = p->data[0];
    strncpy(ret->emsg, (char*)(p->data+1), sizeof(ret->emsg)-1);
    return ret;
}
static BoeErr* doCommand(A_Package *p, AQData **d)
{
    BoeErr *ret = NULL;
    WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
    if(msgc_send(&wqc, wm) == 0)
    {
        AQData *q = msgc_read(&wqc, wm);
        if(q == NULL || q->buf == NULL)
            return &e_msgc_read_timeout;
        A_Package *r = (A_Package*)q->buf;
        if(isErr(r))
        {
            ret = get_error(r);
            aqd_free(q);
            return ret;
        }
        else
        {
            *d = q;
            return &e_ok;
        }
    }
    else
        return &e_msgc_send_fail;
}

static A_Package* make_query_simple(ACmd cmd)
{
    A_Package *p = axu_package_new(0);
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_ts_start(ACmd cmd, uint8_t usage, uint32_t fid, uint32_t chk,
        uint32_t len, TVersion hw, TVersion fw, TVersion axu)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, usage);
        PSetData(p, offset, fid);
        PSetData(p, offset, chk);
        PSetData(p, offset, len);
        PSetData(p, offset, hw);
        PSetData(p, offset, fw);
        PSetData(p, offset, axu);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_ts_mid(ACmd cmd, uint32_t fid, uint16_t doffset, uint32_t len, uint8_t *data)
{
    int offset = 0;
    A_Package *p = axu_package_new(PACKAGE_MAX_SIZE);

    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, fid);
        PSetData(p, offset, doffset);
        PSetData(p, offset, len);
        PSetDataLen(p, offset, data, len);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_ts_fin(ACmd cmd, uint32_t fid, uint16_t doffset, uint32_t len, uint8_t *data)
{
    A_Package *p = axu_package_new(PACKAGE_MAX_SIZE);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, fid);
        PSetData(p, offset, doffset);
        PSetData(p, offset, len);
        PSetDataLen(p, offset, data, len);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_upgrade_start(ACmd cmd, uint32_t fid)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, fid);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_upgrade_abort(ACmd cmd, uint32_t fid)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, fid);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_set_boeid(ACmd cmd, uint32_t id)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, id);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_bind_account(ACmd cmd, uint8_t *baccount)
{
    A_Package *p = axu_package_new(256);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, baccount, 256);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_hwsign(ACmd cmd, uint8_t *data, uint32_t len)
{
    A_Package *p = axu_package_new(len);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, data, len);

        axu_finish_package(p);
    }
    return p;
}

int axu_check_response(uint8_t* data, int plen, uint32_t uid)
{
    if(plen >= sizeof(A_Package))
    {
        A_Package *p = (A_Package*)data;
        if(p->header.package_id == uid && p->header.q_or_r == AP_RESPONSE)
            return 1;
    }
    return 0;
}



#define BPGetHWVersion(p)  (p->data[0])
#define BPGetFWVersion(p)  (p->data[1])
#define BPGetAXUVersion(p)  (p->data[2])
BoeErr* doAXU_GetVersionInfo(TVersion *hw, TVersion *fw, TVersion *axu)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_VERSION_INFO);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);

            *hw = BPGetHWVersion(q);
            *fw = BPGetFWVersion(q);
            *axu = BPGetAXUVersion(q);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}


BoeErr* doAXU_Reset(void)
{
    A_Package *p = make_query_simple(ACMD_PB_RESET);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}


#define GetRandom(p)       (*((uint32_t*)p->data))
BoeErr* doAXU_GetRandom(uint32_t *val)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_RANDOM);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            *val = GetRandom(q);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

#define GetBOEID(p)       (*((uint32_t*)p->data))
BoeErr* doAXU_GetBOEID(uint32_t *id)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_BOEID);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            *id = GetBOEID(q);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_GetSingleVer(TVersion *v, ACmd cmd)
{
    A_Package *p = make_query_simple(cmd);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            *v = (*((TVersion*)(q->data)));
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

#define GetBindAccount(p)   (p->data)
BoeErr* doAXU_GetBindAccount(uint8_t *account_256)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_BINDINFO);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            memcpy(account_256, q->data, 256);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}
BoeErr* doAXU_GetHWVer(TVersion *hw)
{
    return doAXU_GetSingleVer(hw, ACMD_PB_GET_HW_VER);
}

BoeErr* doAXU_GetFWVer(TVersion *fw)
{
    return doAXU_GetSingleVer(fw, ACMD_PB_GET_FW_VER);
}

BoeErr* doAXU_GetAXUVer(TVersion *axu)
{
    return doAXU_GetSingleVer(axu, ACMD_PB_GET_AXU_VER);
}

BoeErr* doAXU_SetBoeID(uint32_t id)
{
    A_Package *p = make_query_set_boeid(ACMD_PB_SET_BOEID, id);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_BindAccount(uint8_t *baccount)
{
    A_Package *p = make_query_bind_account(ACMD_PB_BIND_ACCOUNT, baccount);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_HWSign(uint8_t *data, int len, uint8_t *result)
{
    A_Package *p = make_query_hwsign(ACMD_PB_HW_SIGN, data, len);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            // get sign r, s, v.
            A_Package *q = (A_Package*)r->buf;
            if(q->header.body_length >= 65)
            {
                memcpy(result, q->data, 65);
                aqd_free(r);
                return &e_ok;
            }
            else
            {
                aqd_free(r);
                return &e_result_invalid;
            }
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_TransportStart(ImageHeader *info)
{
    A_Package *p = make_query_ts_start(ACMD_PB_TRANSPORT_START, info->usage, 
            info->chk, info->chk, info->len, info->hw, info->fw, info->axu);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

#define TransMidFidOffset()   (0)
#define TransMidOffsetOffset()   (4)
#define TransMidDataOffset()   (6)
BoeErr* doAXU_TransportMid(uint32_t fid, uint32_t offset, int len, uint8_t *data)
{
    A_Package *p = make_query_ts_mid(ACMD_PB_TRANSPORT_MIDDLE, fid, offset, len, data);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_TransportFin(uint32_t fid, uint32_t offset, int len, uint8_t *data)
{
    A_Package *p = make_query_ts_fin(ACMD_PB_TRANSPORT_FINISH, fid, offset, len, data);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Transport(ImageHeader *info, uint8_t *data)
{
    BoeErr *ret = NULL;
    ret = doAXU_TransportStart(info);
    if(ret == &e_ok)
    {
        uint16_t offset = 0;
        int plen = 0, pmaxlen = PACKAGE_MAX_SIZE - TransMidDataOffset(); 
        while(1)
        {
            plen = info->len - offset;
            if(plen > pmaxlen)
            {
                ret = doAXU_TransportMid(info->chk, offset, pmaxlen, data+offset);
                offset += pmaxlen;
                if(ret != &e_ok)
                    break;
            }
            else
            {
                ret = doAXU_TransportFin(info->chk, offset, plen, data+offset);
                offset += plen;
                break;
            }
        }
        return ret;
    }
    return ret;
}

BoeErr* doAXU_UpgradeStart(uint32_t fid)
{
    A_Package *p = make_query_upgrade_start(ACMD_PB_UPGRADE_START, fid);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}


BoeErr* doAXU_UpgradeAbort(uint32_t fid)
{
    A_Package *p = make_query_upgrade_abort(ACMD_PB_UPGRADE_ABORT, fid);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}


BoeErr* doAXU_Init(char *r_devname, char *w_devname, MsgHandle msghandle, void*userdata)
{
    int ret = msgc_init(&wqc, r_devname, w_devname, msghandle, userdata);
    if(ret != 0)
        return &e_init_fail;
    return &e_ok;
}

BoeErr* doAXU_Release()
{
    msgc_release(&wqc);
    return &e_ok;
}

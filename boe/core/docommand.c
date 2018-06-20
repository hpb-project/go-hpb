// Last Update:2018-06-20 17:39:26
/**
 * @file docommand.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-18
 */

#include <string.h>
#include "docommand.h"
#include "common.h"
#include "wq.h"
#include "axu_connector.h"
#include "community.h"

static int gShortTimeout = 100000; // 100ms
static int gLongTimeout = 5000000; // 5s

static Context_t wqc;

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

static A_Package* make_query_simple(ACmd cmd)
{
    A_Package *p = (A_Package*)malloc(sizeof(A_Package));
    if(p)
    {
        p->header.body_length = 0;
        axu_package_init(p, NULL, cmd);
        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_ts_start(ACmd cmd, uint8_t usage, uint32_t fid, uint32_t chk,
        uint32_t len, TVersion hw, TVersion fw, TVersion axu)
{
    A_Package *p = axu_package_new(PACKAGE_MIN_SIZE);
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

static A_Package* make_query_ts_mid(ACmd cmd, uint32_t fid, uint16_t doffset, int len, uint8_t *data)
{
    A_Package *p = axu_package_new(PACKAGE_MAX_SIZE);
    int offset = 0;
    int maxlen = p->header.body_length - sizeof(fid) - sizeof(doffset);
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, fid);
        PSetData(p, offset, doffset);
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
    A_Package *p = axu_package_new(PACKAGE_MIN_SIZE);
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
    A_Package *p = axu_package_new(PACKAGE_MIN_SIZE);
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
    A_Package *p = axu_package_new(PACKAGE_MIN_SIZE);
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
    A_Package *p = axu_package_new(256 + sizeof(A_Package));
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        axu_set_data(p, offset, baccount, 256);
        offset += 256;

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_hwsign(ACmd cmd, uint8_t *data, int len)
{
    A_Package *p = axu_package_new(len + sizeof(A_Package));
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        axu_set_data(p, offset, data, len);
        offset += len;

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

static inline int isAck(A_Package *p)
{
    return p->header.acmd == ACMD_BP_RES_ACK;
}
static inline int isErr(A_Package *p)
{
    return p->header.acmd == ACMD_BP_RES_ERR;
}
struct BoeErr{
    int errCode;
    char errMsg[100];
};
static inline int getErr(A_Package *p, struct BoeErr *err)
{
    err->errCode = p->data[0];
    strncpy(err->errMsg, (char*)(p->data+1), 90);
    return 0;
}


#define BPGetHWVersion(p)  (p->data[0])
#define BPGetFWVersion(p)  (p->data[1])
#define BPGetAXUVersion(p)  (p->data[2])
int doGetVersionInfo(TVersion *hw, TVersion *fw, TVersion *axu)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_VERSION_INFO);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response.
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            *hw = BPGetHWVersion(r);
            *fw = BPGetFWVersion(r);
            *axu = BPGetAXUVersion(r);
            return 0;
        }
    }
    return 1;
}


int doReset(void)
{
    A_Package *p = make_query_simple(ACMD_PB_RESET);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // have no response.
        return 0;
    }
    return 1;
}


#define GetRandom(p)       (*((uint32_t*)p->data))
int doGetRandom(uint32_t *val)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_RANDOM);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            *val = GetRandom(r);
            return 0;
        }
    }
    return 1;
}

#define GetBOEID(p)       (*((uint32_t*)p->data))
int doGetBOEID(uint32_t *id)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_BOEID);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            *id = GetBOEID(r);
            return 0;
        }
    }
    return 1;
}

int doGetSingleVer(TVersion *v, ACmd cmd)
{
    A_Package *p = make_query_simple(cmd);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            *v = (*((TVersion*)(r->data)));
            return 0;
        }
    }
    return 1;
}

#define GetBindAccount(p)   (p->data)
int doGetBindAccount(uint8_t *account_256)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_BINDINFO);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            memcpy(account_256, GetBindAccount(r), 256);
            return 0;
        }
    }
    return 1;
}
int doGetHWVer(TVersion *hw)
{
    return doGetSingleVer(hw, ACMD_PB_GET_HW_VER);
}

int doGetFWVer(TVersion *fw)
{
    return doGetSingleVer(fw, ACMD_PB_GET_FW_VER);
}

int doGetAXUVer(TVersion *axu)
{
    return doGetSingleVer(axu, ACMD_PB_GET_AXU_VER);
}

int doSetBoeID(uint32_t id)
{
    A_Package *p = make_query_set_boeid(ACMD_PB_SET_BOEID, id);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            return 0;
        }
    }
    return 1;
}

int doBindAccount(uint8_t *baccount)
{
    A_Package *p = make_query_bind_account(ACMD_PB_BIND_ACCOUNT, baccount);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            return 0;
        }
    }
    return 1;
}

int doHWSign(uint8_t *data, int len, uint8_t *result)
{
    A_Package *p = make_query_hwsign(ACMD_PB_HW_SIGN, data, len);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            // get sign r.
            // get sign s.
            // get sign v.
            return 0;
        }
    }
    return 1;
}

int doTransportStart(ImageHeader *info)
{
    A_Package *p = make_query_ts_start(ACMD_PB_TRANSPORT_START, info->usage, info->chk, info->chk, info->len, info->hw, info->fw, info->axu);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            return 0;
        }
    }
    return 1;
}

#define TransMidFidOffset()   (0)
#define TransMidOffsetOffset()   (4)
#define TransMidDataOffset()   (6)
int doTransportMid(uint32_t fid, uint32_t offset, int len, uint8_t *data)
{
    A_Package *p = make_query_ts_mid(ACMD_PB_TRANSPORT_MIDDLE, fid, offset, len, data);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            return 0;
        }
    }
    return 1;
}

int doTransportFin(uint32_t fid, uint32_t offset, int len, uint8_t *data)
{
    A_Package *p = make_query_ts_fin(ACMD_PB_TRANSPORT_FINISH, fid, offset, len, data);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            return 0;
        }
    }
    return 1;
}

int doTransport(ImageHeader *info, uint8_t *data)
{
    int ret = doTransportStart(info);
    if(ret == 0)
    {
        uint16_t offset = 0;
        int plen = 0, pmaxlen = PACKAGE_MAX_SIZE - sizeof(A_Package) - TransMidDataOffset(); 
        while(1)
        {
            plen = info->len - offset;
            if(plen > pmaxlen)
            {
                ret = doTransportMid(info->chk, offset, pmaxlen, data+offset);
                offset += pmaxlen;
                if(ret != 0)
                    break;
            }
            else
            {
                ret = doTransportFin(info->chk, offset, plen, data+offset);
                offset += plen;
                break;
            }
        }
        return ret;
    }
}
int doUpgradeStart(uint32_t fid)
{
    A_Package *p = make_query_upgrade_start(ACMD_PB_UPGRADE_START, fid);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            return 0;
        }
    }
    return 1;
}

int doUpgradeAbort(uint32_t fid)
{
    A_Package *p = make_query_upgrade_start(ACMD_PB_UPGRADE_ABORT, fid);
    if(p)
    {
        WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout);
        wq_push(wqc, wm);
        // Todo: send msg.
        pcie_write((uint8_t*)p, axu_package_len(p));
        // wait response
        A_Package *r = (A_Package*)WMessageWait(wm);
        if(r!=NULL && isAck(r))
        {
            return 0;
        }
    }
    return 1;
}

int doc_init(MsgHandle func, void *userdata)
{
    wq_init(&wqc);
    return 0;
}

int doc_release()
{
    wq_final(&wqc);
    return 0;
}

// Last Update:2018-05-24 15:23:18
/**
 * @file boe.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-22
 */

#include "boe.h"
#include "common.h"
#include "tsu_connector.h"


typedef struct boe_handle_t{
    void *handle;
}boe_handle_t;

int BOEInit(void)
{
    // pcie init.
    return BOE_OK;
}

int BOERelease(void)
{
    // release resource.
    return BOE_OK;
}
int BOEBind(void)
{
    // 绑定过程：
    // 通过工具扫描主机的ssd，ddr，cpu等信息，符合需求则往下走，否则退出，不能
    // 进行绑定；
    // 扫描主机的主板型号/网卡地址，也可以再加上账户地址，通过固定算法算的一个
    // id,将以上内容存到文件中然后发送到hpb.
    //
    // 验证过程：
    // 通过上述方法再次获得id与板卡内的id进行比较。
    return BOE_OK;
}
TVersion GetBOEHWVersion(void)
{
    return tsu_get_hw_version();
}
TVersion GetBOEFWVersion(void)
{
    return tsu_get_fw_version();
}
int BOEFWUpdate(void)
{
    // todo.
    return BOE_OK;
}
int BOEFWUpdateAbort(void)
{
    // todo.
    return BOE_OK;
}
int GetBOEID(void)
{
    return tsu_get_boeid();
}
int SetBOEID(uint32_t id)
{
    return tsu_set_boeid(id);
}
int BOEValidateSign()
{
    return BOE_OK;
}
int GetRand(void)
{
    return BOE_OK;
}

int BOEHWSign(uint8_t *p_data, int datalen, sign_result_t *result)
{
    return tsu_hw_sign(p_data, datalen, result);
}

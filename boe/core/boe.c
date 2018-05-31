// Last Update:2018-05-29 11:27:54
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
#include "axu_connector.h"
#include <stdio.h>
#include <string.h>


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
    return axu_get_hw_version();
}

TVersion GetBOEFWVersion(void)
{
    return axu_get_fw_version();
}

TVersion GetBOEAXUVersion(void)
{
    return axu_get_axu_version();
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
    uint32_t id = 0;
    return axu_get_boeid(&id);
}

int SetBOEID(uint32_t id)
{
    return axu_set_boeid(id);
}

int BOEValidSign(uint8_t* hash, uint8_t* r, uint8_t* s, uint8_t v, PublicKey_t *result)
{
    //printf("hash = 0x%p, r = 0x%p, s = 0x%p\n", hash, r, s);
    //int i = 0;
    //for(i = 0; i < 32; i++)
    //{
    //    printf("hash[%d] = 0x%x.\n", i , hash[i]);
    //    printf("r[%d] = 0x%x.\n", i , r[i]);
    //    printf("s[%d] = 0x%x.\n", i , s[i]);
    //}
    //memset(result->x, 0xa1, 32);
    //memset(result->y, 0xb1, 32);
    tsu_validate_sign(hash, r, s, v, result);
    return BOE_OK;
}
int GetRand(void)
{
    return axu_get_random();
}

int BOEHWSign(uint8_t *p_data, int datalen, uint8_t *result)
{
    return tsu_hw_sign(p_data, datalen, result);
}

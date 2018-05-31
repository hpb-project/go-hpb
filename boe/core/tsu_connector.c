// Last Update:2018-05-31 14:54:18
/**
 * @file tsu_connector.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-23
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tsu_connector.h"
#include "community.h"
#include "common.h"
#include "atomic.h"
#define TRACE() printf("func:%s,line:%d\n", __FUNCTION__, __LINE__)

typedef struct T_PACKAGE{
    uint32_t    sequence;           // package sequence id.
    uint8_t     version;            // protocol version.
    uint8_t     is_response;        // the package is request(0) or responsed(1).
    uint8_t     fragment_flag;      // 0: no fragment; 1: first fragment; 
                                    // 2: middle fragment; 3:last fragment.
    uint8_t     function_id;        // task type.
    uint16_t    reserved;           // reserved.
    uint16_t    length;             // payload data length.
    uint32_t    checksum;           // payload data checksum.
    uint8_t     payload[];          // payload data pointor.
}T_Package;

#define FUNCTION_ECSDA_SIGN 0x1 
#define FUNCTION_ECSDA_CHECK 0x2 
#define FUNCTION_SHA3_256 0x3 
#define FUNCTION_SHA3_512 0x4 
#define FUNCTION_AES256 0x5 
#define FUNCTION_RLP 0x6

static uint32_t  g_sequence = 0;
static const TVersion g_tsu_version = 0x10;

#define fetch_tsu_package_sequence() atomic_fetch_and_add(&g_sequence,1)

#define TSU_PAYLOAD_MAX_SIZE (65535)

static void tsu_init_package(T_Package *pack)
{
    pack->sequence = fetch_tsu_package_sequence();
    pack->version = g_tsu_version;
    pack->is_response = 0;
    pack->fragment_flag = 0;
}

int tsu_validate_sign(uint8_t *hash, uint8_t *r, uint8_t *s, uint8_t v, PublicKey_t *result)
{
    T_Package *pack = (T_Package*)malloc(sizeof(T_Package) + 32*3+ 1);
    if(pack == NULL)
        return -2;

    tsu_init_package(pack);
    pack->function_id = FUNCTION_ECSDA_CHECK;

    memcpy(pack->payload, hash, 32);
    pack->length = 32;

    memcpy(pack->payload + 32, r, 32);
    pack->length += 32;

    memcpy(pack->payload+64, s, 32);
    pack->length += 32;

    memcpy(pack->payload+3*32, &v, 1);
    pack->length += 1;
    pack->checksum = checksum(pack->payload, pack->length);

    // Todo: send request.
    if(pcie_write((uint8_t*)pack, pack->length + sizeof(T_Package)) < 0)
    {
        free(pack);
        return -3;
    }


    T_Package *res = (T_Package*)malloc(sizeof(T_Package) + 2*32);
    // Todo: get response.
    if(pcie_read((uint8_t*)res, sizeof(T_Package) + 2*32) < 0)
    {
        free(res);
        return -4;
    }
    memcpy(result->x, res->payload, 32);
    memcpy(result->y, res->payload+32, 32);

    free(res);
    return 0;
}

int tsu_hw_sign(uint8_t *info, int info_len, uint8_t *result)
{
    if(info_len > TSU_PAYLOAD_MAX_SIZE)
        return -1;
    T_Package *pack = (T_Package*)malloc(sizeof(T_Package) + info_len);
    if(pack == NULL)
        return -2;
    tsu_init_package(pack);
    pack->function_id = FUNCTION_ECSDA_SIGN;
    memcpy(pack->payload, info, info_len);
    pack->length = info_len;
    pack->checksum = checksum(pack->payload, pack->length);

    // Todo: send request.
    if(pcie_write((uint8_t*)pack, info_len + sizeof(T_Package)) < 0)
    {
        free(pack);
        return -3;
    }

    // Todo: get response.
    T_Package *res = (T_Package*)malloc(sizeof(T_Package) + 2*32+1);
    if(pcie_read((uint8_t*)res, sizeof(T_Package) + 2*32+1) < 0)
    {
        free(res);
        return -4;
    }
    memcpy(result, res->payload, 32);

    free(res);
    return 0;
}

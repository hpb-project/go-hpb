// Last Update:2018-05-25 21:16:17
/**
 * @file axu_connector.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-24
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "axu_connector.h"
#include "community.h"
#include "atomic.h"

typedef struct A_PACKAGE_HEADER {
    uint16_t magic_aacc;
    uint16_t package_id;
    uint16_t body_length;
    uint8_t  acmd;
    uint8_t  reserved;
    uint16_t magic_ccaa;
}A_Package_Header;

typedef struct A_PACKAGE{
    A_Package_Header header;
    uint32_t    checksum;
    uint8_t     data[];
}A_Package;

typedef enum A_CMD {
    ACMD_START = 0x0,
    ACMD_PB_GET_VERSION_INFO    = 0x01,
    ACMD_PB_TRANSPORT_START     = 0x02,
    ACMD_PB_TRANSPORT_MIDDLE    = 0x03,
    ACMD_PB_TRANSPORT_FINISH    = 0x04,
    ACMD_PB_UPGRADE_START       = 0x05,
    ACMD_PB_UPGRADE_ABORT       = 0x06,
    ACMD_PB_RESET               = 0x07,
    ACMD_PB_RANDOM              = 0x08,
    ACMD_PB_GET_BOEID           = 0x09,
    ACMD_PB_GET_HW_VER          = 0x0A,
    ACMD_PB_GET_FW_VER          = 0x0B,
    ACMD_PB_GET_AXU_VER         = 0x0C,

    ACMD_BP_RES_ACK             = 0x51,
    ACMD_BP_RES_VERSION         = 0x52,
    ACMD_BP_RES_UPGRADE_PROGRESS= 0x53,
    ACMD_BP_RES_ERR             = 0x54,
    ACMD_BP_RES_RANDOM          = 0x55,
    ACMD_BP_RES_BOEID           = 0x56,
    ACMD_BP_RES_HW_VER          = 0x57,
    ACMD_BP_RES_FW_VER          = 0x58,
    ACMD_BP_RES_AXU_VER         = 0x59,


    ACMD_END                    = 0xff,
}ACmd;

static uint32_t  g_sequence_id = 0;
#define MAX_PACKAGE_LENGTH (2048+sizeof(A_Package))

#define fetch_axu_package_sequence() atomic_fetch_and_add(&g_sequence_id,1)

static void axu_init_package(A_Package *pack)
{
    pack->header.magic_aacc = 0xaacc;
    pack->header.package_id = fetch_axu_package_sequence();
    pack->header.body_length = 0;
    pack->header.magic_ccaa = 0xccaa;
    pack->header.acmd = ACMD_END;
    pack->checksum = 0;

}
static void finish_package(A_Package *pack)
{
    if(pack->header.body_length > 0)
    {
        pack->checksum = checksum(pack->data, pack->header.body_length);
    }
}

static int package_send(A_Package *package)
{
    if(package == NULL)
        return -1;
    int ret = pcie_write((uint8_t *)package, sizeof(A_Package)+package->header.body_length);
    if(ret > 0)
        return 0;
    return ret;
}

static int package_receive(A_Package *package)
{
    A_Package *p = NULL;
    uint8_t data[MAX_PACKAGE_LENGTH];
    int ret = pcie_read(data, sizeof(data));
    p = (A_Package*) data;
    if (p->header.magic_aacc == 0xAACC &&
            p->header.magic_ccaa == 0xCCAA)
    {
        if(p->header.body_length > 0 && 
            p->header.body_length < (MAX_PACKAGE_LENGTH-sizeof(A_Package)))
        {
            uint32_t s_chk = p->checksum;
            uint32_t d_chk = checksum(p->data, p->header.body_length);
            if(s_chk == d_chk)
            {
                memcpy(package, p, sizeof(A_Package)+p->header.body_length);
                return 0;
            }
        }
        else if (p->header.body_length == 0)
        {
            memcpy(package, p, sizeof(A_Package));
            return 0;
        }
    }
    return -3;
}



uint32_t axu_get_random()
{
    uint32_t random = 0;
    A_Package package;
    axu_init_package(&package);
    package.header.acmd = ACMD_PB_RANDOM;
    package_send(&package);
    A_Package *r_pack = (A_Package *)malloc(MAX_PACKAGE_LENGTH);
    memset(r_pack, 0x0, MAX_PACKAGE_LENGTH);
    if(package_receive(r_pack)
            && (r_pack->header.acmd == ACMD_BP_RES_RANDOM))
    {
        random = *(uint32_t*)(r_pack->data);
    }
    else 
    {
        random = rand();
    }
    return random;
}

TVersion axu_get_hw_version(void)
{
    return 0xa8;
}

TVersion axu_get_fw_version(void)
{
    return 0;
}

uint32_t axu_get_boeid(void)
{
    return 0;
}

int axu_set_boeid(uint32_t boeid)
{
    return 0;
}

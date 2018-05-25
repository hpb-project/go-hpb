// Last Update:2018-05-24 11:38:06
/**
 * @file common.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-23
 */

#include "common.h"
#include <stdio.h>

#define get_major(version) (version>>0x4)
#define get_minor(version) (version&0x0f)

TVersion get_version_major(TVersion version)
{
    return get_major(version);
}
TVersion get_version_min(TVersion version)
{
    return get_minor(version);
}

uint32_t checksum(uint8_t *data, uint32_t len)
{
    uint32_t chk = 0;
    if(data != NULL && len > 0)
    {
        for(uint32_t i = 0;i < len; i++)
        {
            chk += data[i];
        }
    }
    return chk;
}

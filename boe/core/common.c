// Last Update:2018-05-23 15:57:25
/**
 * @file common.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-23
 */

#include "common.h"
#include <stdio.h>

uint8_t get_version_major(uint8_t version)
{
    return version>>0x4;
}
uint8_t get_version_min(uint8_t version)
{
    return (version & 0x0f);
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

// Last Update:2018-05-26 11:57:16
/**
 * @file community.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-23
 */

#include <stdio.h>
#include <string.h>
#include "community.h"
/*
 * Just a empty function
 */

int pcie_read(uint8_t *p_buf, uint32_t len)
{
    memset(p_buf, 0xa1, len); 
    return 0;
}
int pcie_write(uint8_t *p_data, uint32_t len)
{
    return 0;
}
int pcie_reg_read(uint32_t reg_offset)
{
    return 0;
}
int pcie_reg_write(uint32_t reg_offset, RegWidth width, RegVal val)
{
    switch(width){
        case REG_WIDTH_8:
            val.b_val;
            break;
        case REG_WIDTH_16:
            val.h_val;
            break;
        case REG_WIDTH_32:
            val.w_val;
            break;
    }
    return 0;
}

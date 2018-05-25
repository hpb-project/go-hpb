// Last Update:2018-05-24 15:37:08
/**
 * @file community.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-23
 */

#ifndef COMMUNITY_H
#define COMMUNITY_H

#include <stdint.h>

typedef enum RegWidth {
    REG_WIDTH_8,
    REG_WIDTH_16,
    REG_WIDTH_32
}RegWidth;

typedef union RegVal {
    uint32_t w_val;
    uint16_t h_val;
    uint8_t  b_val;
}RegVal;

int pcie_read(uint8_t *p_buf, uint32_t len);
int pcie_write(uint8_t *p_data, uint32_t len);
int pcie_reg_read(uint32_t reg_offset);
int pcie_reg_write(uint32_t reg_offset, RegWidth width, RegVal val);

#endif  /*COMMUNITY_H*/

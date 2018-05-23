// Last Update:2018-05-23 09:33:26
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

int pcie_read(uint8_t *p_buf, uint32_t len);
int pcie_write(uint8_t *p_data, uint32_t len);

#endif  /*COMMUNITY_H*/

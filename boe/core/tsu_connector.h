// Last Update:2018-05-23 14:21:15
/**
 * @file tsu_connector.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-22
 */

#ifndef TSU_CONNECTOR_H
#define TSU_CONNECTOR_H

#include <stdint.h>

uint8_t get_hw_version(void);
uint8_t get_fw_version(void);
uint32_t get_boeid(void);
int set_boeid(uint32_t boeid);
int validate_sign(u256 r, u256 s, uint8_t v, u256 x, u256 y);
int get_randnum();
int hw_sign(uint8_t *info, int info_len, sign_result_t *result);

#endif  /*TSU_CONNECTOR_H*/

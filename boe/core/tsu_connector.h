// Last Update:2018-05-25 09:26:09
/**
 * @file tsu_connector.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-22
 */

#ifndef TSU_CONNECTOR_H
#define TSU_CONNECTOR_H

#include "common.h"

TVersion tsu_get_hw_version(void);
TVersion tsu_get_fw_version(void);
uint32_t tsu_get_boeid(void);
int tsu_set_boeid(uint32_t boeid);
int tsu_validate_sign(u256 hash, u256 r, u256 s, uint8_t v, sign_check_result_t *result);
int tsu_hw_sign(uint8_t *info, int info_len, sign_result_t *result);

#endif  /*TSU_CONNECTOR_H*/

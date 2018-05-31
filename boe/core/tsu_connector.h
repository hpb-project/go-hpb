// Last Update:2018-05-25 21:48:13
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

int tsu_validate_sign(uint8_t *hash, uint8_t *r, uint8_t *s, uint8_t v, PublicKey_t*result);
int tsu_hw_sign(uint8_t *info, int info_len, uint8_t *result);

#endif  /*TSU_CONNECTOR_H*/

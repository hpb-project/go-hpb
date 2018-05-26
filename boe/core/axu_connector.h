// Last Update:2018-05-25 17:46:09
/**
 * @file axu_connector.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-24
 */

#ifndef AXU_CONNECTOR_H
#define AXU_CONNECTOR_H
#include "common.h"

TVersion axu_get_hw_version(void);
TVersion axu_get_fw_version(void);
uint32_t axu_get_random();
uint32_t axu_get_boeid(void);
int      axu_set_boeid(uint32_t boeid);
int      axu_update(void);
int      axu_update_abort(void);
#endif  /*AXU_CONNECTOR_H*/

// Last Update:2018-05-23 10:35:47
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

#define MAJOR_V(package) ((package).version >> 4)
#define MINER_V(package) ((package).version & 0x04)

typedef struct T_PACKAGE{
    uint32_t    sequence;           // package sequence id.
    uint8_t     version;            // protocol version.
    uint8_t     is_response;        // the package is request(0) or responsed(1).
    uint8_t     fragment_flag;      // 0: no fragment; 1: first fragment; 
                                    // 2: middle fragment; 3:last fragment.
    uint8_t     function_id;        // task type.
    uint16_t    reserved;           // reserved.
    uint16_t    length;             // payload data length.
    uint32_t    checksum;           // payload data checksum.
    uint8_t     payload[];          // payload data pointor.
}T_Package;


uint8_t get_hw_version(void);
uint8_t get_fw_version(void);
uint32_t get_boeid(void);
int set_boeid(uint32_t boeid);
int validate_sign(u256 r, u256 s, uint8_t v, u256 x, u256 y);
int get_randnum();
int hw_sign(uint8_t *info, int info_len, sign_result_t *result);

#endif  /*TSU_CONNECTOR_H*/

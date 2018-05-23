// Last Update:2018-05-23 14:16:26
/**
 * @file common.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-22
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

typedef struct u256 {
    uint8_t data[32];
}u256;

typedef struct sign_result_t {
    u256 r;
    u256 s;
    uint8_t v;
}sign_result_t;

uint8_t get_version_major(uint8_t version);
uint8_t get_version_min(uint8_t version);
uint32_t checksum(uint8_t *data, uint32_t len);


#endif  /*COMMON_H*/

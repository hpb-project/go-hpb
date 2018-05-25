// Last Update:2018-05-24 15:18:41
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

typedef uint8_t TVersion;
typedef struct u256 {
    uint8_t data[32];
}u256;

typedef struct sign_result_t {
    u256 r;
    u256 s;
    uint8_t v;
}sign_result_t;

typedef struct sign_check_result_t {
    u256 x;
    u256 y;
}sign_check_result_t;

typedef struct sign_check_param_t {
    u256 h;
    u256 r;
    u256 s;
    uint8_t v;
}sign_check_param_t;

TVersion get_version_major(TVersion version);
TVersion get_version_min(TVersion version);
uint32_t checksum(uint8_t *data, uint32_t len);


#endif  /*COMMON_H*/

// Last Update:2018-05-23 10:35:17
/**
 * @file common.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-22
 */

#ifndef COMMON_H
#define COMMON_H

typedef struct u256 {
    uint8_t data[32];
}u256;

typedef struct sign_result_t {
    u256 r;
    u256 s;
    uint8_t v;
}sign_result_t;


#endif  /*COMMON_H*/

// Last Update:2018-05-26 10:25:34
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

typedef struct SignResult_t{
    uint8_t *r;
    uint8_t *s;
    uint8_t *v;
}SignResult_t;

typedef struct PublicKey_t{
    uint8_t* x;
    uint8_t* y;
}PublicKey_t;

PublicKey_t* new_pubkey(void);
void delete_pubkey(PublicKey_t *pub);
SignResult_t* new_signresult(void);
void delete_signresult(SignResult_t *result);
TVersion get_version_major(TVersion version);
TVersion get_version_min(TVersion version);
uint32_t checksum(uint8_t *data, uint32_t len);


#endif  /*COMMON_H*/

// Last Update:2018-05-22 20:30:17
/**
 * @file test.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-22
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef struct T_PACKAGE{
    uint32_t sequence;
    uint8_t version;
    uint8_t ask_or_request;
    uint8_t fragment_flag;
    uint8_t function_id;
    uint16_t reserved;
    uint16_t length;
    uint32_t checksum;
    uint8_t payload[];
}T_Package;


int main(int argc, char *argv[])
{
    printf("sizeof(T_Package)=%d\n", sizeof(T_Package));
    T_Package *p = (T_Package*)malloc(sizeof(T_Package)+100);

    return 0;
}

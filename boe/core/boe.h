// Last Update:2018-05-29 09:45:16
/**
 * @file boe.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-22
 */

#ifndef BOE_H
#define BOE_H

#include "common.h"

typedef enum BOE_ERR_ENUM{
    BOE_OK = 0,
}BOE_ERR_CODE;

int BOEInit(void);
int BOERelease(void);
int BOEBind(void);
TVersion GetBOEHWVersion(void);
TVersion GetBOEFWVersion(void);
TVersion GetBOEAXUVersion(void);
int BOEFWUpdate(void);
int BOEFWUpdateAbort(void);
int GetBOEID(void);
int SetBOEID(uint32_t id);
int BOEValidSign(uint8_t* hash, uint8_t* r, uint8_t* s, uint8_t v, PublicKey_t *result);
int GetRand(void);
int BOEHWSign(uint8_t *p_data, int datalen, uint8_t *result);
int BOESubscribeEvent(void);// go api.


#endif  /*BOE_H*/

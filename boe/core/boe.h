// Last Update:2018-05-22 16:25:39
/**
 * @file boe.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-22
 */

#ifndef BOE_H
#define BOE_H

typedef enum BOE_ERR_ENUM{
    BOE_OK = 0,
}BOE_ERR_CODE;

int BOEInit(void);
int BOERelease(void);
int BOEBind(void);
int GetBOEHWVersion(void);
int GetBOEFWVersion(void);
int BOEFWUpdate(void);
int BOEFWUpdateAbort(void);
int GetBOEID(void);
int SetBOEID(void);
int BOEValidateSign(void);
int GetRand(void);
int BOEHWSign(void);
int BOESubscribeEvent(void);// go api.



#endif  /*BOE_H*/

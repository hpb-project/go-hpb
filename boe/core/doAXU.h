// Last Update:2018-06-21 14:59:45
/**
 * @file doAXU.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-21
 */

#ifndef DO_A_X_U_H
#define DO_A_X_U_H

#include "boe.h"
#include "axu_connector.h"

typedef int (*MsgHandle)(uint8_t *data, int len, void *userdata);
BoeErr* doAXU_Init(char *r_devname, char *w_devname, MsgHandle msghandle, void*userdata);
BoeErr* doAXU_Release();
BoeErr* doAXU_GetVersionInfo(TVersion *hw, TVersion *fw, TVersion *axu);
BoeErr* doAXU_Reset(void);
BoeErr* doAXU_GetRandom(uint32_t *val);
BoeErr* doAXU_GetBOEID(uint32_t *id);
BoeErr* doAXU_GetHWVer(TVersion *hw);
BoeErr* doAXU_GetFWVer(TVersion *fw);
BoeErr* doAXU_GetAXUVer(TVersion *axu);
BoeErr* doAXU_SetBoeID(uint32_t id);
BoeErr* doAXU_BindAccount(uint8_t *baccount);
BoeErr* doAXU_GetBindAccount(uint8_t *account_256);
BoeErr* doAXU_HWSign(uint8_t *data, int len, uint8_t *result);
BoeErr* doAXU_Transport(ImageHeader *info, uint8_t *data);
BoeErr* doAXU_UpgradeStart(uint32_t fid);
BoeErr* doAXU_UpgradeAbort(uint32_t fid);



#endif  /*DO_A_X_U_H*/

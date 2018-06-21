// Last Update:2018-06-21 15:00:06
/**
 * @file error.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-20
 */

#ifndef ERROR_H
#define ERROR_H
#include "boe.h"
#include "axu_connector.h"

BoeErr e_ok;
BoeErr e_init_fail;
BoeErr e_conn_fail;
BoeErr e_no_device;
BoeErr e_no_mem;
BoeErr e_param_invalid;
BoeErr e_msgc_send_fail;
BoeErr e_msgc_read_timeout;
BoeErr e_result_invalid;
BoeErr e_axu_inner[MAX_AXU_ERRNUM];


#endif  /*ERROR_H*/

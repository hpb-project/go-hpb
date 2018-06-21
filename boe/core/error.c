// Last Update:2018-06-21 15:45:07
/**
 * @file error.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-21
 */
#include "error.h"

BoeErr e_ok = {.ecode = 100, .emsg = "ok", .bfree = 0};
BoeErr e_init_fail = {.ecode = 101, .emsg = "init failed", .bfree = 0};
BoeErr e_conn_fail = {.ecode = 102, .emsg = "connect failed", .bfree = 0};
BoeErr e_no_device = {.ecode = 103, .emsg = "have no device", .bfree = 0};
BoeErr e_no_mem = {.ecode = 104, .emsg = "memory not enough", .bfree = 0};
BoeErr e_param_invalid = {.ecode = 105, .emsg = "param invalid", .bfree = 0};
BoeErr e_msgc_send_fail = {.ecode = 106, .emsg = "msgc send failed", .bfree = 0};
BoeErr e_msgc_read_timeout = {.ecode = 107, .emsg = "msgc read timeout", .bfree = 0};
BoeErr e_result_invalid = {.ecode = 108, .emsg = "result invalid", .bfree = 0};
BoeErr e_image_chk_error = {.ecode = 109, .emsg = "image checksum error", .bfree = 0};
BoeErr e_image_header_error = {.ecode = 110, .emsg = "image header error", .bfree = 0};
BoeErr e_gen_host_id_failed = {.ecode = 111, .emsg = "general host id failed", .bfree = 0};
BoeErr e_axu_inner[MAX_AXU_ERRNUM];

BoeErr *BOE_OK = &e_ok;

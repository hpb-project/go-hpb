package boe
import (
    "errors"
)

var (
	ErrInvalidParams     = errors.New("invalid params")
	ErrInitFailed        = errors.New("init failed")
	ErrReleaseFailed     = errors.New("release failed")
	ErrSignCheckFailed   = errors.New("recover pubkey failed")
	ErrHWSignFailed      = errors.New("hw sign failed")
	ErrUnknownEvent      = errors.New("unknown event")
	ErrIDNotMatch        = errors.New("id not match")
	ErrUpdateFailed      = errors.New("update failed")
	ErrUpdateAbortFailed = errors.New("update abort failed")
	ErrGetAccountFailed  = errors.New("get bind account failed")
	ErrSetAccountFailed  = errors.New("set bind account failed")
	ErrGetNextHashFailed = errors.New("get next hash failed")
	ErrGetSNFailed       = errors.New("get sn failed")
	ErrNoNeedUpdate      = errors.New("no need update")
	ErrHashVerifyFailed  = errors.New("verify hash failed")
	ErrHashTimeLimited   = errors.New("get hash time limited")
)

const (
	e_ok                   uint32 = 100
	e_init_fail            uint32 = 101
	e_conn_fail            uint32 = 102
	e_no_device            uint32 = 103
	e_no_mem               uint32 = 104
	e_param_invalid        uint32 = 105
	e_msgc_send_fail       uint32 = 106
	e_msgc_read_timeout    uint32 = 107
	e_result_invalid       uint32 = 108
	e_image_chk_error      uint32 = 109
	e_image_header_error   uint32 = 110
	e_gen_host_id_failed   uint32 = 111
	e_hw_verify_failed     uint32 = 112
	e_update_ver_not_match uint32 = 113
	e_update_reboot_failed uint32 = 114
	e_hash_get_time_limit  uint32 = 115
	e_hash_check_error     uint32 = 116
)

// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

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

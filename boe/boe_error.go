package boe
import (
    "errors"
)

var (
    ErrInvalidParams         = errors.New("invalid params")
    ErrInitFailed            = errors.New("init failed")
    ErrReleaseFailed         = errors.New("release failed")
    ErrSignCheckFailed       = errors.New("sign check failed")
    ErrHWSignFailed          = errors.New("hw sign failed")
    ErrUnknownEvent          = errors.New("unknown event")
    ErrIDNotMatch            = errors.New("id not match")
    ErrUpdateFailed          = errors.New("update failed")
    ErrUpdateAbortFailed     = errors.New("update abort failed")
    ErrGetAccountFailed      = errors.New("get bind account failed")
    ErrSetAccountFailed      = errors.New("set bind account failed")
)

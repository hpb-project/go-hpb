package boe
import "C"

//export HardwareRecoverCallback
func HardwareRecoverCallback() {
	//log.Info("HardwareRecoverCallback","Got callbacl from ","C")
	BoeGetInstance().rboeCh <- struct{}{}
}

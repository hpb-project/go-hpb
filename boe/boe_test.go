package BOE
import (
    "fmt"
    "testing"
)

func TestNewEvent(t *testing.T) {
    var ver = BOEGetHWVersion()
    fmt.Printf("hwversion = %02x\n", ver)
    var (
        hash = make([]byte, 32)
        r    = make([]byte, 32)
        s    = make([]byte, 32)
    )
    var v byte

    x,y,err := BOEValidateSign(hash, r, s, v)
    if err == nil {
        //fmt.Printf("len(x)=%d\n", len(x))
        for i:=0; i < len(x); i++ {
            fmt.Printf("x[%d]=%02x\n", i, x[i])
        }
        for i:=0; i < len(y); i++ {
            fmt.Printf("y[%d]=%02x\n", i, y[i])
        }
    }

}

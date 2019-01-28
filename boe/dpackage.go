package boe

import (
    "fmt"
    "os"
    "bufio"
    "io"
    "log"
    "encoding/json"
    "path/filepath"
    "strings"
    "os/exec"
    "io/ioutil"
)

type Release struct {
    Hv      int `json:"hv"`
    Mv      int `json:"mv"`
    Fv      int `json:"fv"`
    Dv      int `json:"dv"`
    File     string `json:"file"`
    Time     string `json:"time"`
}

func loadJSON(filename string, v interface{}) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return
    }

    //读取的数据为json格式，需要进行解码
    err = json.Unmarshal(data, v)
    if err != nil {
        return
    }
}



func destorytemp(path string, prefix string) {
    filepath.Walk(path, func(path string, fi os.FileInfo, err error) error {
        if nil == fi {
            return err
        }
        if !fi.IsDir() {
            return nil
        }
        name := fi.Name()

        if strings.Contains(name, prefix) {

            fmt.Println("temp file name:", path)

            err := os.RemoveAll(path)
            if err != nil {
                fmt.Println("delet dir error:", err)
            }
        }
        return nil
    })

}

func createtmpdir(path string, prefix string) (string, error){
    f, e := ioutil.TempDir(path, prefix)
    if e != nil {
        //fmt.Println("create tempDir error")
        return "", e
    }
    return f, nil
}

func httpdown(url string, destfile string) error {
    cmd := exec.Command("wget", url, "-N", "-O", destfile)
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        log.Fatal(err)
    }
    defer stdout.Close()

    if err := cmd.Start(); err != nil {
        log.Fatal(err)
    }
    reader := bufio.NewReader(stdout)
    var index int
    for{
        line, err2 := reader.ReadString('\n')
        if err2 != nil || io.EOF == err2 {
            break
        }
        fmt.Println(line)
        index++
    }
    return cmd.Wait()

}
func vMajor(ver int) uint8 {
    var ret = (uint8)(ver&0xff)>>4
    return ret

}

func downloadrelease(hver int, mver int, fver int, dver int)  ([]byte,error) {
    baseurl := "https://raw.githubusercontent.com/hpb-project/boe_release_firmware/master/"
    // create temp dir and delete it after finished
    dir, e := createtmpdir("/tmp/", "hpbupgrade")
    defer destorytemp("/tmp/", "hpbupgrade")
    if e != nil {
        return nil,e
    }
    fmt.Println("tmpdir :", dir)
    // download release.json
    releasePath := filepath.Join(dir, "release.json")
    jsonurl := baseurl + "release.json"
    e = httpdown(jsonurl, releasePath)
    if e == nil {
        fmt.Println("json download ok.")
        var rlist []Release

        var finfo = &Release{Hv:hver, Mv:mver, Fv:fver, Dv:dver}
        loadJSON(releasePath, &rlist)

        for _, release:= range rlist {
            nhver := release.Hv
            nmver := release.Mv
            nfver := release.Fv
            ndver := release.Dv
            //fmt.Printf("nhver=0x%02x,finfo.Hv=0x%02x\n", nhver, finfo.Hv)
            if vMajor(nhver) == vMajor(finfo.Hv) {
                nvcnt := nmver * 1000000 + nfver * 1000 + ndver 
                ovcnt := finfo.Mv * 1000000 + finfo.Fv * 1000 + finfo.Dv
                if nvcnt > ovcnt {
                    finfo.Hv = nhver
                    finfo.Mv = nmver
                    finfo.Fv = nfver
                    finfo.Dv = ndver
                    finfo.File = release.File
                    finfo.Time = release.Time
                }
            }
        }
        if finfo.Mv != mver || finfo.Fv != fver || finfo.Dv != dver {
            fmt.Printf("find upgrade img %s\n", finfo.File)
            binpath := filepath.Join(dir, "upgrade.bin")
            binurl  := baseurl + finfo.File
            fmt.Printf("download %s...\n", finfo.File);
            e = httpdown(binurl, binpath)
            if e != nil {
                fmt.Println("download failed")
                return nil,e
            }
            
            fmt.Printf("download finished.")
            return ioutil.ReadFile(binpath)
        }else {
            return nil, ErrNoNeedUpdate 
        }

    }else{
        fmt.Printf("download release.json failed\r\n")
    }

    return nil, e
}

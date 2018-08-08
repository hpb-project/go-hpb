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
    "fmt"
    "bufio"
    "io"
    "log"
    "os/exec"
)
func Gitclone(url string, destdir string) error {
    cmd := exec.Command("git", "clone", url, destdir)
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


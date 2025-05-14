package main 

import (
  "fmt"
  "net"
  "io"
  "bytes"
  "encoding/binary"
  "math/rand/v2"
)

func SendData(x int64) {
  file := make([]byte, x)
  conn, err := net.Dial("tcp", "0.0.0.0:8079")
  if err != nil {
    fmt.Println(err)
    return
  }
  binary.Write(conn, binary.LittleEndian, x)
  _, err = io.CopyN(conn, bytes.NewReader(file), x)
  if err != nil {
    fmt.Println(err)
  }
  cur_bfr := make([]byte, 1024)
  _, err = conn.Read(cur_bfr)
  fmt.Println(string(cur_bfr))
  return
}

func main() {
  n := int64(rand.IntN(8000))
  SendData(n)
}


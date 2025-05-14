package main

import (
  "fmt"
  "net"
  "io"
  "bytes"
  "encoding/binary"
)

func Start() {
  ln, err := net.Listen("tcp", "0.0.0.0:8079")
  defer ln.Close()
  if err != nil {
    fmt.Println(err)
    return
  }
  for {
    conn, err := ln.Accept()
    fmt.Println("loop")
    if err != nil {
      fmt.Println("error:", err)
      return
    }
    go ReceiveData(&conn)
  }
}

func ReceiveData(conn *net.Conn) {
  cur_bffr := &bytes.Buffer{}
  var n int64
  var err error
  for {
    binary.Read(*conn, binary.LittleEndian, &n)
    _, err = io.CopyN(cur_bffr, *conn, n)
    if err != nil {
      fmt.Println("error:", err)
      return
    }
    fmt.Println(cur_bffr.Bytes(), n)
    _, err = (*conn).Write([]byte("ok"))
    if err != nil {
      fmt.Println(err)
      return
    }
  }
}

func main() {
  fmt.Println("start")
  Start()
  fmt.Println("end")
}




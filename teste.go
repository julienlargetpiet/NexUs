package main 

import (
  "fmt"
  "compress/zlib"
  "os"
  "bytes"
  "io"
)

func CompByteSlice(x *[]byte, x2 *[]byte) bool {
  n := len(*x) 
  if n != len(*x2) {
    return false
  }
  for i := 0; i < n; i++ {
    if (*x)[i] != (*x2)[i] {
      return false
    }
  }
  return true
}

func Compress(x *[]byte) ([]byte, error) {
  var b bytes.Buffer
  w := zlib.NewWriter(&b)
  _, err := w.Write(*x)
  if err != nil {
    return nil, err
  }
  err = w.Close()
  if err != nil {
    return nil, err
  }
  return b.Bytes(), nil
}

func deCompress(x *[]byte) ([]byte, error) {
  r, err := zlib.NewReader(bytes.NewReader(*x))
  if err != nil {
    return nil, err
  }
  var rtn_data bytes.Buffer
  _, err = io.Copy(&rtn_data, r)
  if err != nil {
    return nil, err
  }
  return rtn_data.Bytes(), nil
}

func main() {
  data, err := os.ReadFile("teste.txt")
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println("pre_compressed:", data)
  compressed_data, err := Compress(&data)
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println("compressed:", compressed_data)
  decompressed_data, err := deCompress(&compressed_data)
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println("decompressed:", decompressed_data)
  comp_vl := CompByteSlice(&data,  &decompressed_data)
  fmt.Println(comp_vl)
  return
}





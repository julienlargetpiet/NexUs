package main

import (
  "fmt"
  "os"
  "path/filepath"
)

func ExistDirFile(x *string, file_name *string) (bool, error) {
  data, err := os.ReadFile(*file_name)
  var cur_val string = ""
  if err != nil {
    return false, err
  }
  n := len(*x)
  var i2 int
  for i := 0; i < len(data); i++ {
    if data[i] != 10 {
      cur_val += string(data[i])
    } else {
      if n == len(cur_val) {
        i2 = 0
        for i2 < len(cur_val) {
          if (*x)[i2] != cur_val[i2] {
            break
          }
          i2++
        }
        if i2 == n {
          return true, nil 
        }
      }
      cur_val = ""
    }
  }
  return false, nil
}

func main () {
  filename := "data_file.txt"
  dir, _ := filepath.Abs(".")
  dir += "/"
  x := dir + "teste3"
  vl, err := ExistDirFile(&x, &filename)
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println(vl)
}



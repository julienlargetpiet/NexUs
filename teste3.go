package main

import (
  "fmt"
  "path/filepath"
  "os"
)

func main() {
  dir, _ := filepath.Abs(".")
  fmt.Println(dir)
  entries, err := os.ReadDir(".")
  if err != nil {
    fmt.Println(err)
    return
  }
  var data string = ""
  for _, v := range entries {
    if v.IsDir() {
      fmt.Println(" dir:", dir + "/" + v.Name())
    } else {
      fmt.Println("file:", dir + "/" + v.Name())
    }
    data += dir + "/" + v.Name() + "\n"
  }
  err = os.WriteFile("data_file.txt", []byte(data), 0644)
  if err != nil {
    fmt.Println(err)
    return
  }
}


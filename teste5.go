package main

import (
  "fmt"
  "os"
  "slices"
)

func CopyDir(src *string, dst *string) error {
  var cur_path string
  var cur_path2 string
  var cur_path_dir_found string
  var vec_dirname = []string{*src}
  var n int = 0
  var data []byte
  var ovr int = len(*src)
  for n > -1 {
    cur_path = vec_dirname[n]
    entries, err := os.ReadDir(cur_path)
    fmt.Println("loop", cur_path)
    for _, v := range entries {
      fmt.Println("loop2", v.Name())
      if v.IsDir() {
        cur_path_dir_found = cur_path + "/" + v.Name()
        vec_dirname = slices.Insert(vec_dirname, 0, cur_path_dir_found)
        cur_path2 = *dst + cur_path_dir_found[ovr:]
        err = os.Mkdir(cur_path2, 0755)
        if err != nil {
          return err
        }
        n += 1
      } else {
        data, err = os.ReadFile(cur_path + "/" + v.Name())
        if err != nil {
          return err
        }
        fmt.Println("okok")
        cur_path2 = *dst + cur_path[ovr:]
        err = os.WriteFile(cur_path2 + "/" + v.Name(), data, 0644)
        if err != nil {
          return err
        }
      }
    }
    vec_dirname = vec_dirname[:len(vec_dirname) - 1]
    n -= 1
  }
  return nil
}

func main() {
  src := "src_copy"
  dst := "dst_copy"
  err := Tree(&src, &dst)
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println("ok")
}



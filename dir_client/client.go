package main 

import (
  "fmt"
  "os"
  "bytes"
  "io"
  "compress/zlib"
  "path/filepath"
  "encoding/hex"
  "encoding/pem"
  "crypto"
  "crypto/x509"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha256"
  "net"
)

var base_dir string = "/home/kvv/ssd1/NexUs/dir_client/"
var len_base_dir int = len(base_dir)
var ref_nb = [10]uint8{'0', '1', '2', '3', '4', 
                       '5', '6', '7', '8', '9'}

func CompByteSlice(x []byte, x2 []byte) bool {
  n := len(x)
  n2 := len(x2)
  if n < len(x2) {
    return false
  }
  for i := 0; i < n2; i++ {
    if x[i] != x2[i] {
      return false
    }
  }
  return true
}

func IntToByteSlice(x int) []byte {
  if x == 256 {
    return []byte{0, 0}
  } else if x < 256 {
    return []byte{byte(x)}
  }
  var rtn_byte []byte
  var rest int = x % 256
  rtn_byte = append(rtn_byte, byte(rest))
  x -= rest
  x /= 256
  for x > 256 {
    rtn_byte = append(rtn_byte, 255)
    rest = x % 256
    rtn_byte = append(rtn_byte, byte(rest))
    x -= rest
    x /= 256
  }
  rtn_byte = append(rtn_byte, byte(x - 1))
  return rtn_byte
}

func ByteSliceToInt(x []byte) int {
  var rtn_int int = 256
  var ref_mult int = 256
  var i int = len(x) - 1
  if i == 0 {
    return int(x[0])
  }
  for i > -1 {
    rtn_int = ((int(x[i]) + 1) * ref_mult + int(x[i - 1]))
    ref_mult = rtn_int
    i -= 2
  }
  return rtn_int
}

func GoodIP(x *string) bool {
  var n int  = len(*x)
  var i int = 0
  var i2 int
  var cur_val string
  for I := 0; I < 3; I++ {
    cur_val = ""
    for i < n && (*x)[i] != '.' {
      i2 = 0
      for i2 < 10 {
        if ref_nb[i2] != (*x)[i] {
          i2++
        } else {
          break
        }
      }
      if i2 == 10 {
        return false
      }
      cur_val += string((*x)[i])
      i++
    }
    if len(cur_val) > 3 || len(cur_val) == 0 {
      return false
    }
    i++
  }
  cur_val = ""
  for i < n {
    i2 = 0
    for i2 < 10 {
      if ref_nb[i2] != (*x)[i] {
        i2++
      } else {
        break
      }
    }
    if i2 == 10 {
      return false
    }
    cur_val += string((*x)[i])
    i++
  }
  if len(cur_val) > 3 || len(cur_val) == 0 {
    return false
  }
  return true
}

func GoodPort(x *string) bool {
  var i2 int
  for i := 0; i < len(*x); i++ {
    i2 = 0
    for i2 < 10 {
      if (*x)[i] != ref_nb[i2] {
        i2++
      } else {
        break
      }
    }
    if i2 == 10 {
      return false
    }
  }
  int_port := StringToInt(*x)
  if int_port < 5000 || int_port > 90000 {
    return false
  }
  return true
}

func VerifHost(x *string) (bool, string) {
  cur_val := ""
  var i int = 0
  var n int = len(*x)
  for i < n && (*x)[i] != ':' {
    cur_val += string((*x)[i])
    i++
  }
  if i == n {
    return false, "no port provided"
  }
  i++ 
  if i == n {
    return false, "no port provided"
  }
  is_valid := GoodIP(&cur_val)
  if !is_valid {
    return false, "the ip is not a valid ip format"
  }
  cur_val = ""
  for i < n {
    cur_val += string((*x)[i])
    i++
  }
  is_valid = GoodPort(&cur_val)
  if !is_valid {
    return false, "the port is not valid"
  }
  return true, ""
}

func StringToInt(x string) int {
  var ref_nb = [10]uint8{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
  var rtn_val int = 0
  var lngth int = len(x)
  var i2 int
  var cur_rn uint8
  var i int
  for i = 0; i + 1 < lngth; i++ {
    cur_rn = x[i]
    i2 = 0
    for cur_rn != ref_nb[i2]{
      i2++
    }
    rtn_val += i2
    rtn_val *= 10
  }
  cur_rn = x[i]
  i2 = 0
  for cur_rn != ref_nb[i2]{
    i2++
  }
  rtn_val += i2
  return rtn_val
}

func DisplayDiff(file1 *string, file2 *string, sep *string) error {
  var dataa string
  var datab string
  var comp bool = true
  data, err := os.ReadFile(*file1)
  if err != nil {
    return err
  }
  data, err = deCompress(&data)
  if err != nil {
    return err
  }
  str_data := string(data)
  var sl_str_data1 []string
  var sl_str_data2 []string
  var i int = 0
  var cur_val string = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data1 = append(sl_str_data1, cur_val)
      cur_val = ""
    }
    i++
  }
  data, err = os.ReadFile(*file2)
  if err != nil {
    return err
  }
  data, err = deCompress(&data)
  if err != nil {
    return err
  }
  str_data = string(data)
  i = 0
  cur_val = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data2 = append(sl_str_data2, cur_val)
      cur_val = ""
    }
    i++
  }
  i = 0
  var i2 int = 0
  n := len(sl_str_data1)
  n2 := len(sl_str_data2)
  for i < n2 && comp {
    datab = sl_str_data2[i]
    dataa = sl_str_data1[i2]
    i2++
    for i2 < n && datab != dataa {
      fmt.Printf("%v%v -\n", dataa, *sep)
      dataa = sl_str_data1[i2]
      i2++
    }
    comp = (datab == dataa)
    if comp {
      fmt.Printf("%v%v%v\n", dataa, *sep, datab)
    } else {
      fmt.Printf("%v+ %v\n", *sep, datab)
    }
    i++
    if i2 == n {
      break
    }
  }
  for i < n2 {
    datab = sl_str_data2[i]
    fmt.Printf("%v+ %v\n", *sep, datab)
    i++
  }
  if comp {
    for i2 < n {
      dataa = sl_str_data1[i2]
      fmt.Printf("%v%v -\n", dataa, *sep)
      i2++
    }
  }
  return nil
}

func DisplayDiffCommit(file1 *string, file2 *string, sep *string) error {
  var dataa string
  var datab string
  var comp bool = true
  data, err := os.ReadFile(*file1)
  if err != nil {
    return err
  }
  str_data := string(data)
  var sl_str_data1 []string
  var sl_str_data2 []string
  var i int = 0
  var cur_val string = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data1 = append(sl_str_data1, cur_val)
      cur_val = ""
    }
    i++
  }
  data, err = os.ReadFile(*file2)
  if err != nil {
    return err
  }
  str_data = string(data)
  i = 0
  cur_val = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data2 = append(sl_str_data2, cur_val)
      cur_val = ""
    }
    i++
  }
  i = 0
  var i2 int = 0
  n := len(sl_str_data1)
  n2 := len(sl_str_data2)
  for i < n2 && comp {
    datab = sl_str_data2[i]
    dataa = sl_str_data1[i2]
    i2++
    for i2 < n && datab != dataa {
      fmt.Printf("%v%v -\n", dataa, *sep)
      dataa = sl_str_data1[i2]
      i2++
    }
    comp = (datab == dataa)
    if comp {
      fmt.Printf("%v%v%v\n", dataa, *sep, datab)
    } else {
      fmt.Printf("%v+ %v\n", *sep, datab)
    }
    i++
    if i2 == n {
      break
    }
  }
  for i < n2 {
    datab = sl_str_data2[i]
    fmt.Printf("%v + %v\n", *sep, datab)
    i++
  }
  if comp {
    for i2 < n {
      dataa = sl_str_data1[i2]
      fmt.Printf("%v%v -\n", dataa, *sep)
      i2++
    }
  }
  return nil
}

func DisplayDiffDual(file1 *string, file2 *string, sep *string) error {
  var dataa string
  var datab string
  var comp bool = true
  data, err := os.ReadFile(*file1)
  if err != nil {
    return err
  }
  data, err = deCompress(&data)
  if err != nil {
    return err
  }
  str_data := string(data)
  var sl_str_data1 []string
  var sl_str_data2 []string
  var i int = 0
  var cur_val string = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data1 = append(sl_str_data1, cur_val)
      cur_val = ""
    }
    i++
  }
  data, err = os.ReadFile(*file2)
  if err != nil {
    return err
  }
  str_data = string(data)
  i = 0
  cur_val = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data2 = append(sl_str_data2, cur_val)
      cur_val = ""
    }
    i++
  }
  i = 0
  var i2 int = 0
  n := len(sl_str_data1)
  n2 := len(sl_str_data2)
  for i < n2 && comp {
    datab = sl_str_data2[i]
    dataa = sl_str_data1[i2]
    i2++
    for i2 < n && datab != dataa {
      fmt.Printf("%v%v -\n", dataa, *sep)
      dataa = sl_str_data1[i2]
      i2++
    }
    comp = (datab == dataa)
    if comp {
      fmt.Printf("%v%v%v\n", dataa, *sep, datab)
    } else {
      fmt.Printf("%v+ %v\n", *sep, datab)
    }
    i++
    if i2 == n {
      break
    }
  }
  for i < n2 {
    datab = sl_str_data2[i]
    fmt.Printf("%v+ %v\n", *sep, datab)
    i++
  }
  if comp {
    for i2 < n {
      dataa = sl_str_data1[i2]
      fmt.Printf("%v%v -\n", dataa, *sep)
      i2++
    }
  }
  return nil
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

func ExistDirFile2(x *string, file_name *string) (bool, string, error) {
  data, err := os.ReadFile(*file_name)
  var cur_val string = ""
  if err != nil {
    return false, "", err
  }
  n := len(*x)
  var i2 int
  var n2 int
  var pre_rtn []string
  var i int
  var cur_int int = 0
  var cur_idx int = 0
  for i = 0; i < len(data); i++ {
    if data[i] != 10 {
      cur_val += string(data[i])
    } else {
      n2 = len(cur_val)
      if n > n2 {
        if (*x)[n2] == '/' {
          i2 = 0
          for i2 < n2 {
            if (*x)[i2] != cur_val[i2] {
              break
            }
            i2++
          }
          if i2 == n2 {
            pre_rtn = append(pre_rtn, cur_val)
          }
        }
      } else if *x == cur_val {
        return true, cur_val, nil
      }
      cur_val = ""
    }
  }
  if len(pre_rtn) > 0 {
    for i2 = 0; i2 < len(pre_rtn); i2++ {
      if len(pre_rtn[i2]) > cur_int {
        cur_int = len(pre_rtn[i2])
        cur_idx = i2
      }
    }
    return true, pre_rtn[cur_idx], nil
  } else {
    return false, "", nil
  }
}

func ExistDirFile3(x *string, file_name *string) (bool, string, error) {
  data, err := os.ReadFile(*file_name)
  var cur_val string = ""
  if err != nil {
    return false, "", err
  }
  n := len(*x)
  var i2 int
  rtn_str := ""
  var rtn_bool bool = false
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
          rtn_bool = true
          cur_val = ""
        }
      }
      rtn_str += cur_val
      rtn_str += "\n"
      cur_val = ""
    }
  }
  return rtn_bool, rtn_str, nil
}

func Tree(src string) ([]string, error) {
  var cur_path string
  var cur_path_dir_found string
  var vec_dirname = []string{src}
  var data []byte
  var n int = 0
  var rtn_data = []string{src}
  for n > -1 {
    cur_path = vec_dirname[n]
    entries, err := os.ReadDir(cur_path)
    for _, v := range entries {
      if v.IsDir() {
        cur_path_dir_found = cur_path + "/" + v.Name()
        vec_dirname = append([]string{cur_path_dir_found}, vec_dirname...)
        rtn_data = append(rtn_data, cur_path_dir_found)
        n += 1
      } else {
        data, err = os.ReadFile(cur_path + "/" + v.Name())
        if err != nil {
          return rtn_data, err
        }
        rtn_data = append(rtn_data, string(data))
      }
    }
    vec_dirname = vec_dirname[:len(vec_dirname) - 1]
    n -= 1
  }
  return rtn_data, nil
}

func TreeSend(conn *net.Conn, 
              src string, 
              private_key *rsa.PrivateKey) (error) {
  var cur_path string
  var cur_path_found string
  var cur_path_found2 string
  var vec_dirname = []string{src}
  var n int = 0
  var file_val = []byte{0}
  var dir_val = []byte{1}
  var end_val = []byte{2}
  var cur_send []byte
  var cur_send_len []byte
  var err error
  var hash_buffr [32]byte
  var hash_sl []byte
  var sign_sl []byte
  var final_cur_send_len []byte
  var i int
  for n > -1 {
    cur_path = vec_dirname[n]
    entries, err := os.ReadDir(cur_path)
    if err != nil {
      return err
    }
    for _, v := range entries {
      cur_path_found = cur_path + "/" + v.Name()
      cur_path_found2 = ""
      for i = len_base_dir; i < len(cur_path_found); i++ {
        cur_path_found2 += string(cur_path_found[i])
      }
      cur_send = []byte(cur_path_found2)
      cur_send_len = []byte{byte(len(cur_send))}
      hash_buffr = sha256.Sum256(cur_send_len)
      hash_sl = hash_buffr[:]
      sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                                 private_key, 
                                 crypto.SHA256,
                                 hash_sl)
      if err != nil {
        return err
      }
      _, err = (*conn).Write(sign_sl)
      if err != nil {
        return err
      }
      _, err = (*conn).Write(cur_send_len)
      if err != nil {
        return err
      }
      hash_buffr = sha256.Sum256(cur_send)
      hash_sl = hash_buffr[:]
      sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                                 private_key, 
                                 crypto.SHA256,
                                 hash_sl)
      if err != nil {
        return err
      }
      _, err = (*conn).Write(sign_sl)
      if err != nil {
        return err
      }
      _, err = (*conn).Write(cur_send)
      if err != nil {
        return err
      }
      if v.IsDir() {
        vec_dirname = append([]string{cur_path_found}, vec_dirname...)
        hash_buffr = sha256.Sum256(dir_val)
        hash_sl = hash_buffr[:]
        sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                                   private_key, 
                                   crypto.SHA256,
                                   hash_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(sign_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(dir_val)
        if err != nil {
          return err
        }
        n += 1
      } else {
        hash_buffr = sha256.Sum256(file_val)
        hash_sl = hash_buffr[:]
        sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                                   private_key, 
                                   crypto.SHA256,
                                   hash_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(sign_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(file_val)
        if err != nil {
          return err
        }
        cur_send, err = os.ReadFile(cur_path_found)
        if err != nil {
          return err
        }
        final_cur_send_len = IntToByteSlice(len(cur_send))
        cur_send_len = []byte{byte(len(final_cur_send_len))}
        hash_buffr = sha256.Sum256(cur_send_len)
        hash_sl = hash_buffr[:]
        sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                                   private_key, 
                                   crypto.SHA256,
                                   hash_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(sign_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(cur_send_len)
        if err != nil {
          return err
        }
        hash_buffr = sha256.Sum256(final_cur_send_len)
        hash_sl = hash_buffr[:]
        sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                                   private_key, 
                                   crypto.SHA256,
                                   hash_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(sign_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(final_cur_send_len)
        if err != nil {
          return err
        }
        hash_buffr = sha256.Sum256(cur_send)
        hash_sl = hash_buffr[:]
        sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                                   private_key, 
                                   crypto.SHA256,
                                   hash_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(sign_sl)
        if err != nil {
          return err
        }
        _, err = (*conn).Write(cur_send)
        if err != nil {
          return err
        } 
      }
    }
    vec_dirname = vec_dirname[:len(vec_dirname) - 1]
    n -= 1
  }
  cur_path_found = cur_path + "/" + "END"
  cur_send = []byte(cur_path_found)
  cur_send_len = []byte{byte(len(cur_send))}
  hash_buffr = sha256.Sum256(cur_send_len)
  hash_sl = hash_buffr[:]
  sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                             private_key, 
                             crypto.SHA256,
                             hash_sl)
  if err != nil {
    return err
  }
  _, err = (*conn).Write(sign_sl)
  if err != nil {
    return err
  }
  _, err = (*conn).Write(cur_send_len)
  if err != nil {
    return err
  }
  hash_buffr = sha256.Sum256(cur_send)
  hash_sl = hash_buffr[:]
  sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                             private_key, 
                             crypto.SHA256,
                             hash_sl)
  if err != nil {
    return err
  }
  _, err = (*conn).Write(sign_sl)
  if err != nil {
    return err
  }
  _, err = (*conn).Write(cur_send)
  if err != nil {
    return err
  }
  hash_buffr = sha256.Sum256(end_val)
  hash_sl = hash_buffr[:]
  sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                             private_key, 
                             crypto.SHA256,
                             hash_sl)
  if err != nil {
    return err
  }
  _, err = (*conn).Write(sign_sl)
  if err != nil {
    return err
  }
  _, err = (*conn).Write(end_val)
  if err != nil {
    return err
  } 
  return nil
}

func TreeSum(src string) ([32]byte, error) {
  var cur_path string
  var cur_path_dir_found string
  var vec_dirname = []string{src}
  var data []byte
  var n int = 0
  var all_data []byte
  var rtn_data [32]byte
  for n > -1 {
    cur_path = vec_dirname[n]
    entries, err := os.ReadDir(cur_path)
    for _, v := range entries {
      if v.IsDir() {
        cur_path_dir_found = cur_path + "/" + v.Name()
        vec_dirname = append([]string{cur_path_dir_found}, vec_dirname...)
        n += 1
      } else {
        data, err = os.ReadFile(cur_path + "/" + v.Name())
        if err != nil {
          return rtn_data, err
        }
        all_data = append(all_data, data...)
      }
      all_data = append(all_data, []byte(v.Name())...)
    }
    vec_dirname = vec_dirname[:len(vec_dirname) - 1]
    n -= 1
  }
  rtn_data = sha256.Sum256(all_data)
  return rtn_data, nil
}

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
    for _, v := range entries {
      if v.IsDir() {
        cur_path_dir_found = cur_path + "/" + v.Name()
        vec_dirname = append([]string{cur_path_dir_found}, vec_dirname...)
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

func deCompressCopyDir(src *string, dst *string) error {
  var cur_path string
  var cur_path2 string
  var cur_path_dir_found string
  var vec_dirname = []string{*src}
  var n int = 0
  var data []byte
  var ovr int = len(*src)
  var dc_data []byte
  for n > -1 {
    cur_path = vec_dirname[n]
    entries, err := os.ReadDir(cur_path)
    for _, v := range entries {
      if v.IsDir() {
        cur_path_dir_found = cur_path + "/" + v.Name()
        vec_dirname = append([]string{cur_path_dir_found}, vec_dirname...)
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
        dc_data, err = deCompress(&data)
        if err != nil {
          return err
        }
        cur_path2 = *dst + cur_path[ovr:]
        err = os.WriteFile(cur_path2 + "/" + v.Name(), dc_data, 0644)
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

  arg_v := os.Args
  var err error
  var file string
  var cur_val string
  var cur_val2 string
  var cur_val3 string
  var cur_val4 string
  var is_valid bool
  var data []byte
  var str_data string
  initiated_repo := base_dir + "initiated.txt"
  var i int = 6
  var i2 int
  pre_cur_dir, _ := filepath.Abs(".")
  for pre_cur_dir[i] != '/' {
    i += 1
  }
  cur_dir := pre_cur_dir[i + 1:]
  pre_cur_dir = pre_cur_dir[:i + 1]
  n := len(arg_v)

  if n == 1 {
    fmt.Println("Not enough argument")
    return
  }

  frst_arg := os.Args[1]

  if frst_arg == "help" {
    fmt.Println("Commands list:")
    fmt.Println("'init' is to initiate a repo, this will create a NexUs project for the current directory you are calling it from, this will automatically create a 'main' branch")
    fmt.Println("Example: nexus init\n")
    fmt.Println("'sethost' will bind a server ip and port to your current NexUs project")
    fmt.Println("Example: nexus sethost 12.12.12.12:5600\n")
    fmt.Println("'hostinfo' will tell you the host informations for your current NexUs project")
    fmt.Println("Example: nexus hostinfo\n")
    fmt.Println("'branchnew' is to create a branch, this will copy all the current files and directories from your current branch to a new one that you can modify without repercusion on other branches")
    fmt.Println("Example: nexus branchnew main2\n")
    fmt.Println("'branchlist' this will list all the branch available for your NexUs project")
    fmt.Println("Example: nexus branchlist\n")
    fmt.Println("'branchmy' this will print your current branch")
    fmt.Println("Example: nexus branchmy\n")
    fmt.Println("'branchswitch' will switch over the specified branch, bringing the last content of its commit to your current directory")
    fmt.Println("Example: nexus branchswitch main2\n")
    fmt.Println("'branchrm' will delete a branch")
    fmt.Println("Example: nexus branchrm main2\n")
    fmt.Println("'branchbring branchname file' will bring a file from another branch")
    fmt.Println("Example: nexus branchbring main2 file.txt ,will bring file.txt from main2 to your current branch")
    fmt.Println("'add' is to add files or directory to a temporary NexUs location called 'sas' before commiting")
    fmt.Println("Example: nexus add a.txt dira dira/*\n")
    fmt.Println("'addsee' prints the current content addes for next commit")
    fmt.Println("Example: nexus addsee\n")
    fmt.Println("'addclear' will erase all content added for next commit")
    fmt.Println("Example: nexus addclear")
    fmt.Println("'addlocate' prints the location of the file where all the name of the content for the next commit is stored")
    fmt.Println("Example nexus addlocate\n")
    fmt.Println("'rm' is to remove files or folders from your current directory and the 'sas'")
    fmt.Println("Example: nexus rm a.txt\n")
    fmt.Println("'commit' is to save the changes made to your project, after adding them into 'sas'")
    fmt.Println(`Example: nexus commit "message of the commit"` + "\n")
    fmt.Println("'commitlist' this will list all commit for the current branch, in chronological order")
    fmt.Println("Example: nexus commitlist\n")
    fmt.Println("'commitlast' this will print the last commit")
    fmt.Println("Example: nexus commitlast\n")
    fmt.Println("'commitgoback x' Go back to a previous commit")
    fmt.Println("Example: nexus commitgoback 2 ,will go back to the third commit")
    fmt.Println("'commitmsg x' where x specifies the commit number, prints the message of thespecified commit")
    fmt.Println("Example: nexus commitmsg 5, will print the commit message of the fith commit\n")
    fmt.Println("'commitdiff x1 x2 file file' will print the diff between the specified file through 2 differents commits")
    fmt.Println("Example: commitdiff 2 3 a.txt a.txt ,will print the content diff between the content of a.txt through the third commit and the fourth commit\n")
    fmt.Println("'commitstructdiff x1 x2' will print the difference between the filestructure of 2 specified commits. To make sure it works as intended, the files and folders must be added in the same order, you can spcify it using 'addorder' command")
    fmt.Println("Example: nexus commitstructdiff 2 6 ,will print the filestructure difference between the third and the seventh commit\n")
    fmt.Println("'addorder' performs a 'nexus add' with the specified order specified with 'addordernew'")
    fmt.Println("Example: nexus addorder\n")
    fmt.Println("'addordernew file1 folder folder/file2...' add in order the file and/or directories to add during the 'addorder' command")
    fmt.Println("Example: nexus addordernew file1 folder folder/file2\n")
    fmt.Println("'addorderclear' erases the content of the 'addorder' command")
    fmt.Println("Example: nexus addorderclear\n")
    fmt.Println("'addorderlocate' prints the location of the content 'addorder' command uses")
    fmt.Println("Example: nexus addorderlocate\n")
    fmt.Println("'addordersee' prints the content of addorder.txt")
    fmt.Println("Example: nexus addordersee\n")
    fmt.Println("'sasdiff x file' will print the content diff between your current added file in sas stage, and the commit number provided")
    fmt.Println("Example: nexus sasdiff 18 b.txt\n")
    fmt.Println("'sasstructdiff x' prints the filestructure diff between a chosen commit number and the the current sas filestructure")
    fmt.Println("Example: nexus sasstructdiff 18 ,will prints the filestructure diff between your current sas filestructure and the 19th commit\n")
    fmt.Println("'send' sends the content of your last commit to the server")
    fmt.Println("Example: nexus send ,will send the content of your last commit to the server\n")
    fmt.Println("'sync' will sync your commits with the server commit for the same branch on the same project, this won't download the content of the non synchronized commit like explained in the README.md but will sync the commits.txt file\n")
    fmt.Println("'branchget' ,will download the provided admin branch NexUs project")
    fmt.Println("Example: nexus branchget 125.14.146.179:8080@_home_project1/main will download the main branch of the _home_project1 NexUs project\n")
    fmt.Println("'bring' will just bring the required project downloaded via 'branchget' or 'waitingbranchget' to your current directory")
    fmt.Println("Example: nexus bring _home_project1 will bring the branch of the _home_project1 NexUs project downloaded via 'branchget' or 'waitingbranchget', in this case the main branch\n")
    fmt.Println("'seebranch host@_home_project1' ,will print the official branches for the provided project")
    fmt.Println("Example: nexus seebranch 12.145.123.14:8080@_home_project1 ,will print all the available official branches for the _home_project1 NexUs project\n")
    fmt.Println("'seewaitingbranch host@_home_project1' ,will print the unofficial branches for the provided project")
    fmt.Println("Example: nexus 12.43.128.223:8080@seewaitingbranch _home_project1 ,will print all the available unofficial branches for the _home_project1 NexUs project\n")
    fmt.Println("'seeproject host' ,will print the available NexUs projects from the host")
    fmt.Println("Example: nexus 156.214.36.44:8080 ,will print all the available NexUs projects from the provided host\n")
    fmt.Println("'whoami' prints if you are a standard or admin user")
    fmt.Println("Example: nexus whoami\n")
    return
  }

  if frst_arg == "init" {
    if n > 2 {
      fmt.Println("Error: init does not require more arguments")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil { 
      fmt.Println("Error:", err)
      return
    }
    if is_valid {
      fmt.Println("Error: repo already initiated")
      return
    }
    is_valid, _, err = ExistDirFile2(&cur_dir, &initiated_repo)
    if err != nil { 
      fmt.Println("Error:", err)
      return
    }
    if is_valid {
      fmt.Println("Error: Can't initilize a repo within another initialize repo")
      return
    }
    cur_val = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val += "_"
      } else {
        cur_val += string(cur_dir[i])
      }
    }
    err = os.Mkdir(base_dir + cur_val, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.Mkdir(base_dir + cur_val + "/main", 0755)
    if err != nil {
      fmt.Println("Error1:", err)
      return
    }
    err = os.Mkdir(base_dir + cur_val + "/main/sas", 0755)
    if err != nil {
      fmt.Println("Error1:", err)
      return
    }
    err = os.Mkdir(base_dir + cur_val + "/main/data", 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/main/cur_added.txt", 
                       []byte(cur_dir + "\n"), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/main/is_pushed.txt", 
                       []byte("1"), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/main/addorder.txt", 
                       []byte(""), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/main/commits.txt", 
                       []byte(""), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/branches.txt", 
                       []byte("main\n"), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/cur_branch.txt", 
                       []byte("main"), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/host_info.txt", 
                       []byte(""), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/main/cur_commit.txt", 
                       []byte(""), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    str_data += (cur_dir + "\n")
    err = os.WriteFile(initiated_repo,
                       []byte(str_data), 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "add" {
    if n < 3 {
      fmt.Println("Error: not enough argument for add")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/cur_added.txt"
    var all_args []string
    var fileinfo os.FileInfo
    var tmp_val string
    var tmp_valv []string
    for i = 2; i < n; i++ {
      tmp_val = os.Args[i]
      if tmp_val[len(tmp_val) - 1] == '*' {
        tmp_val = tmp_val[:len(tmp_val) - 2]
        fileinfo, err = os.Stat(tmp_val)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        if fileinfo.IsDir() {
          tmp_valv, err = Tree(tmp_val)
          if err != nil {
            fmt.Println("Error:", err)
            return
          }
          all_args = append(all_args, tmp_valv...)
        } else {
          fmt.Println("Error: the statement '*' is only used to include all elements within a dir")
        }
      } else {
        all_args = append(all_args, tmp_val)
      }
    }
    for i = 0; i < len(all_args); i++ {
      cur_val4 = all_args[i]
      file = cur_dir + "/" + cur_val4
      is_valid, cur_val, err = ExistDirFile2(&file, &cur_val2)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      if !is_valid {
        fmt.Println("Error: files and/or folders non existing for the currrent initiated repos")
        return
      }
      if file == cur_val {
        fmt.Println("Error: file or directory already added for this commit")
        return
      }
      i2 = len(cur_val) + 1
      for i2 < len(file) - 1 {
        if file[i2] == '/' {
          fmt.Println("Error: Must include directories where the new element is being added")
          return
        }
        i2++
      }
      data, err = os.ReadFile(cur_val2)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      str_data = string(data)
      str_data += (file + "\n")
      err = os.WriteFile(cur_val2, []byte(str_data), 0755)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      file = pre_cur_dir + file
      fileinfo, err = os.Stat(file)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      var c_data []byte
      if !fileinfo.IsDir() {
        data, err = os.ReadFile(file)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        c_data, err = Compress(&data)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        err = os.WriteFile(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4, 
                           c_data,
                           0644)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      } else {
        err = os.Mkdir(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4, 0755)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      }
    }
    return
  }

  if frst_arg == "rm" {
    if n < 3 {
      fmt.Println("Error: not enough argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/cur_added.txt"
    for i = 2; i < n; i++ {
      cur_val4 = os.Args[i]
      file = cur_dir + "/" + cur_val4
      is_valid, str_data, err = ExistDirFile3(&file, &cur_val2)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      if !is_valid {
        fmt.Println("Error: files and/or folders non existing for the currrent commit")
        return
      }      
      err = os.WriteFile(cur_val2, []byte(str_data), 0755)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      file = pre_cur_dir + file
      fileinfo, err := os.Stat(file)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      if fileinfo.IsDir() {
        err = os.RemoveAll(file)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        err = os.RemoveAll(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4)
        if err != nil {
          fmt.Println("Warning: no " + cur_val4 + " in sas state")
        }
      } else {
        err = os.Remove(file)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        err = os.Remove(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4)
        if err != nil {
          fmt.Println("Warning: no " + cur_val4 + " in sas state")
        }
      }
    }
    return
  }

  if frst_arg == "branchmy" {
    if n > 2 {
      fmt.Println("Too much args")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    fmt.Println(branch)
    return
  }

  if frst_arg == "branchlist" {
    if n > 2 {
      fmt.Println("Too much args")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/branches.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    fmt.Printf("%v", branch)
    return
  }

  if frst_arg == "branchswitch" {
    if n < 3 {
      fmt.Println("Error: not enough args")
      return
    }
    if n > 3 {
      fmt.Println("Error: not enough args")
      return
    }
    swtch_branch := os.Args[2]
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val = base_dir + cur_val3 + "/branches.txt"
    is_valid, err = ExistDirFile(&swtch_branch, &cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: swicth branch does not exist")
      return
    }
    err = os.WriteFile(base_dir + cur_val3 + "/cur_branch.txt", 
                       []byte(swtch_branch), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    cur_val2 = base_dir + cur_val3 + "/" + swtch_branch
    data, err = os.ReadFile(cur_val2 + "/cur_commit.txt")
    str_data = string(data)
    if str_data == "" {
      fmt.Println("No commit has never been taken in", swtch_branch)
      return
    }
    cur_val2 += ("/data/" + str_data + "/data")
    entries, err := os.ReadDir(pre_cur_dir + cur_dir)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    for _, vl := range entries {
      if vl.IsDir() {
        err = os.RemoveAll(vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      } else {
        err = os.Remove(vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      }
    }
    actual_dir := pre_cur_dir + cur_dir
    err = deCompressCopyDir(&cur_val2, &actual_dir)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "branchrm" {
    if n < 3 {
      fmt.Println("Error: not enough args")
      return
    }
    if n > 3 {
      fmt.Println("Error: too much args")
      return
    }
    rm_branch := os.Args[2]
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val = base_dir + cur_val3 + "/branches.txt"
    is_valid, cur_val4, err = ExistDirFile3(&rm_branch, &cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: branch to remove does not exist")
      return
    }
    err = os.WriteFile(cur_val, []byte(cur_val4), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.RemoveAll(base_dir + cur_val3 + "/" + rm_branch)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "branchmv" {
    if n < 4 {
      fmt.Println("Error: not enough args")
      return
    }
    if n > 4 {
      fmt.Println("Error: too much args")
      return
    }
    frst_branch := os.Args[2]
    scd_branch := os.Args[3]
    if frst_branch == scd_branch {
      fmt.Println("Branch to renaming should have a different name")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val = base_dir + cur_val3 + "/branches.txt"
    is_valid, cur_val4, err = ExistDirFile3(&frst_branch, &cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: branch to rename does not exist")
      return
    }
    is_valid, err = ExistDirFile(&scd_branch, &cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if is_valid {
      fmt.Println("Error: branch to rename to already exist")
      return
    }
    cur_val4 += "\n"
    cur_val4 += scd_branch
    err = os.WriteFile(cur_val, []byte(cur_val4), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "branchbring" {
    if n < 3 {
      fmt.Println("Error: not enough args, the branch where the content to bring is, is not mentioned")
      return
    }
    if n < 4 {
      fmt.Println("Error: the content to bring is not mentioned")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    extrn_branch := os.Args[2]
    cur_val2 = base_dir + cur_val3 + "/" + extrn_branch
    data, err = os.ReadFile(cur_val2 + "/cur_commit.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    cur_val2 += ("/data/" + string(data))
    cur_val = cur_val2 + "/added.txt"
    var dc_data []byte
    for i = 3; i < n; i++ {
      file = os.Args[i]
      cur_val4 = cur_dir + "/" + file
      is_valid, err = ExistDirFile(&cur_val4, &cur_val)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      if !is_valid {
        fmt.Println("Error: the file " + cur_val4 + " does not exist")
        return
      }
      data, err = os.ReadFile(cur_val2 + "/data/" + file)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      dc_data, err = deCompress(&data)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      err = os.WriteFile(pre_cur_dir + cur_dir + "/" + file, dc_data, 0644)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
    }
    return
  }

  if frst_arg == "branchnew" {
    if n < 3 {
      fmt.Println("Error: not enough argument, branch name is required")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    my_branch := os.Args[2]
    ref_branch := my_branch
    cur_val = base_dir + cur_val3 + "/branches.txt"
    is_valid, err = ExistDirFile(&my_branch, &cur_val)
    if err != nil {
      fmt.Println(err)
      return
    }
    if is_valid {
      fmt.Println("Error: Branch name already used")
      return
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    my_branch = base_dir + cur_val3 + "/" + my_branch
    err = os.Mkdir(my_branch, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = CopyDir(&cur_val2, &my_branch)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    str_data += (ref_branch + "\n")
    err = os.WriteFile(cur_val, 
                      []byte(str_data), 
                      0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "commitlast" {
    if n > 2 {
      fmt.Println("Error: too much arguments")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    data, err = os.ReadFile(cur_val2 + "/cur_commit.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    fmt.Println(string(data))
    return
  }

  if frst_arg == "commitlist" {
    if n > 2 {
      fmt.Println("Error: too much arguments")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    cur_val = ""
    i2 = 0
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        i2 += 1
        fmt.Println("commit -", i2 - 1, ":", cur_val)
        cur_val = ""
      }
    }
    return
  }

  if frst_arg == "commitdiff" {
    if n < 6 {
      fmt.Println("Error: not enough arguments")
      return
    }
    if n > 6 {
      fmt.Println("Error: too much arguments")
      return
    }
    commit1 := os.Args[2]
    commit2 := os.Args[3]
    if commit1 == commit2 {
      fmt.Println("Error: can't express a diff between same comit")
      return
    }
    content1 := os.Args[4]
    content2 := os.Args[5]
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    var commit_hist []string
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    ref_cur_val2 := cur_val2
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    if str_data == "" {
      fmt.Println("Error: No commit found")
      return
    }
    cur_val = ""
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        commit_hist = append(commit_hist, cur_val)
        cur_val = ""
      }
    }
    int_commit1 := StringToInt(commit1)
    if int_commit1 < 0 {
      fmt.Println("Error: the first commit begins at 0")
      return
    }
    if int_commit1 > len(commit_hist) {
      fmt.Println("Error: the last commit is", len(commit_hist) - 1)
      return
    }
    int_commit2 := StringToInt(commit2)
    if int_commit2 < 0 {
      fmt.Println("Error: the first commit begins at 0")
      return
    }
    if int_commit2 > len(commit_hist) {
      fmt.Println("Error: the last commit is", len(commit_hist) - 1)
      return
    }
    cur_val4 = cur_val2 + "/data/" + commit_hist[int_commit2] + "/added.txt"
    cur_val = cur_dir + "/" + content1
    is_valid, err = ExistDirFile(&cur_val, &cur_val4)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: the file " + content1 + " does not exist in fisrt commit provided")
      return
    }
    cur_val2 += ("/data/" + commit_hist[int_commit1] + "/added.txt")
    cur_val = cur_dir + "/" + content2
    is_valid, err = ExistDirFile(&cur_val, &cur_val2)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: the file " + content2 + " does not exist in second commit provided")
      return
    }
    cur_val4 = ref_cur_val2 + "/data/" + commit_hist[int_commit2] + "/data/" + content2
    ref_cur_val2 += "/data/" + commit_hist[int_commit1] + "/data/" + content1
    cur_sep := " | "
    err = DisplayDiff(&ref_cur_val2, &cur_val4, &cur_sep)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "commitstructdiff" {
    if n < 4 {
      fmt.Println("Error: not enough arguments")
      return
    }
    if n > 4 {
      fmt.Println("Error: too much arguments")
      return
    }
    content1 := os.Args[2]
    content2 := os.Args[3]
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    int_content1 := StringToInt(content1)
    int_content2 := StringToInt(content2)
    if int_content1 == int_content2 {
      fmt.Println("Error: can(t express a diff between same commit)")
      return
    }
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    var hist_commit []string
    str_data = string(data)
    cur_val = ""
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        hist_commit = append(hist_commit, cur_val)
        cur_val = ""
      }
    }
    if int_content1 < 0 || int_content2 < 0 {
      fmt.Println("Error: the first commit begins at 0")
      return
    }
    if int_content1 > len(hist_commit) || int_content2 > len(hist_commit) {
      fmt.Println("Error: the last comit is ", len(hist_commit) - 1)
      return
    }
    content1 = hist_commit[int_content1]
    content2 = hist_commit[int_content2]
    cur_val4 = cur_val2 + "/data/" + content2 + "/added.txt"
    cur_val2 = cur_val2 + "/data/" + content1 + "/added.txt"
    cur_sep := " | "
    fmt.Println("The left commit is:", content1)
    fmt.Println("The right commit is:", content2)
    fmt.Println("####")
    err := DisplayDiffCommit(&cur_val2, &cur_val4, &cur_sep)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "commitgoback" {
    if n < 3 {
      fmt.Println("Error: not enough arguments")
      return
    }
    if n > 3 {
      fmt.Println("Error: too much arguments")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val4 = os.Args[2]
    i2 = StringToInt(cur_val4)
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error: ")
      return
    }
    str_data = string(data)
    cur_val = ""
    var i3 int = 0
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        if i2 == i3 {
          if cur_val == "" {
            fmt.Println("Error: the commit name is empty")
            return
          }
          break
        }
        cur_val = ""
        i3 += 1
      }
    }
    if i2 != i3 {
      fmt.Println("Error: the commit you are trying to go back doesn't exist")
      return
    }
    err = os.WriteFile(cur_val2 + "/cur_commit.txt", []byte(cur_val), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    str_data += (cur_val + "\n")
    err = os.WriteFile(cur_val2 + "/commits.txt", []byte(str_data), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    cur_dir = pre_cur_dir + cur_dir
    entries, err := os.ReadDir(cur_dir)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    for _, vl := range entries {
      if vl.IsDir() {
        err = os.RemoveAll(vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      } else {
        err = os.Remove(vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      }
    }
    cur_val2 += ("/data/" + cur_val + "/data")
    err = deCompressCopyDir(&cur_val2, &cur_dir)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "sethost" {
    if n < 3 {
      fmt.Println("Error: not enough argument, the ip and port must be provided")
      return
    }
    if n > 3 {
      fmt.Println("Error: too much argument")
      return
    }
    host_vl := os.Args[2]
    is_valid, rtn_msg := VerifHost(&host_vl)
    if !is_valid {
      fmt.Println("Error:", rtn_msg)
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    err = os.WriteFile(base_dir + cur_val3 + "/host_info.txt", 
                             []byte(host_vl), 
                             0644)
    if err != nil {
      fmt.Println("Error", err)
      return
    }
    return
  }

  if frst_arg == "commit" {
    if n > 3 {
      fmt.Println("Error: too much argument")
      return
    }
    if n < 3 {
      fmt.Println("Error: the message is not provided")
      return
    }
    message := os.Args[2]
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    data, err = os.ReadFile(cur_val2 + "/is_pushed.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    if str_data != "1" {
      fmt.Println("Error: no data has been pushed since last commit")
      return
    }
    commit, err := TreeSum(cur_val2 + "/sas/.")
    str_commit := hex.EncodeToString(commit[:])
    cur_val4 = cur_val2 + "/commits.txt"
    is_valid, err = ExistDirFile(&str_commit, &cur_val4)
    fmt.Println("commit hash:", str_commit)
    if is_valid {
      fmt.Println("Error: the exacts content are found in the previous commit " + str_commit, " consider doing a 'commitgback' if you want to make this your last commit, or that's already your last commit, check this by doing 'commitlast'")
      return
    }
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    tmp_val2 := cur_val2 + "/data/" + str_commit
    err = os.Mkdir(tmp_val2, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    tmp_val2 += "/data"
    err = os.Mkdir(tmp_val2, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    tmp_val := cur_val2 + "/sas"
    err = CopyDir(&tmp_val, &tmp_val2)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.RemoveAll(tmp_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.Mkdir(tmp_val, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(cur_val2 + "/cur_added.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/data/" + str_commit + "/added.txt", 
                       data,
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/cur_added.txt", 
                      []byte(cur_dir + "\n"), 
                      0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/data/" + str_commit + "/message.txt", 
                       []byte(message),
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    str_data += (str_commit + "\n")
    err = os.WriteFile(cur_val2 + "/commits.txt", 
                       []byte(str_data), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/is_pushed.txt", []byte("0"), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/cur_commit.txt", 
                      []byte(str_commit), 
                      0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "commitmsg" {
    if n < 3 {
      fmt.Println("Error: not enough argument")
      return
    }
    if n > 3 {
      fmt.Println("Error: too much argument")
      return
    }
    tmp_val := os.Args[2]
    i2 = StringToInt(tmp_val)
    var i3 int = 0
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    cur_val = ""
    i = 0
    for i < len(str_data) {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        if i3 == i2 {
          if cur_val == "" {
            fmt.Println("Error: the commit name is empty")
            return
          }
          break
        }
        cur_val = ""
        i3 += 1
      }
      i++
    }
    data, err = os.ReadFile(cur_val2 + "/data/" + cur_val + "/message.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    fmt.Println(string(data))
    return
  }

  if frst_arg == "hostinfo" {
    if n > 2 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/host_info.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    fmt.Println(string(data))
    return
  }

  if frst_arg == "addordernew" {
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/addorder.txt"
    data, err = os.ReadFile(cur_val2)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    for i = 2; i < n; i++ {
      str_data += (os.Args[i] + "\n")
    }
    err = os.WriteFile(cur_val2, 
                       []byte(str_data), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "addorderclear" {
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/addorder.txt"
    err = os.WriteFile(cur_val2, []byte(""), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "addorderlocate" {
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/addorder.txt"
    fmt.Println(string(cur_val2))
    return
  }

  if frst_arg == "addordersee" {
    if n > 2 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/addorder.txt"
    data, err = os.ReadFile(cur_val2)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    fmt.Printf(string(data))
    return
  }

  if frst_arg == "addorder" {
    if n > 2 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    var pre_all_args []string
    data, err = os.ReadFile(cur_val2 + "/addorder.txt")
    cur_val2 += "/cur_added.txt"
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    cur_val = ""
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        pre_all_args = append(pre_all_args, cur_val)
        cur_val = ""
      }
    }
    var all_args []string
    var tmp_val string
    var tmp_valv []string
    var fileinfo os.FileInfo
    for i = 0; i < len(pre_all_args); i++ {
      tmp_val = pre_all_args[i]
      if tmp_val[len(tmp_val) - 1] == '*' {
        tmp_val = tmp_val[:len(tmp_val) - 2]
        fileinfo, err = os.Stat(tmp_val)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        if fileinfo.IsDir() {
          tmp_valv, err = Tree(tmp_val)
          if err != nil {
            fmt.Println("Error:", err)
            return
          }
          all_args = append(all_args, tmp_valv...)
        } else {
          fmt.Println("Error: the statement '*' is only used to include all elements within a dir")
        }
      } else {
        all_args = append(all_args, tmp_val)
      }
    }
    for i = 0; i < len(all_args); i++ {
      cur_val4 = all_args[i]
      file = cur_dir + "/" + cur_val4
      is_valid, cur_val, err = ExistDirFile2(&file, &cur_val2)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      if !is_valid {
        fmt.Println("Error: files and/or folders non existing for the currrent initiated repos")
        return
      }
      if file == cur_val {
        fmt.Println("Error: file or directory already added for this commit")
        return
      }
      i2 = len(cur_val) + 1
      for i2 < len(file) - 1 {
        if file[i2] == '/' {
          fmt.Println("Error: Must include directories where the new element is being added")
          return
        }
        i2++
      }
      data, err = os.ReadFile(cur_val2)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      str_data = string(data)
      str_data += (file + "\n")
      err = os.WriteFile(cur_val2, []byte(str_data), 0755)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      file = pre_cur_dir + file
      fileinfo, err = os.Stat(file)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      var c_data []byte
      if !fileinfo.IsDir() {
        data, err = os.ReadFile(file)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        c_data, err = Compress(&data)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        err = os.WriteFile(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4, 
                           c_data,
                           0644)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      } else {
        err = os.Mkdir(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4, 0755)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      }
    }
    return
  }

  if frst_arg == "addlocate" {
    if n > 2 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/cur_added.txt"
    fmt.Println(cur_val2)
    return
  }
  
  if frst_arg == "addsee" {
    if n > 2 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/cur_added.txt"
    data, err = os.ReadFile(cur_val2)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    fmt.Printf(string(data))
    return
  }

  if frst_arg == "addclear" {
    if n > 2 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    cur_val3 = cur_val2
    cur_val2 += "/sas"
    entries, err := os.ReadDir(cur_val2)
    cur_val2 += "/"
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    for _, vl := range entries {
      if vl.IsDir() {
        err = os.RemoveAll(cur_val2 + vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      } else {
        err = os.Remove(cur_val2 + vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      }
    }
    err = os.WriteFile(cur_val3 + "/cur_added.txt", 
                       []byte(cur_dir + "\n"), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "sasstructdiff" {
    if n < 3 {
      fmt.Println("Error: not enough argument")
      return
    }
    if n > 3 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    i2 = StringToInt(os.Args[2])
    var i3 int = 0
    str_data = string(data)
    cur_val = ""
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        if i2 == i3 {
          if cur_val == "" {
            fmt.Println("Error: the commit name is empty")
            return
          }
          break
        }
        i3 += 1
        cur_val = ""
      }
    }
    if i2 != i3 {
      fmt.Println("The commit doesn't exist")
      return
    }
    cur_val4 = cur_val2 + "/cur_added.txt"
    cur_val2 += ("/data/" + cur_val + "/added.txt")
    cur_sep := " | "
    fmt.Println("The current filestructure is the left one")
    err = DisplayDiffCommit(&cur_val2, &cur_val4, &cur_sep)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "sasdiff" {
    if n < 4 {
      fmt.Println("Error: not enough argument")
      return
    }
    if n > 4 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    tmp_val := cur_val2
    cur_val4 = cur_val2 + "/cur_added.txt"
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    cur_val = ""
    str_data = string(data)
    i2 = StringToInt(os.Args[2])
    var i3 int = 0
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        if i2 == i3 {
          if cur_val == "" {
            fmt.Println("Error: the commit name is empty")
            return
          }
          break
        }
        i3 += 1
        cur_val = ""
      }
    }
    if i2 != i3 {
      fmt.Println("Error: the commit does not exist")
      return
    }
    cur_val2 += ("/data/" + cur_val + "/added.txt")
    file = os.Args[3]
    tmp_val += ("/data/" + cur_val + "/data/" + file)
    cur_val = cur_dir + "/" + file
    is_valid, err = ExistDirFile(&cur_val, &cur_val2)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: the file provided does not exist in the provided commit")
      return
    }
    is_valid, err = ExistDirFile(&cur_val, &cur_val4)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: the file provided does not exist in your current sas files")
      return
    }
    cur_sep := " | "
    tmp_val2 := cur_dir + "/" + file
    fmt.Println("The current sas file is the left one")
    err = DisplayDiffDual(&tmp_val, &tmp_val2, &cur_sep)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "send" {
     if n > 2 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + "pubKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if len(data) == 0 {
      fmt.Println("Error: 'pubKey.pem' has no pub key, make sure to import the standard public key from the NexUs server")
      return
    }
    block, _ := pem.Decode(data)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if block == nil {
      fmt.Println("Error: failed to decode the public key")
      return
    }
    if block.Type != "RSA PUBLIC KEY" {
      fmt.Println("Error: not decoding an RSA public key")
      return
    }
    pub_key, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(base_dir + "/privateKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if len(data) == 0 {
      fmt.Println("Error: 'privateKey.pem' has no private key, make sure to import the private key from the NexUs server")
      return
    }
    block, _ = pem.Decode(data)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if block == nil {
      fmt.Println("Error: failed to decode the private key")
      return
    }
    if block.Type != "RSA PRIVATE KEY" {
      fmt.Println("Error: not decoding an RSA private key")
      return
    }
    private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/host_info.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if len(data) == 0 {
      fmt.Println("Error: no host info provided")
      return
    }
    host_info := string(data)
    conn, err := net.Dial("tcp", host_info)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    //COMMIT CODE SEND
    var hash_slice []byte
    cur_len := []byte{0}
    hash_buffr := sha256.Sum256(cur_len)
    hash_slice = hash_buffr[:]
    sign, err := rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_slice)
    if err != nil {
      fmt.Println(err)
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    ////
    //PROJECT SEND
    tmp_val := []byte(cur_val3)
    cur_len = []byte{byte(len(tmp_val))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_slice = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_slice)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    hash_buffr = sha256.Sum256(tmp_val)
    hash_slice = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_slice)
    if err != nil {
      fmt.Println(err)
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(tmp_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    ////
    //BRANCH SEND
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_len = []byte{byte(len(data))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_slice = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_slice)
    if err != nil {
      fmt.Println(err)
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    hash_buffr = sha256.Sum256(data)
    hash_slice = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_slice)
    if err != nil {
      fmt.Println(err)
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(data)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    ////
    //COMMIT SEND
    cur_val2 = base_dir + cur_val3 + "/" + branch
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    final_cur_len := IntToByteSlice(len(data))
    cur_len = []byte{byte(len(final_cur_len))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_slice = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_slice)
    if err != nil {
      fmt.Println(err)
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    hash_buffr = sha256.Sum256(final_cur_len)
    hash_slice = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_slice)
    if err != nil {
      fmt.Println(err)
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(final_cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    hash_buffr = sha256.Sum256(data)
    hash_slice = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_slice)
    if err != nil {
      fmt.Println(err)
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(data)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    ////
    //GET IF SYNC
    cur_bfr := make([]byte, 6)
    sign_buffr := make([]byte, 256)
    _, err = conn.Read(sign_buffr)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    sign = sign_buffr[:]
    _, err = conn.Read(cur_bfr)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(cur_bfr)
    hash_sl := hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if string(cur_bfr) == "desync" {
      fmt.Println("Error: you are desync from the NexUs server, run 'sync' to be synchronized")
      return
    }
    data, err = os.ReadFile(cur_val2 + "/cur_commit.txt")
    if err != nil {
      conn.Close()
      return
    }
    cur_commit := string(data)
    err = TreeSend(&conn, 
                   cur_val2 + "/data/" + cur_commit, 
                   private_key)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    conn.Close()
    err = os.WriteFile(cur_val2 + "/is_pushed.txt", 
                       []byte("1"),
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "sync" {
    if n > 2 {
      fmt.Println("Error: too much arguments")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    data, err = os.ReadFile(base_dir + "pubKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if len(data) == 0 {
      fmt.Println("Error: 'pubKey.pem' has no pub key, make sure to import the standard public key from the NexUs server")
      return
    }
    block, _ := pem.Decode(data)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if block == nil {
      fmt.Println("Error: failed to decode the public key")
      return
    }
    if block.Type != "RSA PUBLIC KEY" {
      fmt.Println("Error: not decoding an RSA public key")
      return
    }
    pub_key, err := x509.ParsePKCS1PublicKey(block.Bytes)
    data, err = os.ReadFile(base_dir + "privateKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if len(data) == 0 {
      fmt.Println("Error: 'privateKey.pem' has no pub key, make sure to import the standard public key from the NexUs server")
      return
    }
    block, _ = pem.Decode(data)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if block == nil {
      fmt.Println("Error: failed to decode the private key")
      return
    }
    if block.Type != "RSA PRIVATE KEY" {
      fmt.Println("Error: not decoding an RSA private key")
      return
    }
    private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/host_info.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if len(data) == 0 {
      fmt.Println("Error: no host info provided")
      return
    }
    host_info := string(data)
    conn, err := net.Dial("tcp", host_info)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    //SEND SYNC REQUEST
    cur_len := []byte{1}
    hash_buffr := sha256.Sum256(cur_len)
    hash_sl := hash_buffr[:]
    var sign = make([]byte, 256)
    sign, err = rsa.SignPKCS1v15(rand.Reader,
                                 private_key,
                                 crypto.SHA256,
                                 hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    ////
    //PROJECT VERIF
    tmp_val := []byte(cur_val3)
    cur_len = []byte{byte(len(tmp_val))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader,
                                 private_key,
                                 crypto.SHA256,
                                 hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(tmp_val)
    hash_sl = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader,
                                 private_key,
                                 crypto.SHA256,
                                 hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(tmp_val)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    ////
    //BRANCH VERIF
    tmp_val = []byte(branch)
    cur_len = []byte{byte(len(tmp_val))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader,
                                 private_key,
                                 crypto.SHA256,
                                 hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(tmp_val)
    hash_sl = hash_buffr[:]
    sign, err = rsa.SignPKCS1v15(rand.Reader,
                                 private_key,
                                 crypto.SHA256,
                                 hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(tmp_val)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    ////
    //RECEIVE COMMITS SERVER HISTORIC
    _, err = conn.Read(sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    final_cur_len := make([]byte, cur_len[0])
    _, err = conn.Read(sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(final_cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(final_cur_len)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    target_len := ByteSliceToInt(final_cur_len)
    tmp_val = make([]byte, target_len)
    _, err = conn.Read(sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(tmp_val)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(tmp_val)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    conn.Close()
    ////
    //Sync commits historic
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    i := len(data) - 2
    var tmp_data []byte
    var tmp_data2 []byte
    for i > -1 && data[i] != 10 {
      tmp_data = append([]byte{data[i]}, tmp_data...)
      i -= 1
    }
    for i > -1 && data[i] != 10 {
      tmp_data2 = append([]byte{data[i]}, tmp_data2...)
      i -= 1
    }
    is_valid = CompByteSlice(tmp_data, tmp_data2)
    if is_valid {
      fmt.Println("Note: Already Synchronized")
      return
    }
    tmp_data = append(tmp_data, 10)
    tmp_val = append(tmp_val, tmp_data...)
    err = os.WriteFile(cur_val2 + "/commits.txt", tmp_val, 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    ////
    return
  }

  if frst_arg == "branchget" || frst_arg == "waitingbranchget" {
    var depth_commit string = "full"
    var depth_commit_int int = 0
    var cur_host string
    if n < 3 {
      fmt.Println("Error: the host is not provided")
      return
    }
    if n == 4 {
      depth_commit = os.Args[3]
      return
    }
    if n > 4 {
      fmt.Println("Error: too much argument")
      return
    }
    if depth_commit != "full" {
      depth_commit_int = StringToInt(depth_commit)
    }
    cur_host = os.Args[2]
    var cur_ip string = ""
    var cur_port string = ""
    var cur_project string = ""
    var cur_branch string = ""
    var host_len int = len(cur_host)
    var i int = 0
    for i < host_len && cur_host[i] != ':' {
      cur_ip += string(cur_host[i])
      i++
    }
    i++
    is_valid = GoodIP(&cur_ip)
    if !is_valid {
      fmt.Println("Error: the ip provided is not good")
      return
    }
    for i < host_len && cur_host[i] != '@' {
      cur_port += string(cur_host[i])
      i++
    }
    i++
    is_valid = GoodPort(&cur_port)
    if !is_valid {
      fmt.Println("Error: the port provided is not good")
      return
    }
    for i < host_len && cur_host[i] != '/' {
      cur_project += string(cur_host[i])
      i++
    }
    i++
    if cur_project == "" {
      fmt.Println("Error: the project name is empty")
      return
    }
    for i < host_len {
      cur_branch += string(cur_host[i])
      i++
    }
    if cur_branch == "" {
      fmt.Println("Error: the branch name is empty")
      return
    }
    data, err = os.ReadFile(base_dir + "pubKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    block, _ := pem.Decode(data)
    if block == nil {
      fmt.Println("Error: Failed to decode 'pubKey.pem'")
      return
    }
    if block.Type != "RSA PUBLIC KEY" {
      fmt.Println("Error: 'pubKey.pem' does not contain an RSA public key")
      return
    }
    pub_key, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(base_dir + "privateKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    block, _ = pem.Decode(data)
    if block == nil {
      fmt.Println("Error: Failed to decode 'privateKey.pem'")
      return
    }
    if block.Type != "RSA PRIVATE KEY" {
      fmt.Println("Error: 'privateKey.pem' does not contain an RSA private key")
      return
    }
    private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    } 
    conn, err := net.Dial("tcp", cur_ip + ":" + cur_port)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    //SEND GET REQUEST
    var cur_len = make([]byte, 1)
    if frst_arg == "branchget" {
      cur_len = []byte{byte(2)}
    } else {
      cur_len = []byte{byte(3)}
    }
    hash_buffr := sha256.Sum256(cur_len)
    hash_sl := hash_buffr[:]
    sign_sl, err := rsa.SignPKCS1v15(rand.Reader,
                                    private_key,
                                    crypto.SHA256,
                                    hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    ////
    //SEND PROJECT
    tmp_val := []byte(cur_project)
    cur_len = []byte{byte(len(tmp_val))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                                 private_key,
                                 crypto.SHA256,
                                 hash_sl)
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(tmp_val)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                                 private_key,
                                 crypto.SHA256,
                                 hash_sl)
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(tmp_val)
    if err != nil {
      conn.Close()
      return
    }
    ////
    //SEND BRANCH
    tmp_val = []byte(cur_branch)
    cur_len = []byte{byte(len(tmp_val))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                                 private_key,
                                 crypto.SHA256,
                                 hash_sl)
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(tmp_val)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                                 private_key,
                                 crypto.SHA256,
                                 hash_sl)
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(tmp_val)
    if err != nil {
      conn.Close()
      return
    }
    ////
    //SEND DEPTH
    final_cur_len := IntToByteSlice(depth_commit_int)
    cur_len = []byte{byte(len(final_cur_len))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(final_cur_len)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(final_cur_len)
    if err != nil {
      conn.Close()
      return
    }
    //PREPARING REPO
    err = os.Mkdir(base_dir + cur_project, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.WriteFile(base_dir + cur_project + "/host_info.txt", 
                       []byte(cur_ip + ":" + cur_port),
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.WriteFile(base_dir + cur_project + "/branches.txt", 
                       []byte(cur_branch + "\n"),
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.WriteFile(base_dir + cur_project + "/cur_branch.txt", 
                       []byte(cur_branch),
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.Mkdir(base_dir + cur_project + "/" + cur_branch, 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.WriteFile(base_dir + cur_project + "/" + cur_branch + "/cur_added.txt", 
                       []byte(""),
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.WriteFile(base_dir + cur_project + "/" + cur_branch + "/cur_commit.txt", 
                       []byte(""),
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.WriteFile(base_dir + cur_project + "/" + cur_branch + "/is_pushed.txt", 
                       []byte(""),
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.Mkdir(base_dir + cur_project + "/" + cur_branch + "/sas", 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.Mkdir(base_dir + cur_project + "/" + cur_branch + "/data", 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    final_cur_len = make([]byte, cur_len[0])
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(final_cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(final_cur_len)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    target_len := ByteSliceToInt(final_cur_len)
    data = make([]byte, target_len)
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(data)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(data)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    err = os.WriteFile(base_dir + cur_project + "/" + cur_branch + "/commits.txt", data, 0644)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    ////
    //RECEIVE COMMIT DATA
    var cur_name string
    var cur_path string
    for {
      _, err = conn.Read(sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(cur_len)
      if err != nil {
        conn.Close()
        return
      }
      hash_buffr = sha256.Sum256(cur_len)
      hash_sl = hash_buffr[:]
      err = rsa.VerifyPKCS1v15(pub_key,
                              crypto.SHA256, 
                              hash_sl, 
                              sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      if cur_len[0] == 0 {
        break
      }
      _, err = conn.Read(sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(cur_len)
      if err != nil {
        conn.Close()
        return
      }
      hash_buffr = sha256.Sum256(cur_len)
      hash_sl = hash_buffr[:]
      err = rsa.VerifyPKCS1v15(pub_key,
                              crypto.SHA256, 
                              hash_sl, 
                              sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      data = make([]byte, cur_len[0])
      _, err = conn.Read(sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(data)
      if err != nil {
        conn.Close()
        return
      }
      hash_buffr = sha256.Sum256(data)
      hash_sl = hash_buffr[:]
      err = rsa.VerifyPKCS1v15(pub_key,
                              crypto.SHA256, 
                              hash_sl, 
                              sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      cur_path = base_dir + cur_project + "/" + cur_branch + "/data/" + string(data)
      err = os.Mkdir(cur_path, 0755)
      if err != nil {
        conn.Close()
        return
      }
      for {
        _, err = conn.Read(sign_sl)
        if err != nil {
          conn.Close()
          return
        }
        _, err = conn.Read(cur_len)
        if err != nil {
          conn.Close()
          return
        }
        hash_buffr = sha256.Sum256(cur_len)
        hash_sl = hash_buffr[:]
        err = rsa.VerifyPKCS1v15(pub_key,
                                crypto.SHA256, 
                                hash_sl, 
                                sign_sl)
        if err != nil {
          conn.Close()
          return
        }
        data = make([]byte, cur_len[0])
        _, err = conn.Read(sign_sl)
        if err != nil {
          conn.Close()
          return
        }
        _, err = conn.Read(data)
        if err != nil {
          conn.Close()
          return
        }
        hash_buffr = sha256.Sum256(data)
        hash_sl = hash_buffr[:]
        err = rsa.VerifyPKCS1v15(pub_key,
                                crypto.SHA256, 
                                hash_sl, 
                                sign_sl)
        if err != nil {
          conn.Close()
          return
        }
        cur_name = string(data)
        _, err = conn.Read(sign_sl)
        if err != nil {
          conn.Close()
          return
        }
        _, err = conn.Read(cur_len)
        if err != nil {
          conn.Close()
          return
        }
        hash_buffr = sha256.Sum256(cur_len)
        hash_sl = hash_buffr[:]
        err = rsa.VerifyPKCS1v15(pub_key,
                                crypto.SHA256, 
                                hash_sl, 
                                sign_sl)
        if err != nil {
          conn.Close()
          return
        }
        if cur_len[0] == 0 {
          _, err = conn.Read(sign_sl)
          if err != nil {
            conn.Close()
            return
          }
          _, err = conn.Read(cur_len)
          if err != nil {
            conn.Close()
            return
          }
          hash_buffr = sha256.Sum256(cur_len)
          hash_sl = hash_buffr[:]
          err = rsa.VerifyPKCS1v15(pub_key,
                                  crypto.SHA256, 
                                  hash_sl, 
                                  sign_sl)
          if err != nil {
            conn.Close()
            return
          }
          final_cur_len = make([]byte, cur_len[0])
          _, err = conn.Read(sign_sl)
          if err != nil {
            conn.Close()
            return
          }
          _, err = conn.Read(final_cur_len)
          if err != nil {
            conn.Close()
            return
          }
          hash_buffr = sha256.Sum256(final_cur_len)
          hash_sl = hash_buffr[:]
          err = rsa.VerifyPKCS1v15(pub_key,
                                  crypto.SHA256, 
                                  hash_sl, 
                                  sign_sl)
          if err != nil {
            conn.Close()
            return
          } 
          target_len = ByteSliceToInt(final_cur_len)
          data = make([]byte, target_len)
          _, err = conn.Read(sign_sl)
          if err != nil {
            conn.Close()
            return
          }
          _, err = conn.Read(data)
          if err != nil {
            conn.Close()
            return
          }
          hash_buffr = sha256.Sum256(data)
          hash_sl = hash_buffr[:]
          err = rsa.VerifyPKCS1v15(pub_key,
                                  crypto.SHA256, 
                                  hash_sl, 
                                  sign_sl)
          if err != nil {
            conn.Close()
            return
          }
          err = os.WriteFile(cur_path + "/" + cur_name, data, 0644)
          if err != nil {
            conn.Close()
            return
          }
        } else if cur_len[0] == 1 {
          err = os.Mkdir(cur_path + "/" + cur_name, 0755)
          if err != nil {
            conn.Close()
            return
          }
        } else if cur_len[0] == 2 {
          break
        }
      }
    }
    conn.Close()
    ////
    return
  }
  
  if frst_arg == "bring" {
    if n < 3 {
      fmt.Println("Error: the project name should been provided")
      return
    }
    cur_project := base_dir + os.Args[2]
    data, err = os.ReadFile(cur_project + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    cur_project += ("/" + string(data))
    data, err = os.ReadFile(cur_project + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    i = len(data) - 2
    i2 = 63
    tmp_val := make([]byte, 64)
    for i > -1 && data[i] != 10 {
      tmp_val[i2] = data[i]
      i2 -= 1
      i -= 1
    }
    cur_project += ("/data/" + string(tmp_val) + "/data")
    actual_dir := pre_cur_dir + cur_dir
    err = deCompressCopyDir(&cur_project, &actual_dir)
    if err != nil {
      fmt.Println("Error:", err) 
      return
    }
    data, err = os.ReadFile(base_dir + "initiated.txt")
    if err != nil {
      fmt.Println("Error:", err) 
      return
    }
    data = append(data, []byte(cur_dir + "\n")...)
    err = os.WriteFile(base_dir + "initiated.txt", data, 0644)
    if err != nil {
      fmt.Println("Error:", err) 
      return
    }
    return
  }

  if frst_arg == "seebranch" || frst_arg == "seewaitingbranch" {
    var cur_host string
    if n < 3 {
      fmt.Println("Error: host is not provided")
      return
    } else if n > 3 {
      fmt.Println("Error: too much arguments")
      return
    }
    cur_host = os.Args[2]
    var cur_ip string = ""
    var cur_port string = ""
    var cur_project string = ""
    var host_len int = len(cur_host)
    var i int = 0
    for i < host_len && cur_host[i] != ':' {
      cur_ip += string(cur_host[i])
      i++
    }
    i++
    is_valid = GoodIP(&cur_ip)
    if !is_valid {
      fmt.Println("Error: the ip provided is not good")
      return
    }
    for i < host_len && cur_host[i] != '@' {
      cur_port += string(cur_host[i])
      i++
    }
    i++
    is_valid = GoodPort(&cur_port)
    if !is_valid {
      fmt.Println("Error: the port provided is not good")
      return
    }
    for i < host_len {
      cur_project += string(cur_host[i])
      i++
    }
    if cur_project == "" {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(base_dir + "pubKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    block, _ := pem.Decode(data)
    if block == nil {
      fmt.Println("Error: Failed to decode 'pubKey.pem'")
      return
    }
    if block.Type != "RSA PUBLIC KEY" {
      fmt.Println("Error: 'pubKey.pem' does not contain an RSA public key")
      return
    }
    pub_key, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(base_dir + "privateKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    block, _ = pem.Decode(data)
    if block == nil {
      fmt.Println("Error: Failed to decode 'privateKey.pem'")
      return
    }
    if block.Type != "RSA PRIVATE KEY" {
      fmt.Println("Error: 'privateKey.pem' does not contain an RSA private key")
      return
    }
    private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    var cur_len = make([]byte, 1)
    if frst_arg == "seebranch" {
      cur_len = []byte{4}
    } else {
      cur_len = []byte{5}
    }
    hash_buffr := sha256.Sum256(cur_len)
    hash_sl := hash_buffr[:]
    sign_sl, err := rsa.SignPKCS1v15(rand.Reader,
                                    private_key,
                                    crypto.SHA256,
                                    hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    conn, err := net.Dial("tcp", cur_ip + ":" + cur_port)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    tmp_val := []byte(cur_project)
    cur_len = []byte{byte(len(tmp_val))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                               private_key,
                               crypto.SHA256,
                               hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(tmp_val)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                               private_key,
                               crypto.SHA256,
                               hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(tmp_val)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    final_cur_len := make([]byte, cur_len[0])
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(final_cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(final_cur_len)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    target_len := ByteSliceToInt(final_cur_len)
    data = make([]byte, target_len)
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(data)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(data)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    conn.Close()
    fmt.Printf("%v", string(data))
    return
  }

  if frst_arg == "seeproject" {
    var cur_host string
    if n < 3 {
      fmt.Println("Error: host is not provided")
      return
    } else if n > 3 {
      fmt.Println("Error: too much arguments")
      return
    }
    cur_host = os.Args[2]
    var cur_ip string = ""
    var cur_port string = ""
    var host_len int = len(cur_host)
    var i int = 0
    for i < host_len && cur_host[i] != ':' {
      cur_ip += string(cur_host[i])
      i++
    }
    i++
    is_valid = GoodIP(&cur_ip)
    if !is_valid {
      fmt.Println("Error: the ip provided is not good")
      return
    }
    for i < host_len {
      cur_port += string(cur_host[i])
      i++
    }
    i++
    is_valid = GoodPort(&cur_port)
    if !is_valid {
      fmt.Println("Error: the port provided is not good")
      return
    }
    data, err = os.ReadFile(base_dir + "pubKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    block, _ := pem.Decode(data)
    if block == nil {
      fmt.Println("Error: Failed to decode 'pubKey.pem'")
      return
    }
    if block.Type != "RSA PUBLIC KEY" {
      fmt.Println("Error: 'pubKey.pem' does not contain an RSA public key")
      return
    }
    pub_key, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(base_dir + "privateKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    block, _ = pem.Decode(data)
    if block == nil {
      fmt.Println("Error: Failed to decode 'privateKey.pem'")
      return
    }
    if block.Type != "RSA PRIVATE KEY" {
      fmt.Println("Error: 'privateKey.pem' does not contain an RSA private key")
      return
    }
    private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    var cur_len = []byte{6}
    hash_buffr := sha256.Sum256(cur_len)
    hash_sl := hash_buffr[:]
    sign_sl, err := rsa.SignPKCS1v15(rand.Reader,
                                    private_key,
                                    crypto.SHA256,
                                    hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    conn, err := net.Dial("tcp", cur_ip + ":" + cur_port)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    final_cur_len := make([]byte, cur_len[0])
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(final_cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(final_cur_len)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    target_len := ByteSliceToInt(final_cur_len)
    data = make([]byte, target_len)
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(data)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(data)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    conn.Close()
    fmt.Printf("%v", string(data))
    return
  }

  if frst_arg == "whoami" {
    if n > 3 {
      fmt.Println("Error: too much arguments")
      return
    }
    data, err = os.ReadFile(base_dir + "pubKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    block, _ := pem.Decode(data)
    if block == nil {
      fmt.Println("Error: Failed to decode 'pubKey.pem'")
      return
    }
    if block.Type != "RSA PUBLIC KEY" {
      fmt.Println("Error: 'pubKey.pem' does not contain an RSA public key")
      return
    }
    pub_key, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(base_dir + "privateKey.pem")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    block, _ = pem.Decode(data)
    if block == nil {
      fmt.Println("Error: Failed to decode 'privateKey.pem'")
      return
    }
    if block.Type != "RSA PRIVATE KEY" {
      fmt.Println("Error: 'privateKey.pem' does not contain an RSA private key")
      return
    }
    private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/host_info.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    cur_host := string(data)
    cur_len := []byte{7}
    hash_buffr := sha256.Sum256(cur_len)
    hash_sl := hash_buffr[:]
    sign_sl, err := rsa.SignPKCS1v15(rand.Reader,
                                    private_key,
                                    crypto.SHA256,
                                    hash_sl)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    conn, err := net.Dial("tcp", cur_host)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    _, err = conn.Write(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Write(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    _, err = conn.Read(cur_len)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(pub_key,
                             crypto.SHA256,
                             hash_sl,
                             sign_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    if cur_len[0] == 0 {
      fmt.Println("Standard user")
    } else {
      fmt.Println("Admin user")
    }
    return
  }

  fmt.Println("Error: command not found, try 'help' command")
  return
}



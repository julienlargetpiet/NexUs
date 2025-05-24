package main

import (
  "fmt"
  "os"
  "encoding/pem"
  "crypto"
  "crypto/x509"
  "crypto/sha256"
  "crypto/rsa"
  "crypto/rand"
  "net"
  "time"
  "sync"
)

var mu sync.RWMutex

func TreeSend(conn *net.Conn, 
              src string, 
              private_key *rsa.PrivateKey) (error) {
  var len_base_dir int = len(src)
  var err error
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
  var hash_buffr [32]byte
  var hash_sl []byte
  var sign_sl []byte
  var final_cur_send_len []byte
  var i int
  for n > -1 {
    cur_path = vec_dirname[n]
    fmt.Println("cur_path:", cur_path)
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
      fmt.Println("cur_path2:", cur_path_found2)
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
        mu.RLock()
        cur_send, err = os.ReadFile(cur_path_found)
        if err != nil {
          return err
        }
        mu.RUnlock()
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

func CompByteSlice(x *[]byte, x2 *[]byte) bool {
  n := len(*x)
  n2 := len(*x2)
  if n < len(*x2) {
    return false
  }
  for i := 0; i < n2; i++ {
    if (*x)[i] != (*x2)[i] {
      return false
    }
  }
  return true
}

func ExistDirFile(x *string, file_name *string) (bool, error) {
  mu.RLock()
  data, err := os.ReadFile(*file_name)
  if err != nil {
    return false, err
  }
  mu.RUnlock()
  var cur_val string = ""
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

func RunServer(admin_pub_key *rsa.PublicKey, 
               standard_pub_key *rsa.PublicKey,
               ref_rtn_data *[]byte,
               sign *[]byte,
               signb *[]byte,
               ref_rtn_data2 *[]byte,
               sign2 *[]byte,
               sign2b *[]byte,
               admin_private_key *rsa.PrivateKey,
               standard_private_key *rsa.PrivateKey) error {
  ln, err := net.Listen("tcp", "0.0.0.0:8079")
  defer ln.Close()
  if err != nil {
    return err
  }
  for {
    conn, err := ln.Accept()
    if err != nil {
      return err
    }
    go ReceiveRequest(conn, 
                      admin_pub_key, 
                      standard_pub_key,
                      ref_rtn_data,
                      sign,
                      signb,
                      ref_rtn_data2,
                      sign2,
                      sign2b,
                      admin_private_key,
                      standard_private_key)
  }
}

func CheckDeadLine(err error) {
  netErr, ok := err.(net.Error)
  if ok && netErr.Timeout() {
    fmt.Println("TimeOut")
  }
  fmt.Println("Something went wrong", err)
}

func ReceiveRequest(conn net.Conn, 
                 admin_pub_key *rsa.PublicKey,
                 standard_pub_key *rsa.PublicKey,
                 ref_rtn_data *[]byte,
                 sign *[]byte,
                 signb *[]byte,
                 ref_rtn_data2 *[]byte,
                 sign2 *[]byte,
                 sign2b *[]byte,
                 admin_private_key *rsa.PrivateKey,
                 standard_private_key *rsa.PrivateKey) {
  var n = make([]byte, 1)
  var n_sl []byte
  var err error
  var sign_rcv = make([]byte, 256)
  var hash_buffr [32]byte
  var hash_sl []byte
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_rcv)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(n)
  n_sl = n[:]
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
  } else {
    hash_buffr = sha256.Sum256(n_sl)
    hash_sl = hash_buffr[:]
    err = rsa.VerifyPKCS1v15(admin_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_rcv)
    if err != nil {
       err = rsa.VerifyPKCS1v15(standard_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_rcv)
       if err != nil {
         CheckDeadLine(err)
         conn.Close()
         return
       }
       if n[0] == 0 {
         CommitRequestStandard(conn, 
                    standard_pub_key,
                    ref_rtn_data,
                    sign,
                    ref_rtn_data2,
                    sign2)
         return
       } else if n[0] == 1 {
         SyncRequestStandard(conn, 
           standard_pub_key,
           standard_private_key)
         return
       } else if n[0] == 2 {
         GetRequestStandard(conn, 
                            standard_pub_key, 
                            standard_private_key)
         return
       }
    }
    if n[0] == 0 {
      CommitRequestAdmin(conn, 
                    admin_pub_key, 
                    ref_rtn_data,
                    signb,
                    ref_rtn_data2,
                    sign2b)
      return
    } else if n[0] == 1 {
      SyncRequestAdmin(conn, 
                    admin_pub_key,
                    admin_private_key)
      return
    } else if n[0] == 2 {
      GetRequestAdmin(conn, 
                      admin_pub_key, 
                      admin_private_key)
      return
    }
  }
  return
}

func GetRequestStandard(conn net.Conn, 
                   standard_pub_key *rsa.PublicKey,
                   standard_private_key *rsa.PrivateKey) {
  fmt.Println("Standard")
  return
}

func GetRequestAdmin(conn net.Conn,
                   admin_pub_key *rsa.PublicKey,
                   admin_private_key *rsa.PrivateKey) {
  var cur_len = make([]byte, 1)
  var data_sl []byte
  var hash_sl []byte
  var sign_sl = make([]byte, 256)
  //PROJECT VERIF
  _, err := conn.Read(sign_sl)
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
  fmt.Println("cur_len:", cur_len)
  hash_buffr := sha256.Sum256(cur_len)
  hash_sl = hash_buffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  data_sl = make([]byte, cur_len[0])
  _, err = conn.Read(sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data_sl)
  hash_sl = hash_buffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  tmp_val := string(data_sl)
  tmp_val2 := "initiated.txt"
  is_valid, err := ExistDirFile(&tmp_val, &tmp_val2)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  fmt.Println("tmp_val:", tmp_val)
  if !is_valid {
    fmt.Println("Repo does not exist")
    conn.Close()
    return
  }
  ////
  //BRANCH VERIF
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
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                            crypto.SHA256,
                            hash_sl,
                            sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  data_sl = make([]byte, cur_len[0])
  _, err = conn.Read(sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data_sl)
  hash_sl = hash_buffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                            crypto.SHA256,
                            hash_sl,
                            sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  tmp_val2 = tmp_val + "/initiated.txt"
  my_src := tmp_val
  tmp_val = string(data_sl)
  my_src += ("/" + tmp_val)
  is_valid, err = ExistDirFile(&tmp_val, &tmp_val2)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  if !is_valid {
    fmt.Println("Branch does not exist")
    conn.Close()
    return
  }
  fmt.Println("my_src:", my_src)
  ////
  //RECEIVE DEPTH
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
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  fmt.Println("cur_len:", cur_len)
  data_sl = make([]byte, cur_len[0])
  _, err = conn.Read(sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data_sl)
  hash_sl = hash_buffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                          crypto.SHA256,
                          hash_sl,
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  fmt.Println("data_sl:", data_sl)
  target_len := ByteSliceToInt(data_sl)
  data_sl, err = os.ReadFile(my_src + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  var my_vec []string
  var tmp_vec = make([]byte, 64)
  var cur_commit string = ""
  var i int = len(data_sl) - 2
  var i2 int = 0
  var i3 int = 63
  for i > -1 {
    if data_sl[i] != 10 {
      tmp_vec[i3] = data_sl[i]
    } else {
      fmt.Println("WTF", data_sl[0])
      cur_commit = string(tmp_vec)
      my_vec = append(my_vec, cur_commit)
      tmp_vec = make([]byte, 64)
      i2 += 1
      if i2 == target_len {
        break
      }
      i3 = 64
    }
    i3--
    i--
  }
  if i == -1 {
    cur_commit = string(tmp_vec)
    my_vec = append(my_vec, cur_commit)
  }
  fmt.Println("my_vec:", my_vec, len(my_vec[0]))
  fmt.Println(my_vec[0])
  ////
  //SENDING PREP FILES
  var final_cur_len []byte
  data_sl, err = os.ReadFile(my_src + "/commits.txt")
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  final_cur_len = IntToByteSlice(len(data_sl))
  cur_len = []byte{byte(len(final_cur_len))}
  hash_buffr = sha256.Sum256(cur_len)
  hash_sl = hash_buffr[:]
  sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                               admin_private_key,
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
                               admin_private_key,
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
  _, err = conn.Write(final_cur_len)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data_sl)
  hash_sl = hash_buffr[:]
  sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                               admin_private_key,
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
  _, err = conn.Write(data_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  ////
  //SENDING ACTUAL DATA
  for _, cur_commit := range my_vec {
    cur_len = []byte{1}
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                               admin_private_key,
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
    data_sl = []byte(cur_commit)
    cur_len = []byte{byte(len(data_sl))}
    hash_buffr = sha256.Sum256(cur_len)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                               admin_private_key,
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
    hash_buffr = sha256.Sum256(data_sl)
    hash_sl = hash_buffr[:]
    sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                               admin_private_key,
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
    _, err = conn.Write(data_sl)
    if err != nil {
      fmt.Println("Error:", err)
      conn.Close()
      return
    }
    fmt.Println("ici:", my_src + "/data/" + cur_commit)
    err = TreeSend(&conn, my_src + "/data/" + cur_commit, admin_private_key)
    if err != nil {
      conn.Close()
      return
    }
  }
  cur_len = []byte{0}
  hash_buffr = sha256.Sum256(cur_len)
  hash_sl = hash_buffr[:]
  sign_sl, err = rsa.SignPKCS1v15(rand.Reader,
                             admin_private_key,
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
  ////
  return
}

func CommitRequestStandard(conn net.Conn, 
                 standard_pub_key *rsa.PublicKey,
                 ref_rtn_data *[]byte,
                 sign *[]byte,
                 ref_rtn_data2 *[]byte,
                 sign2 *[]byte) {
  var cur_val string
  var cur_valb string
  var cur_val2 string
  var is_valid bool
  sign_sl := make([]byte, 256)
  var cur_len = make([]byte, 1)
  //PROJECT VERIF
  err := conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl := cur_len[:]
  hash_bffr := sha256.Sum256(cur_len)
  hash_sl := hash_bffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                        crypto.SHA256, 
                        hash_sl, 
                        sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl := make([]byte, cur_len[0])
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = data_buffr[:]
  hash_bffr = sha256.Sum256(data_sl)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                        crypto.SHA256, 
                        hash_sl, 
                        sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  cur_val = string(data_sl)
  cur_val2 = "waiting/initiated.txt"
  is_valid, err = ExistDirFile(&cur_val, &cur_val2)
  if err != nil {
    conn.Close()
    return
  }
  if !is_valid {
    conn.Close()
    return
  }
  cur_val = "waiting/" + cur_val
  ////
  //BRANCH VERIF
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = cur_len[:]
  hash_bffr = sha256.Sum256(cur_len)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = make([]byte, cur_len[0])
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = data_buffr[:]
  hash_bffr = sha256.Sum256(data_sl)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  cur_valb = string(data_sl)
  cur_val2 = cur_val + "/initiated.txt"
  is_valid, err = ExistDirFile(&cur_valb, &cur_val2)
  if err != nil {
    conn.Close()
    return
  }
  if !is_valid {
    mu.RLock()
    data, err := os.ReadFile(cur_val + "/initiated.txt")
    if err != nil {
      conn.Close()
      return
    }
    mu.RUnlock()
    data = append(data, []byte(cur_valb + "\n")...)
    mu.Lock()
    err = os.WriteFile(cur_val + "/initiated.txt", data, 0644)
    if err != nil {
      conn.Close()
      return
    }
    cur_val += ("/" + cur_valb)
    err = os.Mkdir(cur_val, 0755)
    if err != nil {
      conn.Close()
      return
    }
    err = os.WriteFile(cur_val + "/commits.txt", []byte(""), 0644)
    if err != nil {
      conn.Close()
      return
    }
    err = os.Mkdir(cur_val + "/data", 0755)
    if err != nil {
      conn.Close()
      return
    }
    mu.Unlock()
  }
  ////
  //COMMIT VERIF
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = cur_len[:]
  hash_bffr = sha256.Sum256(cur_len)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  final_cur_len := make([]byte, cur_len[0])
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(final_cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = final_cur_len[:]
  hash_bffr = sha256.Sum256(final_cur_len)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  target_len := ByteSliceToInt(final_cur_len)
  data_sl = make([]byte, target_len)
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = data_buffr[:]
  hash_bffr = sha256.Sum256(data_sl)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  mu.RLock()
  data, err := os.ReadFile(cur_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  mu.RUnlock()
  is_valid = CompByteSlice(&data_sl, &data)
  if !is_valid {
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(*sign)
    if err != nil {
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(*ref_rtn_data)
    if err != nil {
      conn.Close()
      return
    }
  }
  ////
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(*sign2)
  if err != nil {
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(*ref_rtn_data2)
  if err != nil {
    conn.Close()
    return
  }
  tmp_val := string(data_sl)
  tmp_val2 := ""
  i := len(tmp_val) - 2
  for i > -1 && tmp_val[i] != '\n' {
    tmp_val2 = string(tmp_val[i]) + tmp_val2
    i--
  }
  mu.RLock()
  data, err = os.ReadFile(cur_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  mu.RUnlock()
  data = append(data, []byte(tmp_val2 + "\n")...)
  mu.Lock()
  err = os.WriteFile(cur_val + "/commits.txt", data, 0644)
  if err != nil {
    conn.Close()
    return
  }
  cur_val += ("/data/" + tmp_val2)
  err = os.Mkdir(cur_val, 0755)
  if err != nil {
    conn.Close()
    return
  }
  mu.Unlock()
  var cur_name string
  for {
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(cur_len)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    //data_sl = cur_len[:]
    hash_bffr = sha256.Sum256(cur_len)
    hash_sl = hash_bffr[:]
    err = rsa.VerifyPKCS1v15(standard_pub_key,
                            crypto.SHA256, 
                            hash_sl, 
                            sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    data_sl = make([]byte, cur_len[0])
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(data_sl)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    //data_sl = data_buffr[:]
    cur_name = string(data_sl)
    hash_bffr = sha256.Sum256(data_sl)
    hash_sl = hash_bffr[:]
    err = rsa.VerifyPKCS1v15(standard_pub_key,
                            crypto.SHA256, 
                            hash_sl, 
                            sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(cur_len)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    //data_sl = cur_len[:]
    hash_bffr = sha256.Sum256(cur_len)
    hash_sl = hash_bffr[:]
    err = rsa.VerifyPKCS1v15(standard_pub_key,
                            crypto.SHA256, 
                            hash_sl, 
                            sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    if cur_len[0] == 0 {
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(sign_sl)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(cur_len)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      //data_sl = cur_len[:]
      hash_bffr = sha256.Sum256(cur_len)
      hash_sl = hash_bffr[:]
      err = rsa.VerifyPKCS1v15(standard_pub_key,
                              crypto.SHA256, 
                              hash_sl, 
                              sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      final_cur_len = make([]byte, cur_len[0])
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(sign_sl)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(final_cur_len)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      //data_sl = cur_len[:]
      hash_bffr = sha256.Sum256(final_cur_len)
      hash_sl = hash_bffr[:]
      err = rsa.VerifyPKCS1v15(standard_pub_key,
                              crypto.SHA256, 
                              hash_sl, 
                              sign_sl)
      if err != nil {
        conn.Close()
        return
      } 
      target_len = ByteSliceToInt(final_cur_len)
      data_sl = make([]byte, target_len)
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(sign_sl)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(data_sl)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      //data_sl = data_buffr[:]
      hash_bffr = sha256.Sum256(data_sl)
      hash_sl = hash_bffr[:]
      err = rsa.VerifyPKCS1v15(standard_pub_key,
                              crypto.SHA256, 
                              hash_sl, 
                              sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      mu.Lock()
      err = os.WriteFile("waiting/" + cur_name, data_sl, 0644)
      if err != nil {
        conn.Close()
        return
      }
      mu.Unlock()
    } else if cur_len[0] == 1 {
      mu.Lock()
      err = os.Mkdir("waiting/" + cur_name, 0755)
      if err != nil {
        conn.Close()
        return
      }
      mu.Unlock()
    } else if cur_len[0] == 2 {
      break
    }
  }
  conn.Close()
  return
}

func CommitRequestAdmin(conn net.Conn, 
                 admin_pub_key *rsa.PublicKey,
                 ref_rtn_data *[]byte,
                 sign *[]byte,
                 ref_rtn_data2 *[]byte,
                 sign2 *[]byte) {
  var cur_val string
  var cur_valb string
  var cur_val2 string
  var is_valid bool
  sign_sl := make([]byte, 256)
  var cur_len = make([]byte, 1)
  //PROJECT VERIF
  err := conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl := cur_len[:]
  hash_bffr := sha256.Sum256(cur_len)
  hash_sl := hash_bffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                        crypto.SHA256, 
                        hash_sl, 
                        sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl := make([]byte, cur_len[0])
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = data_buffr[:]
  hash_bffr = sha256.Sum256(data_sl)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                        crypto.SHA256, 
                        hash_sl, 
                        sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  cur_val = string(data_sl)
  cur_val2 = "initiated.txt"
  is_valid, err = ExistDirFile(&cur_val, &cur_val2)
  if err != nil {
    conn.Close()
    return
  }
  if !is_valid {
    //FOR STANDARD SIDE
    mu.Lock()
    err = os.Mkdir("waiting/" + cur_val, 0755)
    if err != nil {
      conn.Close()
      return
    }
    err = os.WriteFile("waiting/" + cur_val + "/initiated.txt", 
                      []byte(""), 
                      0644)
    if err != nil {
      conn.Close()
      return
    }
    mu.Unlock()
    mu.RLock()
    data_sl, err = os.ReadFile("waiting/initiated.txt")
    if err != nil {
      conn.Close()
      return
    }
    mu.RUnlock()
    data_sl = append(data_sl, []byte(cur_val + "\n")...)
    mu.Lock()
    err = os.WriteFile("waiting/initiated.txt", data_sl, 0644)
    if err != nil {
      conn.Close()
      return
    }
    ////
    //FOR ADMIN SIDE
    err = os.Mkdir(cur_val, 0755)
    if err != nil {
      conn.Close()
      return
    }
    err = os.WriteFile(cur_val + "/initiated.txt", 
                      []byte(""), 
                      0644)
    if err != nil {
      conn.Close()
      return
    }
    mu.Unlock()
    mu.RLock()
    data_sl, err = os.ReadFile("initiated.txt")
    if err != nil {
      conn.Close()
      return
    }
    mu.RUnlock()
    data_sl = append(data_sl, []byte(cur_val + "\n")...)
    mu.Lock()
    err = os.WriteFile("initiated.txt", data_sl, 0644)
    if err != nil {
      conn.Close()
      return
    }
    mu.Unlock()
    ////
  }
  ////
  //BRANCH VERIF
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = cur_len[:]
  hash_bffr = sha256.Sum256(cur_len)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = make([]byte, cur_len[0])
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = data_buffr[:]
  hash_bffr = sha256.Sum256(data_sl)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  cur_valb = string(data_sl)
  cur_val2 = cur_val + "/initiated.txt"
  is_valid, err = ExistDirFile(&cur_valb, &cur_val2)
  if err != nil {
    conn.Close()
    return
  }
  if !is_valid {
    mu.RLock()
    data, err := os.ReadFile(cur_val + "/initiated.txt")
    if err != nil {
      conn.Close()
      return
    }
    mu.RUnlock()
    data = append(data, []byte(cur_valb + "\n")...)
    mu.Lock()
    err = os.WriteFile(cur_val + "/initiated.txt", data, 0644)
    if err != nil {
      conn.Close()
      return
    }
    cur_val += ("/" + cur_valb)
    err = os.Mkdir(cur_val, 0755)
    if err != nil {
      conn.Close()
      return
    }
    err = os.WriteFile(cur_val + "/commits.txt", []byte(""), 0644)
    if err != nil {
      conn.Close()
      return
    }
    err = os.Mkdir(cur_val + "/data", 0755)
    if err != nil {
      conn.Close()
      return
    }
    mu.Unlock()
  }
  ////
  //COMMIT VERIF
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = cur_len[:]
  hash_bffr = sha256.Sum256(cur_len)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  final_cur_len := make([]byte, cur_len[0])
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(final_cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = final_cur_len[:]
  hash_bffr = sha256.Sum256(final_cur_len)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  target_len := ByteSliceToInt(final_cur_len)
  data_sl = make([]byte, target_len)
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  //data_sl = data_buffr[:]
  hash_bffr = sha256.Sum256(data_sl)
  hash_sl = hash_bffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  mu.RLock()
  data, err := os.ReadFile(cur_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  mu.RUnlock()
  is_valid = CompByteSlice(&data_sl, &data)
  if !is_valid {
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(*sign)
    if err != nil {
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Write(*ref_rtn_data)
    if err != nil {
      conn.Close()
      return
    }
  }
  ////
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(*sign2)
  if err != nil {
    conn.Close()
    return
  }
  err = conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(*ref_rtn_data2)
  if err != nil {
    conn.Close()
    return
  }
  tmp_val := string(data_sl)
  tmp_val2 := ""
  i := len(tmp_val) - 2
  for i > -1 && tmp_val[i] != '\n' {
    tmp_val2 = string(tmp_val[i]) + tmp_val2
    i--
  }
  mu.RLock()
  data, err = os.ReadFile(cur_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  mu.RUnlock()
  data = append(data, []byte(tmp_val2 + "\n")...)
  mu.Lock()
  err = os.WriteFile(cur_val + "/commits.txt", data, 0644)
  if err != nil {
    conn.Close()
    return
  }
  cur_val += ("/data/" + tmp_val2)
  err = os.Mkdir(cur_val, 0755)
  if err != nil {
    conn.Close()
    return
  }
  mu.Unlock()
  var cur_name string
  for {
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(cur_len)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    //data_sl = cur_len[:]
    hash_bffr = sha256.Sum256(cur_len)
    hash_sl = hash_bffr[:]
    err = rsa.VerifyPKCS1v15(admin_pub_key,
                            crypto.SHA256, 
                            hash_sl, 
                            sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    data_sl = make([]byte, cur_len[0])
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(data_sl)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    //data_sl = data_buffr[:]
    cur_name = string(data_sl)
    hash_bffr = sha256.Sum256(data_sl)
    hash_sl = hash_bffr[:]
    err = rsa.VerifyPKCS1v15(admin_pub_key,
                            crypto.SHA256, 
                            hash_sl, 
                            sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(sign_sl)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    err = conn.SetDeadline(time.Now().Add(1 * time.Second))
    if err != nil {
      conn.Close()
      return
    }
    _, err = conn.Read(cur_len)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    //data_sl = cur_len[:]
    hash_bffr = sha256.Sum256(cur_len)
    hash_sl = hash_bffr[:]
    err = rsa.VerifyPKCS1v15(admin_pub_key,
                            crypto.SHA256, 
                            hash_sl, 
                            sign_sl)
    if err != nil {
      conn.Close()
      return
    }
    if cur_len[0] == 0 {
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(sign_sl)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(cur_len)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      //data_sl = cur_len[:]
      hash_bffr = sha256.Sum256(cur_len)
      hash_sl = hash_bffr[:]
      err = rsa.VerifyPKCS1v15(admin_pub_key,
                              crypto.SHA256, 
                              hash_sl, 
                              sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      final_cur_len = make([]byte, cur_len[0])
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(sign_sl)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(final_cur_len)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      //data_sl = cur_len[:]
      hash_bffr = sha256.Sum256(final_cur_len)
      hash_sl = hash_bffr[:]
      err = rsa.VerifyPKCS1v15(admin_pub_key,
                              crypto.SHA256, 
                              hash_sl, 
                              sign_sl)
      if err != nil {
        conn.Close()
        return
      } 
      target_len = ByteSliceToInt(final_cur_len)
      data_sl = make([]byte, target_len)
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(sign_sl)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      err = conn.SetDeadline(time.Now().Add(1 * time.Second))
      if err != nil {
        conn.Close()
        return
      }
      _, err = conn.Read(data_sl)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      //data_sl = data_buffr[:]
      hash_bffr = sha256.Sum256(data_sl)
      hash_sl = hash_bffr[:]
      err = rsa.VerifyPKCS1v15(admin_pub_key,
                              crypto.SHA256, 
                              hash_sl, 
                              sign_sl)
      if err != nil {
        conn.Close()
        return
      }
      mu.Lock()
      err = os.WriteFile(cur_name, data_sl, 0644)
      if err != nil {
        conn.Close()
        return
      }
      mu.Unlock()
    } else if cur_len[0] == 1 {
      mu.Lock()
      err = os.Mkdir(cur_name, 0755)
      if err != nil {
        conn.Close()
        return
      }
      mu.Unlock()
    } else if cur_len[0] == 2 {
      break
    }
  }
  conn.Close()
  return
}

func SyncRequestStandard(conn net.Conn, 
                 standard_pub_key *rsa.PublicKey,
                 standard_private_key *rsa.PrivateKey) {
  var data_sl []byte
  var cur_len = make([]byte, 1)
  var sign_sl = make([]byte, 256)
  var hash_buffr [32]byte
  var hash_sl []byte
  //PROJECT VERIF
  err := conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
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
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  data_sl = make([]byte, cur_len[0])
  _, err = conn.Read(sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data_sl)
  hash_sl = hash_buffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  tmp_val := string(data_sl)
  tmp_val2 := "waiting/initiated.txt"
  is_valid, err := ExistDirFile(&tmp_val, &tmp_val2)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  if !is_valid {
    conn.Close()
    return
  }
  ////
  //BRANCH VERIF
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
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  data_sl = make([]byte, cur_len[0])
  _, err = conn.Read(data_sl)
  if err != nil {
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data_sl)
  hash_sl = hash_buffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  ref_tmp_val := "waiting/" + tmp_val
  tmp_val2 = ref_tmp_val + "/initiated.txt"
  tmp_val = string(data_sl)
  is_valid, err = ExistDirFile(&tmp_val, &tmp_val2)
  if err != nil {
    conn.Close()
    return
  }
  if !is_valid {
    conn.Close()
    return
  }
  ////
  //SENDING COMMITS HISTORY
  mu.Lock()
  data, err := os.ReadFile(ref_tmp_val + "/" + tmp_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  mu.Unlock()
  final_cur_len := IntToByteSlice(len(data))
  cur_len = []byte{byte(len(final_cur_len))}
  hash_buffr = sha256.Sum256(cur_len)
  hash_sl = hash_buffr[:]
  sign, err := rsa.SignPKCS1v15(rand.Reader,
                               standard_private_key,
                               crypto.SHA256,
                               hash_sl)
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(sign)
  if err != nil {
    conn.Close()
    return
  }
   _, err = conn.Write(cur_len)
  if err != nil {
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(final_cur_len)
  hash_sl = hash_buffr[:]
  sign, err = rsa.SignPKCS1v15(rand.Reader,
                               standard_private_key,
                               crypto.SHA256,
                               hash_sl)
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(sign)
  if err != nil {
    conn.Close()
    return
  }
   _, err = conn.Write(final_cur_len)
  if err != nil {
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data)
  hash_sl = hash_buffr[:]
  sign, err = rsa.SignPKCS1v15(rand.Reader,
                               standard_private_key,
                               crypto.SHA256,
                               hash_sl)
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(sign)
  if err != nil {
    conn.Close()
    return
  }
   _, err = conn.Write(data)
  if err != nil {
    conn.Close()
    return
  }
  conn.Close()
  ////
  return
}

func SyncRequestAdmin(conn net.Conn, 
                 admin_pub_key *rsa.PublicKey,
                 admin_private_key *rsa.PrivateKey) {
  var data_sl []byte
  var cur_len = make([]byte, 1)
  var sign_sl = make([]byte, 256)
  var hash_buffr [32]byte
  var hash_sl []byte
  //PROJECT VERIF
  err := conn.SetDeadline(time.Now().Add(1 * time.Second))
  if err != nil {
    conn.Close()
    return
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
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  data_sl = make([]byte, cur_len[0])
  _, err = conn.Read(sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Read(data_sl)
  if err != nil {
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data_sl)
  hash_sl = hash_buffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  tmp_val := string(data_sl)
  tmp_val2 := "initiated.txt"
  is_valid, err := ExistDirFile(&tmp_val, &tmp_val2)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  if !is_valid {
    conn.Close()
    return
  }
  ////
  //BRANCH VERIF
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
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  _, err = conn.Read(sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  data_sl = make([]byte, cur_len[0])
  _, err = conn.Read(data_sl)
  if err != nil {
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data_sl)
  hash_sl = hash_buffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                           crypto.SHA256,
                           hash_sl,
                           sign_sl)
  if err != nil {
    fmt.Println("Error:", err)
    conn.Close()
    return
  }
  ref_tmp_val := tmp_val
  tmp_val2 = tmp_val + "/initiated.txt"
  tmp_val = string(data_sl)
  is_valid, err = ExistDirFile(&tmp_val, &tmp_val2)
  if err != nil {
    conn.Close()
    return
  }
  if !is_valid {
    conn.Close()
    return
  }
  ////
  //SENDING COMMITS HISTORY
  mu.Lock()
  data, err := os.ReadFile(ref_tmp_val + "/" + tmp_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  mu.Unlock()
  final_cur_len := IntToByteSlice(len(data))
  cur_len = []byte{byte(len(final_cur_len))}
  hash_buffr = sha256.Sum256(cur_len)
  hash_sl = hash_buffr[:]
  sign, err := rsa.SignPKCS1v15(rand.Reader,
                               admin_private_key,
                               crypto.SHA256,
                               hash_sl)
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(sign)
  if err != nil {
    conn.Close()
    return
  }
   _, err = conn.Write(cur_len)
  if err != nil {
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(final_cur_len)
  hash_sl = hash_buffr[:]
  sign, err = rsa.SignPKCS1v15(rand.Reader,
                               admin_private_key,
                               crypto.SHA256,
                               hash_sl)
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(sign)
  if err != nil {
    conn.Close()
    return
  }
   _, err = conn.Write(final_cur_len)
  if err != nil {
    conn.Close()
    return
  }
  hash_buffr = sha256.Sum256(data)
  hash_sl = hash_buffr[:]
  sign, err = rsa.SignPKCS1v15(rand.Reader,
                               admin_private_key,
                               crypto.SHA256,
                               hash_sl)
  if err != nil {
    conn.Close()
    return
  }
  _, err = conn.Write(sign)
  if err != nil {
    conn.Close()
    return
  }
   _, err = conn.Write(data)
  if err != nil {
    conn.Close()
    return
  }
  conn.Close()
  ////
  return
}

func main () {
  data, err := os.ReadFile("standard_privateKey.pem")
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  block, _ := pem.Decode(data)
  if block == nil {
    fmt.Println("Failed to decode the RSA standard private key")
    return
  }
  if block.Type != "RSA PRIVATE KEY" {
    fmt.Println("Error: this is not a RSA private key")
    return
  }
  standard_private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
  if err != nil {
    fmt.Println("Error: failed parsing RSA standard private key")
    return
  }
  data, err = os.ReadFile("admin_privateKey.pem")
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  block, _ = pem.Decode(data)
  if block == nil {
    fmt.Println("Failed to decode the RSA admin private key")
    return
  }
  if block.Type != "RSA PRIVATE KEY" {
    fmt.Println("Error: this is not a RSA private key")
    return
  }
  admin_private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
  if err != nil {
    fmt.Println("Error: failed parsing RSA admin private key")
    return
  }
  ref_data := []byte("desync")
  hash_buffr := sha256.Sum256(ref_data)
  hash_slice := hash_buffr[:]
  sign, err := rsa.SignPKCS1v15(rand.Reader, 
                                 standard_private_key, 
                                 crypto.SHA256,
                                 hash_slice)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  signb, err := rsa.SignPKCS1v15(rand.Reader, 
                                 admin_private_key, 
                                 crypto.SHA256,
                                 hash_slice)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  ref_data2 := []byte("onsync")
  hash_buffr = sha256.Sum256(ref_data2)
  hash_slice = hash_buffr[:]
  sign2, err := rsa.SignPKCS1v15(rand.Reader, 
                                 standard_private_key, 
                                 crypto.SHA256,
                                 hash_slice)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  sign2b, err := rsa.SignPKCS1v15(rand.Reader, 
                                 admin_private_key, 
                                 crypto.SHA256,
                                 hash_slice)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  data, err = os.ReadFile("admin_pubKey.pem")
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  block, _ = pem.Decode(data)
  if block == nil {
    fmt.Println("Error: failed to decode admin_pubKey.pem")
    return
  }
  if block.Type != "RSA PUBLIC KEY" {
    fmt.Println("Error: this is not a RSA PUBLIC KEY type")
    return
  }
  admin_public_key, err := x509.ParsePKCS1PublicKey(block.Bytes)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  data, err = os.ReadFile("standard_pubKey.pem")
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  block, _ = pem.Decode(data)
  if block == nil {
    fmt.Println("Error: failed to decode standard_pubKey.pem")
    return
  }
  if block.Type != "RSA PUBLIC KEY" {
    fmt.Println("Error: this is not a RSA PUBLIC KEY type")
    return
  }
  standard_public_key, err := x509.ParsePKCS1PublicKey(block.Bytes)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  err = RunServer(admin_public_key, 
                  standard_public_key,
                  &ref_data,
                  &sign,
                  &signb,
                  &ref_data2,
                  &sign2,
                  &sign2b,
                  admin_private_key,
                  standard_private_key)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
}



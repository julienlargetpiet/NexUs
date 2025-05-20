package main

import (
  "fmt"
  "os"
  "encoding/pem"
  "encoding/binary"
  "crypto"
  "crypto/x509"
  "crypto/sha256"
  "crypto/rsa"
  "crypto/rand"
  "net"
  "time"
)

var current_connections int = 0

func ByteSliceToInt(x *[]byte) int {
  var rtn_int int = 256
  var ref_mult int = 256
  var i int = len(*x) - 1
  if i == 0 {
    return int((*x)[0])
  }
  for i > -1 {
    rtn_int = ((int((*x)[i]) + 1) * ref_mult + int((*x)[i - 1]))
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

func RunServer(admin_pub_key *rsa.PublicKey, 
               standard_pub_key *rsa.PublicKey,
               ref_rtn_data *[]byte,
               sign *[]byte,
               signb *[]byte,
               ref_rtn_data2 *[]byte,
               sign2 *[]byte,
               sign2b *[]byte) error {
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
    err = conn.SetDeadline(time.Now().Add(2 * time.Second))
    go ReceiveRequest(conn, 
                      admin_pub_key, 
                      standard_pub_key,
                      ref_rtn_data,
                      sign,
                      signb,
                      ref_rtn_data2,
                      sign2,
                      sign2b)
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
                 sign2b *[]byte) {
  var n [1]byte
  var n_sl []byte
  var err error
  var sign_rcv [256]byte
  var sign_rcv_sl []byte
  var hash_buffr [32]byte
  var hash_sl []byte
  err = binary.Read(conn, binary.LittleEndian, &sign_rcv)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_rcv_sl = sign_rcv[:]
  err = binary.Read(conn, binary.LittleEndian, &n)
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
                          sign_rcv_sl)
    if err != nil {
       err = rsa.VerifyPKCS1v15(standard_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_rcv_sl)
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
       } else {

       }
    }
    if n[0] == 0 {
      CommitRequestAdmin(conn, 
                    admin_pub_key, 
                    ref_rtn_data,
                    signb,
                    ref_rtn_data2,
                    sign2b)
    } else {
      
    }
  }
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
  sign_buffr := make([]byte, 256)
  var cur_len [1]byte
  //PROJECT VERIF
  err := binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl := sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl := cur_len[:]
  hash_bffr := sha256.Sum256(data_sl)
  hash_sl := hash_bffr[:]
  err = rsa.VerifyPKCS1v15(standard_pub_key,
                        crypto.SHA256, 
                        hash_sl, 
                        sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  data_buffr := make([]byte, cur_len[0])
  err = binary.Read(conn, binary.LittleEndian, &data_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = data_buffr[:]
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
  }
  cur_val = "waiting/" + cur_val
  ////
  //BRANCH VERIF
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = cur_len[:]
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
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  data_buffr = make([]byte, cur_len[0])
  err = binary.Read(conn, binary.LittleEndian, &data_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = data_buffr[:]
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
    fmt.Println("ici", err)
    conn.Close()
    return
  }
  if !is_valid {
    data, err := os.ReadFile(cur_val + "/initiated.txt")
    if err != nil {
      conn.Close()
      return
    }
    data = append(data, []byte(cur_valb)...)
    err = os.WriteFile(cur_val + "/initiated.txt", data, 0644)
    if err != nil {
      conn.Close()
      return
    }
    cur_val += ("/" + cur_valb)
    fmt.Println("cur_val:", cur_val)
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
  }
  ////
  //COMMIT VERIF
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = cur_len[:]
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
  final_cur_len := make([]byte, cur_len[0])
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &final_cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = final_cur_len[:]
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
  target_len := ByteSliceToInt(&final_cur_len)
  data_buffr = make([]byte, target_len)
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &data_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = data_buffr[:]
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
  data, err := os.ReadFile(cur_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  is_valid = CompByteSlice(&data_sl, &data)
  if !is_valid {
    _, err = conn.Write(*sign)
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
  _, err = conn.Write(*sign2)
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
  data, err = os.ReadFile(cur_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  data = append(data, []byte(tmp_val2 + "\n")...)
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
  var cur_name string
  for {
    err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    err = binary.Read(conn, binary.LittleEndian, &cur_len)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    data_sl = cur_len[:]
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
    data_buffr = make([]byte, cur_len[0])
    err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    err = binary.Read(conn, binary.LittleEndian, &data_buffr)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    data_sl = data_buffr[:]
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
    err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    err = binary.Read(conn, binary.LittleEndian, &cur_len)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    data_sl = cur_len[:]
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
    if cur_len[0] == 0 {
      err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      err = binary.Read(conn, binary.LittleEndian, &cur_len)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      data_sl = cur_len[:]
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
      final_cur_len = make([]byte, cur_len[0])
      err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      err = binary.Read(conn, binary.LittleEndian, &final_cur_len)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      data_sl = cur_len[:]
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
      target_len = ByteSliceToInt(&final_cur_len)
      data_buffr = make([]byte, target_len)
      err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      err = binary.Read(conn, binary.LittleEndian, &data_buffr)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      data_sl = data_buffr[:]
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
      err = os.WriteFile("waiting/" + cur_name, data_sl, 0644)
      if err != nil {
        conn.Close()
        return
      }
    } else if cur_len[0] == 1 {
      err = os.Mkdir("waiting/" + cur_name, 0755)
      if err != nil {
        conn.Close()
        return
      }
    } else if cur_len[0] == 2 {
      fmt.Println("END")
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
  sign_buffr := make([]byte, 256)
  var cur_len [1]byte
  //PROJECT VERIF
  err := binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl := sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl := cur_len[:]
  hash_bffr := sha256.Sum256(data_sl)
  hash_sl := hash_bffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                        crypto.SHA256, 
                        hash_sl, 
                        sign_sl)
  if err != nil {
    conn.Close()
    return
  }
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  data_buffr := make([]byte, cur_len[0])
  err = binary.Read(conn, binary.LittleEndian, &data_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = data_buffr[:]
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
    data_sl, err = os.ReadFile("waiting/initiated.txt")
    if err != nil {
      conn.Close()
      return
    }
    data_sl = append(data_sl, []byte(cur_val + "\n")...)
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
    data_sl, err = os.ReadFile("initiated.txt")
    if err != nil {
      conn.Close()
      return
    }
    data_sl = append(data_sl, []byte(cur_val + "\n")...)
    err = os.WriteFile("initiated.txt", data_sl, 0644)
    if err != nil {
      conn.Close()
      return
    }
    ////
  }
  ////
  //BRANCH VERIF
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = cur_len[:]
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
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  data_buffr = make([]byte, cur_len[0])
  err = binary.Read(conn, binary.LittleEndian, &data_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = data_buffr[:]
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
    data, err := os.ReadFile(cur_val + "/initiated.txt")
    if err != nil {
      conn.Close()
      return
    }
    data = append(data, []byte(cur_valb)...)
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
  }
  ////
  //COMMIT VERIF
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = cur_len[:]
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
  final_cur_len := make([]byte, cur_len[0])
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &final_cur_len)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = final_cur_len[:]
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
  target_len := ByteSliceToInt(&final_cur_len)
  data_buffr = make([]byte, target_len)
  err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  sign_sl = sign_buffr[:]
  err = binary.Read(conn, binary.LittleEndian, &data_buffr)
  if err != nil {
    CheckDeadLine(err)
    conn.Close()
    return
  }
  data_sl = data_buffr[:]
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
  data, err := os.ReadFile(cur_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  is_valid = CompByteSlice(&data_sl, &data)
  if !is_valid {
    _, err = conn.Write(*sign)
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
  _, err = conn.Write(*sign2)
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
  data, err = os.ReadFile(cur_val + "/commits.txt")
  if err != nil {
    conn.Close()
    return
  }
  data = append(data, []byte(tmp_val2 + "\n")...)
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
  var cur_name string
  for {
    err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    err = binary.Read(conn, binary.LittleEndian, &cur_len)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    data_sl = cur_len[:]
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
    data_buffr = make([]byte, cur_len[0])
    err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    err = binary.Read(conn, binary.LittleEndian, &data_buffr)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    data_sl = data_buffr[:]
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
    err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    err = binary.Read(conn, binary.LittleEndian, &cur_len)
    if err != nil {
      CheckDeadLine(err)
      conn.Close()
      return
    }
    sign_sl = sign_buffr[:]
    data_sl = cur_len[:]
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
    if cur_len[0] == 0 {
      err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      err = binary.Read(conn, binary.LittleEndian, &cur_len)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      data_sl = cur_len[:]
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
      final_cur_len = make([]byte, cur_len[0])
      err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      err = binary.Read(conn, binary.LittleEndian, &final_cur_len)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      data_sl = cur_len[:]
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
      target_len = ByteSliceToInt(&final_cur_len)
      data_buffr = make([]byte, target_len)
      err = binary.Read(conn, binary.LittleEndian, &sign_buffr)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      err = binary.Read(conn, binary.LittleEndian, &data_buffr)
      if err != nil {
        CheckDeadLine(err)
        conn.Close()
        return
      }
      sign_sl = sign_buffr[:]
      data_sl = data_buffr[:]
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
      err = os.WriteFile(cur_name, data_sl, 0644)
      if err != nil {
        conn.Close()
        return
      }
    } else if cur_len[0] == 1 {
      err = os.Mkdir(cur_name, 0755)
      if err != nil {
        conn.Close()
        return
      }
    } else if cur_len[0] == 2 {
      break
    }
  }
  return
}

func SyncRequestStandard(conn *net.Conn, 
                 standard_pub_key *rsa.PublicKey) {

}

func SyncRequestAdmin(conn *net.Conn, 
                 admin_pub_key *rsa.PublicKey) {

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
    fmt.Println(err)
    return
  }
  signb, err := rsa.SignPKCS1v15(rand.Reader, 
                                 admin_private_key, 
                                 crypto.SHA256,
                                 hash_slice)
  if err != nil {
    fmt.Println(err)
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
    fmt.Println(err)
    return
  }
  sign2b, err := rsa.SignPKCS1v15(rand.Reader, 
                                 admin_private_key, 
                                 crypto.SHA256,
                                 hash_slice)
  if err != nil {
    fmt.Println(err)
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
                  &sign2b)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
}



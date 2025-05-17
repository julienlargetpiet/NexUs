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
               ref_rtn_data2 *[]byte,
               sign2 *[]byte) error {
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
    go ReceiveRequest(&conn, 
                      admin_pub_key, 
                      standard_pub_key,
                      ref_rtn_data,
                      sign,
                      ref_rtn_data2,
                      sign2)
  }
}

func CheckDeadLine(err error) {
  netErr, ok := err.(net.Error)
  if ok && netErr.Timeout() {
    fmt.Println("TimeOut")
  }
  fmt.Println("Something went wrong", err)
}

func ReceiveRequest(conn *net.Conn, 
                 admin_pub_key *rsa.PublicKey,
                 standard_pub_key *rsa.PublicKey,
                 ref_rtn_data *[]byte,
                 sign *[]byte,
                 ref_rtn_data2 *[]byte,
                 sign2 *[]byte) {
  var n int32
  var err error
  err = binary.Read(*conn, binary.LittleEndian, &n)
  if err != nil {
    CheckDeadLine(err)
    (*conn).Close()
  } else {
    if n == 0 {
      CommitRequest(conn, 
                    admin_pub_key, 
                    standard_pub_key,
                    ref_rtn_data,
                    sign,
                    ref_rtn_data2,
                    sign2)
    } else {
      
    }
  }
  return
}

func CommitRequest(conn *net.Conn, 
                 admin_pub_key *rsa.PublicKey,
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
  var cur_len int64
  err := binary.Read(*conn, binary.LittleEndian, &sign_buffr)
  if err != nil {
    CheckDeadLine(err)
    (*conn).Close()
    return
  }
  sign_sl := sign_buffr[:]
  err = binary.Read(*conn, binary.LittleEndian, &cur_len)
  if err != nil {
    CheckDeadLine(err)
    (*conn).Close()
    return
  }
  data_buffr := make([]byte, cur_len)
  err = binary.Read(*conn, binary.LittleEndian, &data_buffr)
  if err != nil {
    CheckDeadLine(err)
    (*conn).Close()
    return
  }
  data_sl := data_buffr[:]
  hash_bffr := sha256.Sum256(data_sl)
  hash_sl := hash_bffr[:]
  err = rsa.VerifyPKCS1v15(admin_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
  if err != nil {
     err = rsa.VerifyPKCS1v15(standard_pub_key,
                          crypto.SHA256, 
                          hash_sl, 
                          sign_sl)
    if err != nil {
      (*conn).Close()
      return
    }
    cur_val = string(data_sl)
    cur_val2 = "initiated.txt"
    is_valid, err = ExistDirFile(&cur_val, &cur_val2)
    if err != nil {
      (*conn).Close()
      return
    }
    if !is_valid {
      (*conn).Close()
      return
    }
    err = binary.Read(*conn, binary.LittleEndian, &sign_buffr)
    if err != nil {
      CheckDeadLine(err)
      (*conn).Close()
      return
    }
    sign_sl = sign_buffr[:]
    err = binary.Read(*conn, binary.LittleEndian, &cur_len)
    if err != nil {
      CheckDeadLine(err)
      (*conn).Close()
      return
    }
    data_buffr = make([]byte, cur_len)
    err = binary.Read(*conn, binary.LittleEndian, &data_buffr)
    if err != nil {
      CheckDeadLine(err)
      (*conn).Close()
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
      (*conn).Close()
      return
    }
    cur_valb = string(data_sl)
    cur_val2 = cur_valb + "/initiated.txt"
    is_valid, err = ExistDirFile(&cur_valb, &cur_val2)
    if err != nil {
      (*conn).Close()
      return
    }
    if !is_valid {
      cur_val += ("/" + cur_valb)
      err = os.Mkdir(cur_val, 0755)
      if err != nil {
        (*conn).Close()
        return
      }
    }
    err = binary.Read(*conn, binary.LittleEndian, &sign_buffr)
    if err != nil {
      CheckDeadLine(err)
      (*conn).Close()
      return
    }
    sign_sl = sign_buffr[:]
    err = binary.Read(*conn, binary.LittleEndian, &cur_len)
    if err != nil {
      CheckDeadLine(err)
      (*conn).Close()
      return
    }
    data_buffr = make([]byte, cur_len)
    err = binary.Read(*conn, binary.LittleEndian, &data_buffr)
    if err != nil {
      CheckDeadLine(err)
      (*conn).Close()
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
      (*conn).Close()
      return
    }
    data, err := os.ReadFile(cur_val + "/commits.txt")
    if err != nil {
      (*conn).Close()
      return
    }
    is_valid = CompByteSlice(&data_sl, &data)
    if !is_valid {
      _, err = (*conn).Write(*sign)
      if err != nil {
        (*conn).Close()
        return
      }
      _, err = (*conn).Write(*ref_rtn_data)
      if err != nil {
        (*conn).Close()
        return
      }
    }
    _, err = (*conn).Write(*sign2)
    if err != nil {
      (*conn).Close()
      return
    }
    _, err = (*conn).Write(*ref_rtn_data2)
    if err != nil {
      (*conn).Close()
      return
    }
    return
  }
  return
}

func SyncRequest(conn *net.Conn, 
                 admin_pub_key *rsa.PublicKey,
                 standard_pub_key *rsa.PublicKey) {

}

func main () {
  data, err := os.ReadFile("privateKey.pem")
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  block, _ := pem.Decode(data)
  if block == nil {
    fmt.Println("Failed to decode the RSA private key")
    return
  }
  if block.Type != "RSA PRIVATE KEY" {
    fmt.Println("Error: this is not a RSA private key")
    return
  }
  standard_private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
  if err != nil {
    fmt.Println("Error: failed parsing RSA private key")
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
  ref_data2 := []byte("onsync")
  hash_buffr = sha256.Sum256(ref_data)
  hash_slice = hash_buffr[:]
  sign2, err := rsa.SignPKCS1v15(rand.Reader, 
                                 standard_private_key, 
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
    fmt.Println("Error: failed to decode pubKey.pem")
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
  data, err = os.ReadFile("admin_pubKey.pem")
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
  block, _ = pem.Decode(data)
  if block == nil {
    fmt.Println("Error: failed to decode pubKey.pem")
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
                  &ref_data2,
                  &sign2)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }
}



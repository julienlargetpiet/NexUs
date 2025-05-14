package main

import (
  "fmt"
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha256"
  "reflect"
)

//best practice to sign tha hash of a text than directly the text

func main() {
  data := []byte("okok lolokok lolokok lolokok lolokok lolokok lolo1kok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lolokok lol")
  hash_bfr := sha256.Sum256(data)
  hash_slice := hash_bfr[:]

  fmt.Println(hash_slice, len(hash_slice), reflect.TypeOf(hash_slice))

  private_key, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Println(err)
    return
  }
  sign, err := rsa.SignPKCS1v15(rand.Reader, 
                               private_key, 
                               crypto.SHA256,
                               hash_slice)
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println(sign, len(sign), reflect.TypeOf(sign))

  err = rsa.VerifyPKCS1v15(&private_key.PublicKey,
                          crypto.SHA256, 
                          hash_slice, 
                          sign)
  if err != nil {
    fmt.Println(err)
    return
  }

  fmt.Println("all good")
  return

}




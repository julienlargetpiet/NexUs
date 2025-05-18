package main

import (
  "fmt"
  "os"
  "crypto/rsa"
  "crypto/x509"
  "crypto/rand"
  "encoding/pem"
)

func main() {
  private_key, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Println(err)
    return
  }
  public_key := &private_key.PublicKey
  private_key_bytes := x509.MarshalPKCS1PrivateKey(private_key)
  privatekeyPEM := pem.EncodeToMemory(
                   &pem.Block{Type: "RSA PRIVATE KEY", 
                   Bytes: private_key_bytes})
  err = os.WriteFile("standard_privateKey.pem", 
                    privatekeyPEM, 0644)
  if err != nil {
    fmt.Print(err)
    return
  }
  public_key_bytes := x509.MarshalPKCS1PublicKey(public_key)
  if err != nil {
    fmt.Println(err)
    return
  }
  publickeyPEM := pem.EncodeToMemory(
                   &pem.Block{Type: "RSA PUBLIC KEY", 
                   Bytes: public_key_bytes})
  err = os.WriteFile("standard_pubKey.pem", 
                    publickeyPEM, 0644)
  if err != nil {
    fmt.Print(err)
    return
  }
  private_key, err = rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    fmt.Println(err)
    return
  }
  public_key = &private_key.PublicKey
  private_key_bytes = x509.MarshalPKCS1PrivateKey(private_key)
  privatekeyPEM = pem.EncodeToMemory(
                   &pem.Block{Type: "RSA PRIVATE KEY", 
                   Bytes: private_key_bytes})
  err = os.WriteFile("admin_privateKey.pem", 
                    privatekeyPEM, 0644)
  if err != nil {
    fmt.Print(err)
    return
  }
  public_key_bytes = x509.MarshalPKCS1PublicKey(public_key)
  if err != nil {
    fmt.Println(err)
    return
  }
  publickeyPEM = pem.EncodeToMemory(
                   &pem.Block{Type: "RSA PUBLIC KEY", 
                   Bytes: public_key_bytes})
  err = os.WriteFile("admin_pubKey.pem", 
                    publickeyPEM, 0644)
  if err != nil {
    fmt.Print(err)
    return
  }
}



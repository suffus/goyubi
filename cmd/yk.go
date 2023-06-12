package main

import (
    "yubi"
    "flag"
    "fmt"
    "os"
)


func main() {
    keyFile := flag.String("key-file", "", "Yubi key file")
    input := flag.String("input", "", "Yubi key input")
    id := flag.Int("id", -1, "ID for a new key")
    flag.Parse()
    if *keyFile == "" {
        fmt.Println("No key file specified!")
        return
    }
    keyF, err := os.OpenFile(*keyFile, os.O_RDWR|os.O_CREATE, 0700)
    if err != nil {
        fmt.Println("Error opening key file", err)
    }
    if *id > 0 {
        yubi := yubi.New( *id )
        code, err := yubi.GenerateCode()
        if err != nil {
          fmt.Println("Error - ", err)
          return
        }
        fmt.Println("Writing new key file", code)
        keyF.Write(yubi.AsBytes())
        return
    }
    // now read the key keyFile

    buf := make( []byte, 32 )
    n, err := keyF.Read(buf)
    if err != nil || n != 32 {
        fmt.Println("not a valid key file")
        return
    }
    yubi, err := yubi.FromBytes(buf)
    if err != nil {
        fmt.Println("Error - ",err)
        return
    }

    if *input != "" {
        fmt.Println("Input is", input)
        newYubi, err := yubi.VerifyCode(*input)
        if err != nil {
            fmt.Println("Failed to verify", err)
            return
        } else {
            fmt.Println("Verified!")
        }
        yubi = newYubi
    } else {
        code, err := yubi.GenerateCode()
        if err!= nil {
          fmt.Println("Error generating code", err)
          return
        }
        fmt.Println(code)
    }
    keyF.Seek(0, 0)
    keyF.Write(yubi.AsBytes())

    return
}

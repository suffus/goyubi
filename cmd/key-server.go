package main

import (
    "yubi"
    "flag"
    "fmt"
    "os"
    "net/http"
    "encoding/json"
    "encoding/base64"
    "sync"
    "errors"
)

var keyDirectory = "/var/keys"

var globalLock sync.Mutex

type flock struct {
    MU sync.Mutex
    Name string
}

var keyFileLocks = make(map[string]*flock)

func getKeyLock(fn string) error {
    // first check file exists
    globalLock.Lock()
    if _, err := os.Stat(fn); err != nil {
        // file cannot be statted
        globalLock.Unlock()
        return err
    }
    lock, ok := keyFileLocks[fn]
    if !ok {
        lock = &flock{sync.Mutex{},fn}
        keyFileLocks[fn] = lock
    }
    globalLock.Unlock()
    lock.MU.Lock()
    return nil
}

func releaseKeyLock(fn string) error {
    globalLock.Lock()
    lock, ok := keyFileLocks[fn]
    if !ok {
        globalLock.Unlock()
        return errors.New("Lock does not exist")
    }
    globalLock.Unlock()
    lock.MU.Unlock()
    return nil
}

func verify(w http.ResponseWriter, req *http.Request) {
    resp := make(map[string]string)
    for {
        code := req.FormValue("token")
        if len(code) != 44 {
            w.WriteHeader(http.StatusBadRequest)
            resp["message"] = "BAD_TOKEN_FORMAT"
            break
        }
        bytes := []byte(code)
        keyNum := string(bytes[:12])
        keyFileName := fmt.Sprintf("%s/%s.key", keyDirectory, keyNum)
        err := getKeyLock(keyFileName)
        if err != nil {
            w.WriteHeader(http.StatusNotFound)
            resp["message"] = "NO_KEY"
            break;
        }
        defer releaseKeyLock(keyFileName)
        keyFile, err := os.OpenFile(keyFileName, os.O_RDWR, 0700)
        if err != nil {
            w.WriteHeader(http.StatusNotFound)
            resp["message"] = "WIERD_SHIT"
            break
        }
        buffer := make([]byte, 32)
        n, err := keyFile.Read(buffer)
        if err!= nil || n != 32 {
              w.WriteHeader(http.StatusInternalServerError)
              resp["message"] = "FILE_ERROR_1"
              break
        }
        yubi, err := yubi.FromBytes(buffer)
        if err != nil {
              w.WriteHeader(http.StatusInternalServerError)
              resp["message"] = "FILE_ERROR_2"
              break
        }
        newYubi, err := yubi.VerifyCode(code)
        if err != nil {
              w.WriteHeader(http.StatusUnauthorized)
              resp["message"] = "VERIFICATION_ERROR"
              resp["detail"] = err.Error()
              break
        }
        keyFile.Seek(0,0)
        n, err = keyFile.Write(newYubi.AsBytes())
        if err != nil || n != 32 {
              w.WriteHeader(http.StatusInternalServerError)
              resp["message"] = "FILE_ERROR_3"
              resp["detail"] = err.Error()
              break
        }
        keyFile.Close()
        resp["message"] = "VERIFIED_OK"
        w.WriteHeader(http.StatusOK)
        break
    }
    json_out, _ := json.Marshal( resp )
    w.Header().Set("Content-Type", "application/json")
    w.Write(json_out)
}

func newKey(w http.ResponseWriter, req *http.Request) {
    globalLock.Lock()
    defer globalLock.Unlock()
    resp := make(map[string]string)
    for {
        keyNumFileName := fmt.Sprintf("%s/keynum", keyDirectory)
        if _, err := os.Stat(keyNumFileName); err != nil {
            w.WriteHeader(http.StatusInternalServerError)
            resp["message"] = "NO_KEY_NUM_FILE"
            break
        }
        keyNumFile, err := os.OpenFile(keyNumFileName, os.O_RDWR, 0644)
        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
            resp["message"] = "BAD_KEY_NUM_FILE 1"
            break
        }
        code := make([]byte, 12)
        if n, err := keyNumFile.Read(code); err != nil || n != 12 {
            w.WriteHeader(http.StatusInternalServerError)
            resp["message"] = "BAD_KEY_NUM_FILE 2"
            break
        }
        keyNumBytes, err := yubi.DecodeModHex(string(code))
        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
            resp["message"] = "BAD_KEY_NUM_FILE 3"
            break
        }
        keyNum := yubi.DecodeBE(keyNumBytes)
        keyNum += 1
        newYubi := yubi.New(keyNum)
        name := yubi.EncodeModHex(yubi.EncodeBE(keyNum, 6))
        keyFile, err := os.OpenFile(fmt.Sprintf("%s/%s.key", keyDirectory, name), os.O_RDWR|os.O_CREATE, 0600)
        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
            resp["message"] = "CANNOT_CREATE_KEY_FILE"
            break
        }
        keyBytes := newYubi.AsBytes()
        n, err := keyFile.Write(keyBytes)
        if err != nil || n != 32 {
            /// deal with failed write
        }
        keyNumFile.Seek(0,0)
        keyNumFile.Write([]byte(name))
        resp["message"] = "KEY_OK"
        resp["key-name"] = name
        resp["key-data"] = base64.StdEncoding.EncodeToString(keyBytes)
        w.WriteHeader(http.StatusOK)
        break
    }
    outs, _ := json.Marshal(resp)
    w.Header().Set("Content-Type", "application/json")
    w.Write( outs )
}

func main() {
    keyDir := flag.String("key-dir", "/var/yubi/keys", "Directory where key files are stored")
    flag.Parse()
    keyDirectory = *keyDir
    keyFileLocks = make(map[string]*flock)
    verifyFunc := http.HandlerFunc(verify)
    newKeyFunc := http.HandlerFunc(newKey)
    http.Handle("/verify", verifyFunc)
    http.Handle("/new", newKeyFunc)
    http.ListenAndServe(":8800", nil)
}

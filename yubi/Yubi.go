package yubi

import (
  "crypto/aes"
  "crypto/rand"
  "time"
  "errors"
  //"fmt"
)

type YubiData struct {
    Id  [6]byte
    UseCtr  [2]byte
    Timestamp [3]byte
    SessionCtr byte
    Rnd [2]byte
    Checksum [2]byte
    Secret [16]byte
}

func New(id int) YubiData {
    yubi := YubiData{}
    copy(yubi.Id[:], encodeLE(id, 6))
    rand.Read(yubi.Secret[:])
    yubi.incrementCounter()
    yubi.setTimestamp()
    yubi.setChecksum()
    return yubi
}

func FromBytes( buf []byte ) (YubiData, error) {
    yubi := YubiData{}
    copy(yubi.Id[:], buf[:6])
    copy(yubi.UseCtr[:], buf[6:8])
    copy(yubi.Timestamp[:], buf[8:11])
    yubi.SessionCtr = buf[11]
    copy(yubi.Rnd[:], buf[12:14])
    copy(yubi.Checksum[:], buf[14:16])
    copy(yubi.Secret[:], buf[16:32])
    if !yubi.checkChecksum() {
        return YubiData{}, errors.New("Bad Checksum!")
    }
    return yubi, nil
}

func decodeBE(bytes []byte) int {
    rv := 0
    for i := 0; i < len(bytes); i++ {
        rv *= 256
        rv += int(bytes[i])
    }
    return rv
}

func decodeLE(bytes []byte) int {
    rv := 0
    for i := len(bytes)-1; i>=0; i-- {
        rv *= 256
        rv += int(bytes[i])
    }
    return rv
}

func DecodeBE(bytes []byte) int {
    return decodeBE(bytes)
}

func EncodeBE(val int, sz int) []byte {
    return encodeBE(val, sz)
}

func encodeBE(val int, sz int) []byte {
    out := make([]byte, sz)
    for i := sz-1; i >= 0; i-- {
        out[i] = byte(val & 255)
        val /= 256
    }
    return out
}

func encodeLE(val int, sz int) []byte {
    out := make([]byte, sz)
    for i := 0; i < sz; i++ {
        out[i] = byte(val & 255)
        val /= 256
    }
    return out
}

func (yubi *YubiData) getId( ) int {
    return decodeLE(yubi.Id[:])
}

func (yubi *YubiData) getUseCtr() int {
    return decodeLE(yubi.UseCtr[:])
}

func (yubi *YubiData) getTimestamp() int {
    return decodeLE(yubi.Timestamp[:])
}

func (yubi *YubiData) getSessionCtr() int {
    return int(yubi.SessionCtr)
}

func (yubi *YubiData) setUseCtr( val uint16 ) {
    lev := encodeLE(int(val), 2)
    copy(yubi.UseCtr[:], lev)
}

func (yubi *YubiData) setTimestamp( ) {
    ts := time.Now().UnixNano() / 1e6
    ts *= 8
    ts /= 1000
    ts -= 8*1680000000 // March 2023
    lev := encodeLE(int(ts), 3)
    copy(yubi.Timestamp[:], lev)
}

func (yubi *YubiData) setChecksum( ) {
    buf := yubi.AsBytes()
    crc := crc16(buf[:14])
    crc ^= 0xffff
    crcLev := encodeLE(int(crc),2)
    copy(yubi.Checksum[:], crcLev)
}

func (yubi* YubiData) setRandom( ) {
    rand.Read(yubi.Rnd[:])
}

func (yubi *YubiData) checkChecksum( ) bool {
      buf := yubi.AsBytes()
      crc := crc16(buf[:16])
      return crc == 0xf0b8
}

func cpyb( arr []byte, offset int, cpy []byte ) {
    copy(arr[offset:offset+len(cpy)], cpy)
}

func (yubi *YubiData) AsBytes() []byte {
    out := make([]byte, 32)
    cpyb(out, 0, yubi.Id[:])
    cpyb(out, 6, yubi.UseCtr[:])
    cpyb(out, 8, yubi.Timestamp[:])
    out[11] = yubi.SessionCtr
    cpyb(out, 12, yubi.Rnd[:])
    cpyb(out, 14, yubi.Checksum[:])
    cpyb(out, 16, yubi.Secret[:])
    return out
}

func crc16(buf []byte) uint16 {
    crc := uint16(0xffff)
    for i := 0; i < len(buf); i++ {
        crc ^= uint16(buf[i]);
        for j := 0; j < 8; j++ {
            z :=  crc & 1
            crc >>= 1
            if z != 0 {
                crc ^= 0x8408
            }
        }
    }
    return crc
}

func (yubi *YubiData) incrementCounter() error {
    ctr := yubi.getUseCtr()
    if( ctr < 0x7fff ) {
        yubi.setUseCtr(uint16(ctr+1))
        return nil
    }
    return errors.New("No uses left on device")
}

var modHexEncoding = [16]byte{'c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v'}

var modHexMap = map[byte]int{
  'c': 0,
  'b': 1,
  'd': 2,
  'e': 3,
  'f': 4,
  'g': 5,
  'h': 6,
  'i': 7,
  'j': 8,
  'k': 9,
  'l': 10,
  'n': 11,
  'r': 12,
  't': 13,
  'u': 14,
  'v': 15,
}

func EncodeModHex(buf []byte) string {
    outArray := make([]byte, 2*len(buf))
    for i := 0; i < len(buf); i++ {
        lo := buf[i] & 0xf
        hi := (buf[i]>>4) & 0xf
        outArray[2*i] = modHexEncoding[hi]
        outArray[2*i+1] = modHexEncoding[lo]
    }
    return string(outArray)
}

func DecodeModHex(buf_str string) ([]byte, error) {
    buf := []byte(buf_str)
    outArray := make([]byte, len(buf)/2)
    for i := 0; i < len(buf)/2; i++ {
        outArray[i] = byte(modHexMap[buf[2*i]])*16+byte(modHexMap[buf[2*i+1]])
    }
    return outArray, nil
}

func (yubi *YubiData) GenerateCode() (string, error) {
    yubi.SessionCtr += 1
    if yubi.SessionCtr == 0 {
        err := yubi.incrementCounter()
        if err != nil {
            return "", err
        }
    }
    yubi.setTimestamp()
    yubi.setRandom()
    yubi.setChecksum()
    c, err := aes.NewCipher(yubi.Secret[:])
    if err != nil {
        return "", err
    }
    num := encodeBE(yubi.getId(),6)
    out := make([]byte, 16)
    c.Encrypt(out[:], yubi.AsBytes()[:16])
    return EncodeModHex(append(num,out...)), nil
}

func (yubi *YubiData) VerifyCode( code string ) (YubiData, error) {
    bytes, err := DecodeModHex(code)
    if err != nil {
        return YubiData{}, err
    }
    c, err := aes.NewCipher(yubi.Secret[:])
    if err != nil {
        return YubiData{}, err
    }
    in := make([]byte, 16)
    c.Decrypt(in[:], bytes[6:])
    cryptYubi, err := FromBytes(append(in, yubi.Secret[:]...))
    if err != nil {
        return YubiData{}, err
    }
    if yubi.getId() != cryptYubi.getId() {
        return YubiData{}, errors.New("Bad ID")
    }
    if 256*yubi.getUseCtr() + yubi.getSessionCtr() >= 256*cryptYubi.getUseCtr() + cryptYubi.getSessionCtr() {
        return YubiData{}, errors.New("Replayed OTP")
    }
    return cryptYubi, nil
}
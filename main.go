package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"googlemaps.github.io/maps"
)

func main() {
	dir := "~/.protect_yourhome/"
	apikey := ""
	address := ""
	reconstruct := false
	file := []byte{}
	var (
		privKey *rsa.PrivateKey
		pubKey  *rsa.PublicKey
	)
	flag.StringVar(&apikey, "k", "", "set your apikey. (goto [console.developers.google.com], create your project, turn on api, enable geocoding api, and copy your api key)")
	flag.StringVar(&address, "a", "", "set your home address.")
	flag.BoolVar(&reconstruct, "r", false, "reconfig your app")
	flag.Parse()
	type Info struct {
		Key     string `json:"apiKey"`
		Address string `json:"address"`
		LatLng  string `json:"latlng"`
	}
	func() { // mkdir app dir
		if _, err := os.Stat(func() (r string) { r, _ = homedir.Expand(dir); return }()); err != nil {
			if os.IsNotExist(err) {
				os.MkdirAll(func() (r string) { r, _ = homedir.Expand(dir); return }(), 0700)
			}
		}
	}()
	func() { // touch app config file
		var err error
		file, err = ioutil.ReadFile(func() (r string) { r, _ = homedir.Expand(dir + "data"); return }())
		if err != nil {
			err = ioutil.WriteFile(func() (r string) { r, _ = homedir.Expand(dir + "data"); return }(), func() []byte {
				s, e := json.Marshal(&Info{})
				if e != nil {
					log.Println(e.Error())
					os.Exit(1)
				}
				return s
			}(), 0700)
			if err != nil {
				log.Println("permission denied. cannot write to :[~/.protect-yourhome/data]")
				os.Exit(1)
			}
		}
	}()
	func() { // generate app key (if exist, use it.)
		if f, e := ioutil.ReadFile(func() (r string) { r, _ = homedir.Expand(dir + ".pem"); return }()); e == nil { // .pem file exist
			block, remainB := pem.Decode(f)
			if len(remainB) > 0 {
				log.Println(string(remainB))
				os.Exit(1)
			}
			b := block.Bytes
			var err error
			privKey, err = x509.ParsePKCS1PrivateKey(b)
			if err != nil {
				log.Println(err.Error())
				return
			}
			pubKey = &privKey.PublicKey
		} else if e != nil { // .pem file not exist
			size := 2048
			var err error
			privKey, err = rsa.GenerateKey(rand.Reader, size)
			if err != nil {
				log.Println(err.Error())
				os.Exit(1)
			}
			err = ioutil.WriteFile(
				func() (r string) { r, _ = homedir.Expand(dir + ".pem"); return }(),
				pem.EncodeToMemory(
					&pem.Block{
						Type:  "RSA PRIVATE KEY",
						Bytes: x509.MarshalPKCS1PrivateKey(privKey),
					},
				),
				0600)
			if err != nil {
				// log.Println("sorry, something wrong. pls contact qsf@de-liker.com")
				log.Println(err.Error())
				os.Exit(1)
			}
			pubKey = &privKey.PublicKey
		}
	}()
	// here: restore from file
	info := Info{}
	decryptedApiKey, encryptedApiKey, decryptedAddress, encryptedAddress, encryptedLatLng := "", "", "", "", ""
	err := json.Unmarshal(file, &info)
	if err != nil {
		log.Println(err.Error() + " or is this first time to launch this app?")
		return
	}
	info.Key = func() string { s, _ := base64.StdEncoding.DecodeString(info.Key); return string(s) }()
	info.Address = func() string { s, _ := base64.StdEncoding.DecodeString(info.Address); return string(s) }()
	// info.LatLng = func() string { s, _ := base64.StdEncoding.DecodeString(info.LatLng); return string(s) }()
	// ApiKey
	func() {
		if info.Key == "" && apikey == "" { // APIKEY: [file: no, input: no]
			log.Println("set your apikey by using -k option. (goto [console.developers.google.com], create your project, turn on api, enable geocoding api, copy your api key, and run command like this: [protect-yourhome -k your_api_key])")
			return
		} else if info.Key != "" && apikey == "" { // APIKEY: [file: yes, input: no]
			decryptedApiKey, err = func() (string, error) {
				b, e := rsa.DecryptPKCS1v15(rand.Reader, privKey, []byte(info.Key))
				return string(b), e
			}()
			if err != nil {
				log.Println("sorry, something wrong. pls contact [qsf@de-liker.com].")
				// os.Exit(1)
				return
			}
			encryptedApiKey = info.Key
		} else if apikey != "" { // APIKEY: [file: both, input: yes]
			encryptedApiKey, err = func() (string, error) {
				s, e := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(apikey))
				return string(s), e
			}()
			if err != nil {
				log.Println(err.Error())
				return
			}
			decryptedApiKey = apikey
			reconstruct = true
			log.Println("apikey: encrypt: success!")
		}
	}()
	// Address
	func() {
		if info.Address == "" && address == "" { // ADDRESS: [file: no, input: no]
			log.Println("set your home address by using -a option. (run command like this: [protect-yourhome -a your_home_address])")
			return
		} else if info.Address != "" && address == "" { // ADDRESS: [file: yes, input: no]
			decryptedAddress, err = func() (string, error) {
				s, e := rsa.DecryptPKCS1v15(rand.Reader, privKey, []byte(info.Address))
				return string(s), e
			}()
			if err != nil {
				// log.Println("sorry, something wrong. pls contact [qsf@de-liker.com].")
				log.Println(err.Error())
				// os.Exit(1)
				return
			}
			encryptedAddress = info.Address
		} else if address != "" { // ADDRESS: [file: both, input: yes]
			encryptedAddress, err = func() (string, error) {
				s, e := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(address))
				return string(s), e
			}()
			if err != nil {
				log.Println("sorry, something wrong. pls contact [qsf@de-liker.com].")
				// os.Exit(1)
				return
			}
			decryptedAddress = address
			reconstruct = true
			log.Println("address: encrypt: success!")
		}
	}()
	// LatLng
	// if info.LatLng == "" {
	// 	log.Println("sorry, something wrong. pls reconfig this app from register your api key by using -k option(if you want more help, pls run command: [protect-yourhome -h])")
	// 	// os.Exit(1)
	// 	return
	// }
	// end
	if decryptedAddress != "" && decryptedApiKey != "" {
		c, err := maps.NewClient(maps.WithAPIKey(decryptedApiKey))
		if err != nil {
			log.Println(err.Error())
			return
		}
		r := &maps.GeocodingRequest{
			Address: decryptedAddress,
		}
		resp, err := c.Geocode(context.Background(), r)
		if err != nil {
			log.Println(err.Error())
			return
		}
		if n := len(resp); n > 1 {
			log.Println("pls enter more identifiable address infomation.")
			return
		} else if n <= 0 {
			log.Println("sorry, google map can't find your home.")
			return
		}
		fmt.Printf("%f, %f\n", resp[0].Geometry.Location.Lat, resp[0].Geometry.Location.Lng)
		latLng := []byte(fmt.Sprintf("%f,%f", resp[0].Geometry.Location.Lat, resp[0].Geometry.Location.Lng))
		cost := 8
		encryptedLatLng, err = func() (string, error) { s, e := bcrypt.GenerateFromPassword(latLng, cost); return string(s), e }()
		if err != nil {
			log.Println(err.Error())
			return
		}
		if info.LatLng != "" {
			err = bcrypt.CompareHashAndPassword([]byte(info.LatLng), []byte(latLng))
			if err != nil {
				log.Println("[VERY IMPORTANT NOTIFICATION] it seems you home address is moved on google map. ASAP try to contact to Google by feedback.")
				return
			} else {
				log.Println("ok, it seems no problem :)")
			}
		} else {
			reconstruct = true
		}
	}
	defer func() {
		if reconstruct {
			write := Info{
				Key:     base64.StdEncoding.EncodeToString([]byte(encryptedApiKey)),
				Address: base64.StdEncoding.EncodeToString([]byte(encryptedAddress)),
				// LatLng:  base64.StdEncoding.EncodeToString([]byte(encryptedLatLng)),
				LatLng: encryptedLatLng,
			}
			err = ioutil.WriteFile(func() (r string) { r, _ = homedir.Expand(dir + "data"); return }(), func() []byte {
				r, e := json.Marshal(write)
				if e != nil {
					log.Println(e.Error())
					os.Exit(1)
				}
				return r
			}(), 0700)
			if err != nil {
				log.Println(err.Error())
				os.Exit(1)
			}
		}
	}()
}

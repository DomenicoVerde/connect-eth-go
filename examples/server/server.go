package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!\n")
	})
	http.HandleFunc("/data/", func(w http.ResponseWriter, r *http.Request) {
		number, err := strconv.Atoi(path.Base(r.URL.Path))
		if err != nil {
			http.Error(w, "invalid number", http.StatusBadRequest)
			return
		}

		w.Write(RandomBytes(number))
	})

	go func() {
		if err := http.ListenAndServe(":80", nil); err != nil {
			log.Printf("HTTP server failed: %v\n", err)
			os.Exit(1)
		}
	}()

	server := http3.Server{
		Addr: ":443",
		QUICConfig: &quic.Config{
			InitialPacketSize: 1200,
			EnableDatagrams:   true,
		},
	}
	if err := server.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
		log.Printf("HTTP/3 server failed: %v\n", err)
		os.Exit(1)
	}
}

func RandomBytes(n int) []byte {
	var seed [32]byte
	binary.BigEndian.PutUint64(seed[:], uint64(n))
	rng := rand.NewChaCha8(seed)
	data := make([]byte, n)
	_, err := rng.Read(data)
	if err != nil {
		log.Fatalf("failed to generate random bytes: %v", err)
	}
	return data
}

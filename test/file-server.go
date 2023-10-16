package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"time"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func certificate() tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	/*
	   hosts := strings.Split(*host, ",")
	   for _, h := range hosts {
	   	if ip := net.ParseIP(h); ip != nil {
	   		template.IPAddresses = append(template.IPAddresses, ip)
	   	} else {
	   		template.DNSNames = append(template.DNSNames, h)
	   	}
	   }

	   if *isCA {
	   	template.IsCA = true
	   	template.KeyUsage |= x509.KeyUsageCertSign
	   }
	*/

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %s", err)
	}

	return cert
}

var tlsOn bool

func main() {

	flag.BoolVar(&tlsOn, "tls", false, "Enable TLS")
	flag.Parse()

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			// parse the multipart form in the request with a 1MB max
			err := r.ParseMultipartForm(1 << 20)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// write each uploaded file to disk
			for _, fheaders := range r.MultipartForm.File {
				for _, hdr := range fheaders {
					// open uploaded
					var infile multipart.File
					infile, err = hdr.Open()
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					// open destination file
					var outfile *os.File
					outfile, err = os.Create("./" + hdr.Filename)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					// save the data to the file
					var written int64
					written, err = io.Copy(outfile, infile)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					log.Printf("uploaded file: %s (%d bytes)", hdr.Filename, written)
				}
			}
			break
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	http.Handle("/", http.FileServer(http.Dir("./")))

	var err error

	if tlsOn {
		log.Println("Listening on https://0.0.0.0:8000...")

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{certificate()},
			NextProtos:   []string{"h2", "http/1.1"},
		}

		l, err := net.Listen("tcp", ":8000")
		if err != nil {
			log.Fatal(err)
		}

		tlsListener := tls.NewListener(l, tlsConfig)
		err = http.Serve(tlsListener, nil)
	} else {
		log.Println("Listening on http://0.0.0.0:8000...")
		err = http.ListenAndServe(":8000", nil)
	}

	if err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
)

func main() {
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

	log.Println("Listening on 0.0.0.0:8000...")
	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Fatal(err)
	}
}

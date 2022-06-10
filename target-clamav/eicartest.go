package main

import (
    "io"
    "log"
    "net/http"
    "net/url"
    "os"
    "strings"
)

func downloadFile(fullURLFile string, writePath string) {
	var fileName string
	// Build fileName from fullPath
    fileURL, err := url.Parse(fullURLFile)
    if err != nil {
        log.Fatal(err)
    }
    path := fileURL.Path
    segments := strings.Split(path, "/")
    fileName = segments[len(segments)-1]
 
    // Create blank file
    file, err := os.Create(writePath + fileName)
    if err != nil {
        log.Fatal(err)
    }
    client := http.Client{
        CheckRedirect: func(r *http.Request, via []*http.Request) error {
            r.URL.Opaque = r.URL.Path
            return nil
        },
    }
    // Put content on file
    resp, err := client.Get(fullURLFile)
    if err != nil {
        log.Fatal(err)
    }
	_, err = io.Copy(file, resp.Body)
    defer resp.Body.Close()
    defer file.Close()
}

func main(){
	data := []byte{88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42}
	f, _ := os.Create("/tmp/eicardisk.bin")
	defer f.Close()
	_, _ = f.Write(data)
	downloadFile("https://secure.eicar.org/eicar.com.txt", "/tmp/")
	downloadFile("https://secure.eicar.org/eicar_com.zip", "/home/")
}
package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "ok %d\n", time.Now().Unix()) })
	http.ListenAndServe("0.0.0.0:8080", nil)
}

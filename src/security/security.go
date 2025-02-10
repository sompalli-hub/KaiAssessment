package main

import (
	"fmt"
	"log"
	"net/http"
	pc "payloadcontent"
)

func main() {
	//Start a https server and expose two end points
	severitymap = make(map[string][]pc.Vulnerability)	
	http.HandleFunc("/scan", handleScan)
	http.HandleFunc("/query", handleQuery)

	// Start the server on port 8080
	fmt.Println("Starting server on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))

}

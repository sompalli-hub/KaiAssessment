package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	_"os"
	"log"
	_"path/filepath"
	"net/http"
	_"strings"
	pc "payloadcontent"
)

func fetchJSONFromGitHub(githubRepo, filePath string) ([]pc.ScanArray, error) {
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/refs/heads/main/%s",githubRepo, filePath)



	resp, err := http.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching %s: %v", rawURL, err)
	}
	defer resp.Body.Close()

	fmt.Println(resp)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var scans []pc.ScanArray
	err = json.Unmarshal(body, &scans)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON from %s: %v", rawURL, err)
	}

	return scans, nil
}

func main() {
	//Start a https server and expose two end points
	//githubRepo := "https://raw.githubusercontent.com/velancio/vulnerability_scans/refs/heads/main/"
//	jsonFiles := []string{"vulnscan1011.json", "vulnscan1213.json"}
	severitymap = make(map[string][]pc.Vulnerability)	
	http.HandleFunc("/scan", handleScan)
	http.HandleFunc("/query", handleQuery)

	// Start the server on port 8080
	fmt.Println("Starting server on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))

/*	// Step 2: Fetch and parse each JSON file
	for _, filePath := range jsonFiles {
		fmt.Println("Fetching:", filePath)

		scans, err := fetchJSONFromGitHub(githubRepo, filePath)
		if err != nil {
			log.Println("Error fetching JSON:", err)
			continue
		}

		for _, scan := range scans {
			totalScans = append(totalScans, scan)
		}
	}

//	fmt.Println(severitymap)

	// Print the parsed data
	for _, scan := range totalScans {
		for _, vul := range scan.KeyScanResult.Vulnerabilities {
			fmt.Printf("Severity: %s \n",vul.Severity)
			severitymap[vul.Severity] = append(severitymap[vul.Severity], vul)
		}
	}

	//fmt.Println(severitymap)

	for key, values := range severitymap {
		fmt.Printf("key:  %s \n", key)
		for _, val := range values {
			fmt.Printf("value: %s \n", val)
		}
		fmt.Println()
	}		
*/
}

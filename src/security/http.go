package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"io/ioutil"
	pc "payloadcontent"
)
var severitymap map[string][]pc.Vulnerability
var totalScans []pc.ScanArray

// Handle the POST /scan endpoint to fetch JSON from GitHub and process it
func handleScan(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Extract the GitHub repository and file path from the request body
	var requestData struct {
		Repo     string `json:"repo"`  // Full repo URL (e.g., "username/repo")
		FileNames []string `json:"filenames"` // JSON files within the repo
	}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Construct the raw URL to fetch the JSON file
	//rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/refs/heads/main/",repo)

	// Step 2: Fetch and parse each JSON file
        for _, fileName := range requestData.FileNames {
                fmt.Println("Fetching:", fileName)

                scans, err := fetchJSONFromGitHub(requestData.Repo, fileName)
                if err != nil {
                        log.Println("Error fetching JSON:", err)
                        continue
                }

                for _, scan := range scans {
                        totalScans = append(totalScans, scan)
                }
        }

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


	// Respond with the scan data
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(totalScans)
}

type PostQuery struct {
 	Filters struct {
		Severity string `json:"severity"`
	} `json:"filters"`
}


// Handle the POST /query endpoint to filter scan results
func handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	// Parse the filter request
	var query PostQuery
	if err := json.Unmarshal(body, &query); err != nil {
		http.Error(w, "Error unmarshaling filter request", http.StatusInternalServerError)
		return
	}

	severity := query.Filters.Severity

	var sevResults []pc.Vulnerability
	for sev,result := range severitymap {
		if sev == severity {
			sevResults = result
		}
	}

	// Respond with the filtered results
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sevResults)
}

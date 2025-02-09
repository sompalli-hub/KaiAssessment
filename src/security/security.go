package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	_"os"
	"log"
	"path/filepath"
	pc "payloadcontent"
)
func main() {
	var severitymap map[string][]pc.Vulnerability
	var totalScans []pc.ScanArray

	// Read all files in the directory
	files, err := ioutil.ReadDir("/home/ubuntu/KaiAssessment/src/files")
	if err != nil {
		return
	}

	for _, file := range files {
		// Process only JSON files
		fileName := filepath.Join("/home/ubuntu/KaiAssessment/src/files", file.Name())
		fmt.Println("Processing file:", fileName)

		// Read the file content
		data, err := ioutil.ReadFile(fileName)
		if err != nil {
			log.Printf("Error reading file %s: %v", fileName, err)
			continue
		}

		// Unmarshal JSON into a slice of ScanData
		var scans []pc.ScanArray
		err = json.Unmarshal([]byte(data), &scans)
		if err != nil {
			log.Printf("Error unmarshaling JSON in file %s: %v", fileName, err)
			continue
		}
		fmt.Println(scans)

		// Append to the master list
		for _,scan := range scans {
			totalScans = append(totalScans, scan)
		}
	}


	severitymap = make(map[string][]pc.Vulnerability)
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
}

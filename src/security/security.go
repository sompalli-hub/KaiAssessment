package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	pc "payloadcontent"
)
func main() {
	var scans []pc.ScanArray 

	jsonFile, err := os.Open("/home/ubuntu/KaiAssessment/src/files/example.json")
	if err != nil {
	    fmt.Println(err)
	    return
	}
	defer jsonFile.Close()

	// Read all data from the file
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// Unmarshal the JSON 
	err = json.Unmarshal([]byte(byteValue), &scans)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	fmt.Println(scans)

	// Print the parsed data
	for _, scan := range scans {
		for _, vul := range scan.KeyScanResult.Vulnerabilities {
			fmt.Printf("Severity: %s \n",vul.Severity)
		}
	}
}


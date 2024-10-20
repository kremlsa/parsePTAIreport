package main

import (
	"encoding/json"
	"log"

	"github.com/kremlsa/parsePTAIreport/ptai"
	fileutils "github.com/kremlsa/parsePTAIreport/fileutils"
)

func main() {
	filename := "ptaiReport.json"
	data, err := fileutils.Read(filename)
	if err != nil {
		log.Fatal(err)
	}
	var ptaiReport ptai.Report
	if err := json.Unmarshal(data, &ptaiReport); err != nil {
		panic(err)
	}
	var weakness ptai.Findings
	var vulners ptai.Findings
	for _, v := range ptaiReport.Items {
		if v.Component == "" {
			weakness.AddFinding(v)
		} else {
			vulners.AddFinding(v)
		}
	}
	projectName := ptaiReport.ScanInfo.Settings[0].Value
	ptai.SaveToExcel(projectName, &weakness, &vulners)

}

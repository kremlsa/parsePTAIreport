package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	fileutils "github.com/kremlsa/parsePTAIreport/fileutils"
	"github.com/kremlsa/parsePTAIreport/ptai"
)

func main() {
	// Проверяем количество переданных аргументов
	if len(os.Args) < 2 {
		log.Fatal("No file specified")
	}

	// Проверяем является ли аргумент json файлом
	if !strings.HasSuffix(os.Args[1], ".json") {
		log.Fatal("Wrong extension")
	}

	// Инициализируем параметры подключения из аргументов командной строки
	filename := os.Args[1]
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

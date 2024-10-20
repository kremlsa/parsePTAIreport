package ptai

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
)

func PrintStats(f *Findings) {
	fmt.Printf("High: %d\nMedium: %d\nLow: %d\n", len(f.High), len(f.Medium), len(f.Low))
	fmt.Printf("Total: %d\n", f.Total())
}

func SaveToExcel(projectName string, weakness *Findings, vulners *Findings) {
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Println(err)
		}
	}()
	// Create a new sheet.
	_, err := f.NewSheet("CVE")
	if err != nil {
		fmt.Println(err)
		return
	}
	f.SetSheetName("Sheet1", "CWE")
	// Set value of a cell.
	rowNumber := 1
	f.SetCellValue("CWE", "A"+strconv.Itoa(rowNumber), "Counter")
	f.SetCellValue("CWE", "B"+strconv.Itoa(rowNumber), "SourceFile")
	f.SetCellValue("CWE", "C"+strconv.Itoa(rowNumber), "NumberLine")
	f.SetCellValue("CWE", "D"+strconv.Itoa(rowNumber), "VulnerableCode")
	f.SetCellValue("CWE", "E"+strconv.Itoa(rowNumber), "Entry")
	f.SetCellValue("CWE", "F"+strconv.Itoa(rowNumber), "ID")
	f.SetCellValue("CWE", "G"+strconv.Itoa(rowNumber), "Level.Value")
	f.SetCellValue("CWE", "H"+strconv.Itoa(rowNumber), "Type.Value")
	f.SetCellValue("CWE", "I"+strconv.Itoa(rowNumber), "CweID")
	f.SetCellValue("CWE", "J"+strconv.Itoa(rowNumber), "IsApprovedAutomatically")
	f.SetCellValue("CWE", "K"+strconv.Itoa(rowNumber), "IsApproved")
	f.SetCellValue("CWE", "L"+strconv.Itoa(rowNumber), "IsDiscarded")
	f.SetCellValue("CWE", "M"+strconv.Itoa(rowNumber), "IsNew")
	f.SetCellValue("CWE", "N"+strconv.Itoa(rowNumber), "IsPotential")
	f.SetCellValue("CWE", "O"+strconv.Itoa(rowNumber), "IsSuppressed")
	rowNumber++
	for _, w := range weakness.All() {
		f.SetCellValue("CWE", "A"+strconv.Itoa(rowNumber), w.Counter)
		f.SetCellValue("CWE", "B"+strconv.Itoa(rowNumber), strings.Split(w.SourceFile, " ")[0])
		f.SetCellValue("CWE", "C"+strconv.Itoa(rowNumber), w.NumberLine)
		f.SetCellValue("CWE", "D"+strconv.Itoa(rowNumber), w.VulnerableCode)
		f.SetCellValue("CWE", "E"+strconv.Itoa(rowNumber), w.Entry)
		f.SetCellValue("CWE", "F"+strconv.Itoa(rowNumber), w.ID)
		f.SetCellValue("CWE", "G"+strconv.Itoa(rowNumber), w.Level.Value)
		f.SetCellValue("CWE", "H"+strconv.Itoa(rowNumber), w.Type.Value)
		f.SetCellValue("CWE", "I"+strconv.Itoa(rowNumber), w.CweID)
		f.SetCellValue("CWE", "J"+strconv.Itoa(rowNumber), w.IsApprovedAutomatically)
		f.SetCellValue("CWE", "K"+strconv.Itoa(rowNumber), w.IsApproved)
		f.SetCellValue("CWE", "L"+strconv.Itoa(rowNumber), w.IsDiscarded)
		f.SetCellValue("CWE", "M"+strconv.Itoa(rowNumber), w.IsNew)
		f.SetCellValue("CWE", "N"+strconv.Itoa(rowNumber), w.IsPotential)
		f.SetCellValue("CWE", "O"+strconv.Itoa(rowNumber), w.IsSuppressed)
		rowNumber++
	}

	rowNumber = 1
	f.SetCellValue("CVE", "A"+strconv.Itoa(rowNumber), "Counter")
	f.SetCellValue("CVE", "B"+strconv.Itoa(rowNumber), "SourceFile")
	f.SetCellValue("CVE", "C"+strconv.Itoa(rowNumber), "Type")
	f.SetCellValue("CVE", "D"+strconv.Itoa(rowNumber), "Component")
	f.SetCellValue("CVE", "E"+strconv.Itoa(rowNumber), "Level")
	f.SetCellValue("CVE", "F"+strconv.Itoa(rowNumber), "IsApprovedAutomatically")
	f.SetCellValue("CVE", "G"+strconv.Itoa(rowNumber), "IsApproved")
	f.SetCellValue("CVE", "H"+strconv.Itoa(rowNumber), "IsDiscarded")
	f.SetCellValue("CVE", "I"+strconv.Itoa(rowNumber), "IsNew")
	f.SetCellValue("CVE", "J"+strconv.Itoa(rowNumber), "IsSuppressed")
	rowNumber++
	for _, v := range vulners.All() {
		f.SetCellValue("CVE", "A"+strconv.Itoa(rowNumber), v.Counter)
		f.SetCellValue("CVE", "B"+strconv.Itoa(rowNumber), v.SourceFile)
		f.SetCellValue("CVE", "C"+strconv.Itoa(rowNumber), v.Type.ID)
		f.SetCellValue("CVE", "D"+strconv.Itoa(rowNumber), v.Type.DisplayName)
		f.SetCellValue("CVE", "E"+strconv.Itoa(rowNumber), v.Level.Value)
		f.SetCellValue("CVE", "F"+strconv.Itoa(rowNumber), v.IsApprovedAutomatically)
		f.SetCellValue("CVE", "G"+strconv.Itoa(rowNumber), v.IsApproved)
		f.SetCellValue("CVE", "H"+strconv.Itoa(rowNumber), v.IsDiscarded)
		f.SetCellValue("CVE", "I"+strconv.Itoa(rowNumber), v.IsNew)
		f.SetCellValue("CVE", "J"+strconv.Itoa(rowNumber), v.IsSuppressed)
		rowNumber++
	}

	// Save spreadsheet by the given path.
	if err := f.SaveAs(fmt.Sprintf("%s.xlsx", projectName)); err != nil {
		fmt.Println(err)
	}
}

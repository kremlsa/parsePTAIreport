package ptai

type Report struct {
	ScanInfo struct {
		TotalFileCount                            int    `json:"TotalFileCount"`
		ScannedFileCount                          int    `json:"ScannedFileCount"`
		TotalURLCount                             int    `json:"TotalUrlCount"`
		ScannedURLCount                           int    `json:"ScannedUrlCount"`
		VulnerableFiles                           int    `json:"VulnerableFiles"`
		TotalVulnerabilityCount                   int    `json:"TotalVulnerabilityCount"`
		AcceptedVulnerabilities                   int    `json:"AcceptedVulnerabilities"`
		DiscardedVulnerabilities                  int    `json:"DiscardedVulnerabilities"`
		SuppressedVulnerabilities                 int    `json:"SuppressedVulnerabilities"`
		NewVulnerabilities                        int    `json:"NewVulnerabilities"`
		PreviousVulnerabilities                   int    `json:"PreviousVulnerabilities"`
		PolicyState                               int    `json:"PolicyState"`
		NonFilteredVulnerabilitiesCount           int    `json:"NonFilteredVulnerabilitiesCount"`
		NonFilteredAcceptedVulnerabilitiesCount   int    `json:"NonFilteredAcceptedVulnerabilitiesCount"`
		NonFilteredDiscardedVulnerabilitiesCount  int    `json:"NonFilteredDiscardedVulnerabilitiesCount"`
		NonFilteredSuppressedVulnerabilitiesCount int    `json:"NonFilteredSuppressedVulnerabilitiesCount"`
		NonFilteredNewVulnerabilitiesCount        int    `json:"NonFilteredNewVulnerabilitiesCount"`
		NonFilteredPreviousVulnerabilitiesCount   int    `json:"NonFilteredPreviousVulnerabilitiesCount"`
		VulnerableLinks                           int    `json:"VulnerableLinks"`
		ScanDate                                  string `json:"ScanDate"`
		Settings                                  []struct {
			Name           string `json:"Name"`
			Value          string `json:"Value"`
			Order          int    `json:"Order"`
			NeedLineBreak  bool   `json:"NeedLineBreak"`
			IsExternalLink bool   `json:"IsExternalLink"`
		} `json:"Settings"`
		Policies string `json:"Policies"`
	} `json:"ScanInfo"`
	Items           []Finding `json:"Items"`
	HaveGroups      bool      `json:"HaveGroups"`
	IncludedFilters struct {
		IsInclude bool   `json:"IsInclude"`
		Favorite  string `json:"Favorite"`
	} `json:"IncludedFilters"`
	ExcludedFilters struct {
		IsInclude bool   `json:"IsInclude"`
		Favorite  string `json:"Favorite"`
	} `json:"ExcludedFilters"`
	GlossaryItems []struct {
		DisplayName                 string `json:"DisplayName"`
		Value                       string `json:"Value"`
		IsApprovedAutomaticallyName bool   `json:"IsApprovedAutomaticallyName"`
		TypeName                    string `json:"TypeName"`
		TypeID                      string `json:"TypeId"`
	} `json:"GlossaryItems"`
	FilteredIssuesCount int    `json:"FilteredIssuesCount"`
	ReportType          string `json:"ReportType"`
}

type Finding struct {
	MatchedCode    string `json:"MatchedCode"`
	SourceFile     string `json:"SourceFile"`
	VulnerableCode string `json:"VulnerableCode"`
	TypeKey        string `json:"TypeKey"`
	IsSuspected    bool   `json:"IsSuspected"`
	GroupType      string `json:"GroupType"`
	IsSuppressed   bool   `json:"IsSuppressed"`
	IsNew          bool   `json:"IsNew"`
	ID             string `json:"Id"`
	Type           struct {
		ID          string `json:"Id"`
		GroupID     string `json:"GroupId"`
		DisplayName string `json:"DisplayName"`
		Value       string `json:"Value"`
	} `json:"Type"`
	Counter       int    `json:"Counter"`
	ApprovalState string `json:"ApprovalState"`
	IsFavorite    bool   `json:"IsFavorite"`
	Level         struct {
		Severity    int    `json:"Severity"`
		DisplayName string `json:"DisplayName"`
		Value       string `json:"Value"`
	} `json:"Level"`
	Owasp struct {
		DisplayName string `json:"DisplayName"`
		Value       string `json:"Value"`
	} `json:"Owasp"`
	Owaspm struct {
		DisplayName string `json:"DisplayName"`
		Value       string `json:"Value"`
	} `json:"Owaspm"`
	Sans struct {
		DisplayName string `json:"DisplayName"`
		Value       string `json:"Value"`
	} `json:"Sans"`
	Pcidss []struct {
		DisplayName string `json:"DisplayName"`
		Value       string `json:"Value"`
	} `json:"Pcidss"`
	Nist []struct {
		DisplayName string `json:"DisplayName"`
		Value       string `json:"Value"`
	} `json:"Nist"`
	CweID                   string `json:"CweId"`
	ParentItem              string `json:"ParentItem"`
	IsApproved              bool   `json:"IsApproved"`
	IsDiscarded             bool   `json:"IsDiscarded"`
	IsApprovedAutomatically bool   `json:"IsApprovedAutomatically"`
	Place                   string `json:"Place,omitempty"`
	Component               string `json:"Component,omitempty"`
	CveDescriptions         []struct {
		Key   string `json:"Key"`
		Level string `json:"Level"`
		Cvss2 struct {
			BaseScore  string `json:"BaseScore"`
			BaseVector string `json:"BaseVector"`
		} `json:"Cvss2"`
		Cvss3 struct {
			BaseScore  string `json:"BaseScore"`
			BaseVector string `json:"BaseVector"`
		} `json:"Cvss3"`
		Description string `json:"Description"`
	} `json:"CveDescriptions,omitempty"`
	IsPotential          bool   `json:"IsPotential,omitempty"`
	IsSecondOrder        bool   `json:"IsSecondOrder,omitempty"`
	Function             string `json:"Function,omitempty"`
	Entry                string `json:"Entry,omitempty"`
	NumberLine           int    `json:"NumberLine,omitempty"`
	Exploit              string `json:"Exploit,omitempty"`
	RawLine              string `json:"RawLine,omitempty"`
	AdditionalConditions string `json:"AdditionalConditions,omitempty"`
	ScanMode             string `json:"ScanMode,omitempty"`
}

type Findings struct {
	ProjectName string
	High        []Finding
	Medium      []Finding
	Low         []Finding
	Potential   []Finding
}

func (f *Findings) AddFinding(finding Finding) {
	switch finding.Level.Value {
	case "level-high":
		f.High = append(f.High, finding)
	case "level-medium":
		f.Medium = append(f.Medium, finding)
	case "level-low":
		f.Low = append(f.Low, finding)
	}
}

func (f *Findings) Total() int {
	return len(f.High) + len(f.Medium) + len(f.Low)
}

func (f *Findings) All() []Finding {
	total := append(f.High, f.Medium...)
	total = append(total, f.Low...)
	return total
}

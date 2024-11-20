package parisusers

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"vc/pkg/ehic"
	"vc/pkg/model"
	"vc/pkg/pda1"

	"github.com/xuri/excelize/v2"
)

func makePID(fs *excelize.File) map[string]*model.CompleteDocument {
	storage := map[string]*model.CompleteDocument{}

	// Get value from cell by given worksheet name and cell reference.
	pidRows, err := fs.GetRows("PID")
	if err != nil {
		panic(err)
	}

	for _, row := range pidRows {
		if row[0] == "" || row[0] == "pid_id" {
			continue
		}
		dateOfBirth := strings.ReplaceAll(row[8], "/", "-")
		storage[row[0]] = &model.CompleteDocument{
			DocumentDataVersion: "1.0.0",
			Identities: []model.Identity{
				{
					AuthenticSourcePersonID: fmt.Sprintf("authentic_source_person_id_%s", row[0]),
					Schema: &model.IdentitySchema{
						Name:    "FR",
						Version: "",
					},
					FamilyName: row[6],
					GivenName:  row[7],
					BirthDate:  dateOfBirth,
				},
			},
		}

	}

	return storage

}

// EHIC returns a list of EHIC documents
func EHIC(sourceFilePath string) []model.CompleteDocument {
	f, err := excelize.OpenFile(sourceFilePath)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer func() {
		// Close the spreadsheet.
		if err := f.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	storage := makePID(f)

	ehicRows, err := f.GetRows("EHIC")
	if err != nil {
		panic(err)
	}
	for _, row := range ehicRows {
		pid := row[0]
		if pid == "" || pid == "pid_id" {
			continue
		}

		SocialSecurityPin := row[4]
		startDate := row[5]
		endDate := row[6]

		CardNumber := row[7]
		InstitutionID := row[8]
		InstitutionName := row[9]
		InstitutionCountry := row[10]

		user, ok := storage[pid]
		if !ok {
			panic("no user found for pid " + pid)
		}

		document := &ehic.Document{
			Subject: ehic.Subject{
				Forename:    user.Identities[0].GivenName,
				FamilyName:  user.Identities[0].FamilyName,
				DateOfBirth: user.Identities[0].BirthDate,
			},
			SocialSecurityPin: SocialSecurityPin,
			PeriodEntitlement: ehic.PeriodEntitlement{
				StartingDate: startDate,
				EndingDate:   endDate,
			},
			DocumentID: CardNumber,
			CompetentInstitution: ehic.CompetentInstitution{
				InstitutionID:      InstitutionID,
				InstitutionName:    InstitutionName,
				InstitutionCountry: InstitutionCountry,
			},
		}

		var err error
		user.DocumentData, err = document.Marshal()
		if err != nil {
			panic(err)
		}

		user.Meta = &model.MetaData{
			AuthenticSource: row[2],
			DocumentVersion: "1.0.0",
			DocumentType:    "EHIC",
			DocumentID:      fmt.Sprintf("document_id_ehic_%s", row[0]),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_ehic_%s", row[0]),
				ValidUntil: 0,
			},
			Revocation:                &model.Revocation{},
			CredentialValidFrom:       0,
			CredentialValidTo:         0,
			DocumentDataValidationRef: "",
		}

		user.DocumentDisplay = &model.DocumentDisplay{
			Version: "1.0.0",
			Type:    "secure",
			DescriptionStructured: map[string]any{
				"en": map[string]any{
					"documentType": "EHIC",
				},
				"sv": map[string]any{
					"documentType": "EHIC",
				},
			},
		}

	}

	list := []model.CompleteDocument{}
	for _, v := range storage {
		list = append(list, *v)
	}

	return list
}

// PDA1 returns a list of PDA1 documents
func PDA1(sourceFilePath string) []model.CompleteDocument {
	f, err := excelize.OpenFile(sourceFilePath)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer func() {
		// Close the spreadsheet.
		if err := f.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	storage := makePID(f)

	pda1Rows, err := f.GetRows("PDA1")
	if err != nil {
		panic(err)
	}

	for _, row := range pda1Rows {
		pid := row[0]
		if pid == "" || pid == "pid_id" || pid == "pid_id (Spalte H, nach pda1_issuing_country)" {
			continue
		}

		user, ok := storage[pid]
		if !ok {
			panic("no user found for pid " + pid)
		}

		document := &pda1.Document{
			SocialSecurityPin: row[6],
			Nationality:       []string{row[7]},
			DetailsOfEmployment: []pda1.DetailsOfEmployment{
				{
					TypeOfEmployment: row[8],
					Name:             row[9],
					Address: pda1.AddressWithCountry{
						Street:   row[12],
						PostCode: row[14],
						Town:     row[13],
						Country:  row[15],
					},
					IDsOfEmployer: []pda1.IDsOfEmployer{
						{
							EmployerID: row[10],
							TypeOfID:   row[11],
						},
					},
				},
			},
			PlacesOfWork: []pda1.PlacesOfWork{
				{
					AFixedPlaceOfWorkExist: false,
					CountryWork:            row[16],
					PlaceOfWork: []pda1.PlaceOfWork{
						{
							CompanyVesselName: "",
							FlagStateHomeBase: row[21],
							IDsOfCompany: []pda1.IDsOfCompany{
								{
									CompanyID: row[18],
									TypeOfID:  row[19],
								},
							},
							Address: pda1.Address{
								Street:   row[22],
								PostCode: row[24],
								Town:     row[23],
							},
						},
					},
				},
			},
			DecisionLegislationApplicable: pda1.DecisionLegislationApplicable{
				MemberStateWhichLegislationApplies: row[26],
				TransitionalRuleApply:              false,
				StartingDate:                       row[28],
				EndingDate:                         row[29],
			},
			StatusConfirmation:           row[30],
			UniqueNumberOfIssuedDocument: "",
			CompetentInstitution: pda1.CompetentInstitution{
				InstitutionID:   row[32],
				InstitutionName: row[33],
				CountryCode:     row[34],
			},
		}

		var err error
		user.DocumentData, err = document.Marshal()
		if err != nil {
			panic(err)
		}

		user.Meta = &model.MetaData{
			AuthenticSource: row[3],
			DocumentVersion: "1.0.0",
			DocumentType:    "PDA1",
			DocumentID:      fmt.Sprintf("document_id_pda1_%s", row[0]),
			RealData:        false,
			Collect: &model.Collect{
				ID:         fmt.Sprintf("collect_id_pda1_%s", row[0]),
				ValidUntil: 0,
			},
			Revocation:                &model.Revocation{},
			CredentialValidFrom:       0,
			CredentialValidTo:         0,
			DocumentDataValidationRef: "",
		}

		user.DocumentDisplay = &model.DocumentDisplay{
			Version: "1.0.0",
			Type:    "secure",
			DescriptionStructured: map[string]any{
				"en": map[string]any{
					"documentType": "PDA1",
				},
				"sv": map[string]any{
					"documentType": "PDA1",
				},
			},
		}

	}

	list := []model.CompleteDocument{}
	for _, v := range storage {
		list = append(list, *v)
	}

	return list
}

// Make returns a list of EHIC and PDA1 documents
func Make(filePath string) []model.CompleteDocument {
	return append(EHIC(filePath), PDA1(filePath)...)
}

// CSV converts a list of CompleteDocument to CSV and writes it to a file
func CSV(docs model.CompleteDocuments) ([]string, [][]string, error) {
	fs, err := os.Create("pda1_users.csv")
	if err != nil {
		return nil, nil, err
	}
	defer fs.Close()

	return docs.CSV()

}

func saveCSVToDisk(records [][]string, filePath string) error {
	f, err := os.Create(filePath)
	defer f.Close()
	if err != nil {
		return err
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.WriteAll(records); err != nil {
		return err
	}
	return nil
}

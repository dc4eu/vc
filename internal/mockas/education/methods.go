package education

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"vc/pkg/datastoreclient"
	"vc/pkg/model"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func (c *Service) apply(ctx context.Context) (*http.Response, error) {
	for documentType, users := range c.users {
		for _, user := range users {
			document_data, err := c.readDocumentDataFile(user.document_data_path)
			if err != nil {
				return nil, err
			}
			collectID := fmt.Sprintf("collect_id_%s_%s", documentType, user.number)
			documentID := fmt.Sprintf("document_id_%s_%s", documentType, user.number)
			authenticSourcePersonID := fmt.Sprintf("authentic_source_person_id_%s", user.number)
			authenticSource := fmt.Sprintf("EDU:%s:000001", strings.ToUpper(documentType))

			caser := cases.Title(language.English)

			doc := &datastoreclient.UploadRequest{
				Meta: &model.MetaData{
					AuthenticSource: authenticSource,
					DocumentVersion: "1.0.0",
					DocumentType:    caser.String(documentType),
					DocumentID:      documentID,
					RealData:        false,
					Collect: &model.Collect{
						ID: collectID,
					},
					Revocation:                &model.Revocation{},
					CredentialValidFrom:       0,
					CredentialValidTo:         0,
					DocumentDataValidationRef: "",
				},
				Identities: []model.Identity{
					{
						AuthenticSourcePersonID: authenticSourcePersonID,
						Schema: &model.IdentitySchema{
							Name:    "DefaultSchema",
							Version: "1.0.0",
						},
						FamilyName: user.lastName,
						GivenName:  user.firstName,
						BirthDate:  user.dateOfBirth,
					},
				},
				DocumentDisplay: &model.DocumentDisplay{
					Version: "1.0.0",
					Type:    documentType,
					DescriptionStructured: map[string]any{
						"en": fmt.Sprintf("%s educational credential", documentType),
					},
				},
				DocumentData:        document_data,
				DocumentDataVersion: "1.0.0",
			}

			resp, err := c.datastoreClient.Root.Upload(ctx, doc)
			if err != nil {
				c.log.Error(err, "upload error", "documentType", doc.Meta.DocumentType, "authenticSource", doc.Meta.AuthenticSource)
				return resp, err
			}

			c.log.Debug("upload response", "status", resp.StatusCode, "documentType", documentType, "user", user.firstName+" "+user.lastName)
		}
	}

	return nil, nil
}

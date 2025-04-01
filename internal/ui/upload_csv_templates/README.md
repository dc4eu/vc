# Upload documents using a CSV file

A CSV file can be used to bulk upload documents for test purposes. 

1. Select type of document to upload (currently only EHIC is supported).
2. Choose a CSV file containing the documents to upload.
3. Press Upload
4. For each post (row in the CSV sheet), an Upload status is displayed, along with Upload data (the actual JSON being uploaded to the server) and More information.

It's important to check that both the **Upload status** is "SUCCESS" and there is no **More information** that contradicts that. 

**Known issue/bug:** For a duplicate document, "SUCCESS" is returned from the server but also More information with a JSON containing "DOCUMENT_ALREADY_EXISTS".

## Format and content of the CSV file

See [ehic_upload_template.csv](ehic_upload_template.csv) for an example

### Fields

| Field | Type | Required | Example | Comments |
|--|--|--|--|--|
| authentic_source | string | yes | SWEDEN:SUNET:EHIC | The authentic source to simulate in the test, make it unique for your organisation |
| authentic_source_person_id | string | yes | authentic_source_person_id_70 | Must be selected from [file](https://github.com/dc4eu/vc/blob/main/users_paris.csv) |
| family_name |string | yes | De Niro | Must be selected from [file](https://github.com/dc4eu/vc/blob/main/users_paris.csv) |	
| given_name |string | yes | Robert | Must be selected from [file](https://github.com/dc4eu/vc/blob/main/users_paris.csv) |
| birth_date |string as YYYY-MM-DD| yes |1982-01-15 | Must be selected from [file](https://github.com/dc4eu/vc/blob/main/users_paris.csv) |
| document_id | string | (yes) | 1 | leave field empty to have the system generate a unique one |
| ehic_expiry_date | string as YYYY-MM-DD || 	2026-04-12 ||
| social_security_pin | string | | 23451235 ||
| ehic_start_date | string as YYYY-MM-DD || 2023-09-08 ||
| ehic_end_date | string as YYYY-MM-DD || 2026-04-12 ||
| ehic_card_identification_number | string || 10000000000000000001 ||
| ehic_institution_id | string || NFZ ||
| ehic_institution_name | string || Narodowy Fundusz Zdrowia ||
| ehic_institution_country_code | string || PL ||

### Other rules/logic
- **`authentic_source_person_id`, `family_name`, `given_name` and `birth_date` must be selected and combined exactly as in [file](https://github.com/dc4eu/vc/blob/main/users_paris.csv)**
  - other values may be used BUT the identity then won't be found in an IdP in later stages.
- all the ehic fields including `social_security_pin` is validated against the rules in [schema](https://github.com/dc4eu/vc/blob/main/standards/schema_ehic.json)
- `document_id` must be unique together with `authentic_source` and `document_type`
- `document_version` is always given the value "1.0.0"
- `collect.id` is given the same value as `document_id`
- `collect.valid_until` is given the same value as `ehic_expiry_date`
- `identity.schema.name` is always given the value "DefaultSchema"
- `identity.schema.version` is always given the value "1.0.0"
- `credential_valid`_from is given the same date as `ehic_startdate`
- `credential_valid_to` is given the same date as `ehic_end_date`

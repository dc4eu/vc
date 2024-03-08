# Datastore Rest API

## Version

    APIv2.1 - Proposal

## POST /upload

### Description

The Process starts with the authentic source which is uploading all relevant data to the Datastore.
All steps regarding the general application of an attestation are out of scope and reside to the internal processes of the authentic source.

The data upload (/upload) consist of four objects used as input for the call. These are meta, identity_data, attestation_data and document_data.

First, the meta object consists of the authentic source ID, document type and document ID. These act
as the main identifier in the Datastore. One document ID is valid and unique per document type and
authentic source ID. Another required input is the institutional identifier of the person to ensure
flexibility in identification and reduce susceptibility to errors. Again, this may also be valid and unique
only in the domain of the authentic source. Therefore, in order to match an institutional person ID
(authentic_source_person_id) a filter by authentic source ID needs to be applied before a selection
operation is done. Finally, the meta object has defined revocation and collect ID as optional
parameters. They may be set by the authentic source for special use cases and preferences. If not
defined by the upload they shall be set equal to the document ID by the Datastore System.

Second object is identity data which includes equal to the current definition of the PID, all possible
parameters optional and required concerning the subject of the attestation to be uploaded. This is
the first approach to handle the identity matching topic. An authentic Source shall upload all
available information concerning the defined attributes. The more the better for later matching, against a PID from an EUDIW.

Third there is an attestation data object defined. This object contains attributes that shall be used for
display in a portal solution. Since there are many different credential types and relevant information
to display may differ, it was decided to define this as a generic object containing a short and long text
which can be filled by choice of the authentic source with relevant display information. In addition,
valid from and valid to information of the attestation, shall be provided by default.

Finally, the document data object needs to be submitted. We expect a JSON electronic document
containing all business decision data matching to the document type and schema definitions.

The Datastore responds to this upload with status codes which shall be technical with error logs if occurring.

### Request

```json
{
    "meta": {
        "authentic_source": "",
        "document_id": "",
        "document_type": "",
        "uuid": "",
        "revocation_id": "",
        "document_id": "",
        "collect_id": "",
        "authentic_source_person_id": "",
        "document_version": 0,
    },
    "identity": {
        "identity_version": "",
        "family_name": "",
        "given_name":"",
        "birth_date":"",
        "uuid": "",
        "family_name_birth":"",
        "given_name_birth":"", 
        "birth_place":"",
        "gender":"",
        "age_over_18":"",
        "age_over_NN":"",
        "age_in_years":"",
        "age_birth_year":"",
        "birth_country":"",
        "birth_state":""
    },
    "attestation": {
        "attestation_version": 0,
        "attestation_type": "",
        "description_short": "",
        "description_long": "",
        "valid_from": "",
        "valid_to":""
        },  
    "document_data": {}
}
```

### Response

http status code 200, else 400 and error body

## POST /notification

### Request

```json
{
    "authentic_source": "",
    "document_type": "",
    "document_id": "",
}
```

### Response

```json
{
    "data": {
        "qr": "",
        "deeplink": ""
    }
}
```

http status code 200, else 400 and error body

## DELETE /document

### Request

```json
{
    "authentic_source": "",
    "document_id": ""
}
```

### Response

http status code 200, else 400 and error body

## POST /document/attestation

### Direction

Issuer --> Datastore/authentic source

### Request

```json
{
    "authentic_source": "",
    "collect_id":"",
    "identity": {
        "identity_version": "",
        "family_name": "",
        "given_name":"",
        "birth_date":"",
        "uuid": "",
        "family_name_birth":"",
        "given_name_birth":"", 
        "birth_place":"",
        "gender":"",
        "age_over_18":"",
        "age_over_NN":"",
        "age_in_years":"",
        "age_birth_year":"",
        "birth_country":"",
        "birth_state":""
    },
}
```

### Response

```json
{
    "document_data":"",
    "meta": {
        "authentic_source": "",
        "document_id": "",
        "document_type": "",
        "revocation_id": "",
        "document_id": "",
        "collect_id": "",
    },
}

```

http status code 200, else 400 and error body

## POST /portal

### Direction

Portal --> Datastore

### Request

```json
"authentic_source":"", 
"authentic_source_person_id":""
"valid_after": "",
```

### Response

```json
{ 
"data": {
    "attestations": [
        {
        "document_type": "",
        "document_id": "",
        "collect_id":""
        }
    ],
    "attestation": {
        "attestation_version": 0,
        "attestation_type": "",
        "description_short":"",
        "description_long":"",
        "valid_from":"",
        "valid_to": ""
    },
    "deeplink":"",
    "qr": ""
    }
}

```

http status code 200, else 400 and error body

## POST /document

### Direction

Issuer --> Datastore/authentic source

### Request

```json
{
"authentic_source": "",
"document_type": "",
"document_id": ""
}
```

### Response

```json
{
    "data": {
        "document_data":"",
        "meta": {
            "authentic_source": "",
            "document_id": "",
            "document_type": "",
            "uuid": "",
            "revocation_id": "",
            "document_id": "",
            "collect_id": "",
            "authentic_source_person_id": "",
            "document_version": 0,
        },
    }
}

```

http status code 200, else 400 and error body

## POST /revoke

### Direction

Authentic source --> Issuer

### Request

```json
{
    "authentic_source":"",
    "document_type":"",
    "revocation_id":"" ,
    "revocation_reference":"",
    "revocation_datetime":"", 
}
```

### Response

http status code 200, else 400 and error body

## Types

### meta{}

|type| Attribute | required | description |
|-|-|-|-|
| string | authentic_source | true | |
| string | document_id | true | |
| string | document_type |true | Type of Document “EHIC” or “PDA1” |
| string | uuid | true | ID of the uploaded document Must be generated by authentic source unique per document type|
| string | revocation_id | true | ID for credential revocation; If not defined by institution it should be set to document_id value after upload. Different value may be used to llow credential coupling |
| string | collection_id | false | If not defined by institution it should be set to document_id value after upload.|
| string | authentic_source_person_id |true | Institutional identifier of the person/subject|
| integer | document_data_version | true | JSON object document data version |

### identity{}

|type| Attribute | required | description |
|-|-|-|-|
| integer | identity_version |true | Identity data version|
| string | family_name |true | As in current PID namespace |
| string | given_name | true | As in current PID namespace |
| string | birth_date |true | As in current PID namespace |
| string | uuid | true | As in current PID namespace |
| string | family_name_birth | false | As in current PID namespace |
| string | given_name_birth | false | As in current PID namespace |
| string | birth_place | false | As in current PID namespace |
| string | gender | false | As in current PID namespace |
| string | age_over_18 | false | As in current PID namespace |
| string | age_over_NN | false | As in current PID namespace |
| string | age_in_years | false | As in current PID namespace |
| string | age_birth_year | false | As in current PID namespace |
| string | birth_country | false | As in current PID namespace |
| string | birth_state | false | As in current PID namespace|
| string | birth_city | false | As in current PID namespace |
| string | resident_address | false | As in current PID namespace |
| string | resident_country | false | As in current PID namespace |
| string | resident_state | false | As in current PID namespace |
| string | resident_city | false | As in current PID namespace |
| string | resident_postal_code | false | As in current PID namespace |
| string | resident_street | false | As in current PID namespace |
| string | resident_house_number | false | As in current PID namespace |
| string | nationality | false | As in current PID namespace |

### attestation{}

|type| Attribute | required | description |
|-|-|-|-|
| integer | attestation_version | true | |
| string | attestation_type | true |  For internal display interpretation/differentiation |
| string | description_short | true | To display in the portal |
| string | description_long | true | To display in the portal |
| string | valid_from | true | Validity information of the attestation, iso8601/epoche |
| string | valid_to | true | Validity information of the attestation, iso8601/epoche |

### document_data{}

unspecified json object, used to include any document type from authentic source

## Error response

<<<<<<< HEAD
```json
{
    "title":"",
    "details": {}
}
```
=======
http status code 200, else 400
[//]: TODO(masv): add json error response
>>>>>>> 671ed46 (Add comment.)

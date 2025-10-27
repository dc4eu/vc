package statusissuer

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	StatusValid uint8 = iota
	StatusInvalid
	StatusSuspended
)

const ReferencedTokenLength = 8

type StatusList struct {
	// Bits: REQUIRED. JSON Integer specifying the number of bits per Referenced Token in the compressed byte array (lst). The allowed values for bits are 1,2,4 and 8.
	Bits int `json:"bits" validate:"required,oneof=1 2 4 8"`

	// Lst: REQUIRED. JSON String that contains the status values for all the Referenced Tokens it conveys statuses for. The value MUST be the base64url-encoded compressed byte array as specified in Section 4.1.
	Lst string `json:"lst" validate:"required"`

	// AggregationURI: OPTIONAL. JSON String that contains a URI to retrieve the Status List Aggregation for this type of Referenced Token or Issuer. See section Section 9 for further details.
	AggregationURI string `json:"aggregation_uri,omitempty"`
}

func (s *Service) Append(ctx context.Context, file *os.File, status uint8) error {
	var binbuf bytes.Buffer
	err := binary.Write(&binbuf, binary.BigEndian, status)
	if err != nil {
		return err
	}
	_, err = file.Write(binbuf.Bytes())
	if err != nil {
		fmt.Println("error", err)
		return err
	}

	return nil
}

func (s *Service) CompressAndEncode(ctx context.Context, statuses []uint8) (string, error) {
	var b bytes.Buffer
	w, err := zlib.NewWriterLevel(&b, zlib.BestCompression)
	if err != nil {
		return "", err
	}

	_, err = w.Write(statuses)
	if err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	return s.base64URLEncode(ctx, b.Bytes()), nil

}

func (s *Service) base64URLEncode(ctx context.Context, data []uint8) string {
	return base64.URLEncoding.EncodeToString(data)
}

func (s *Service) ReadAt(ctx context.Context, file *os.File, index int64) (uint8, error) {
	var status uint8

	_, err := file.Seek(index, 0)
	if err != nil {
		return 0, err
	}

	err = binary.Read(file, binary.BigEndian, &status)
	if err != nil {
		return 0, err
	}

	return status, nil
}

func (s *Service) Load(ctx context.Context, file *os.File, index int64) ([]uint8, error) {
	i := []uint8{}

	if err := binary.Read(file, binary.BigEndian, &i); err != nil {
		return nil, err
	}

	return i, nil
}

func (s *Service) Read(filePath string) error {
	var m []uint8
	f, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	buf := bytes.NewReader(f)
	err = binary.Read(buf, binary.BigEndian, &m)
	if err != nil {
		return err
	}

	fmt.Println("buf", buf, "m", m)

	return nil
}

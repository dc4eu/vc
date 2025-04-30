package bootstrapper

import (
	"context"
	"testing"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func mockClient() *Client {
	return &Client{
		identities: map[string]*model.CompleteDocument{},
	}
}

func TestMakeSourceDataEHIC(t *testing.T) {
	ctx := context.Background()

	c := mockClient()
	err := c.makeIdentities("testdata/users_paris.xlsx")
	assert.NoError(t, err)

	ehicClient, err := NewEHICClient(ctx, c)
	assert.NoError(t, err)

	err = ehicClient.makeSourceData("testdata/users_paris.xlsx")
	assert.NoError(t, err)

	err = ehicClient.save2Disk()
	assert.NoError(t, err)

}

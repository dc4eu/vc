package bootstrapper

import (
	"context"
	"testing"
	"vc/pkg/datastoreclient"

	"github.com/stretchr/testify/assert"
)

func mockClient() *Client {
	return &Client{
		identities: map[string]*datastoreclient.UploadRequest{},
	}
}

func TestCreateJSONSourceFiles(t *testing.T) {
	ctx := context.Background()
	c := mockClient()
	err := c.makeIdentities("testdata/users_paris.xlsx")
	assert.NoError(t, err)

	t.Run("ehic", func(t *testing.T) {
		client, err := NewEHICClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("pda1", func(t *testing.T) {
		client, err := NewPDA1Client(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("pid", func(t *testing.T) {
		client, err := NewPIDClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("elm", func(t *testing.T) {
		client, err := NewELMClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("diploma", func(t *testing.T) {
		client, err := NewDiplomaClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("micro_credential", func(t *testing.T) {
		client, err := NewMicroCredentialClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)

	})
}

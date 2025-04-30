package bootstrapper

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeSourceDataPDA1(t *testing.T) {
	ctx := context.Background()

	c := mockClient()
	err := c.makeIdentities("testdata/users_paris.xlsx")
	assert.NoError(t, err)

	pda1Client, err := NewPDA1Client(ctx, c)
	assert.NoError(t, err)

	err = pda1Client.makeSourceData("testdata/users_paris.xlsx")
	assert.NoError(t, err)

	err = pda1Client.save2Disk()
	assert.NoError(t, err)

}

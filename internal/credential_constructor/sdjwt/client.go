package sdjwt

import (
	"context"
)

type Client struct {
	//sdjwtClient *gosdjwt.Client
}

func New(ctx context.Context) (*Client, error) {
	client := &Client{}

	//sdClient, err := gosdjwt.New(ctx, gosdjwt.Config{
	//	JWTType:       "",
	//	SigningMethod: jwt.SigningMethodES256,
	//	Presentation:  nil,
	//})
	//if err != nil {
	//	return nil, err
	//}

	//ins := gosdjwt.Instructions{}

	//siningKey := ""

	//cred, err := sdClient.SDJWT(ins, siningKey)
	//if err != nil {
	//	return nil, err
	//}

	return client, nil
}

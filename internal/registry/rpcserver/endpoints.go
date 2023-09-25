package rpcserver

import (
	"context"
	"vc/internal/registry/apiv1"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// V1 is the handler for rpcserver version 1
type V1 struct {
	log   *logger.Log
	apiv1 Apiv1
}

// Add is the RPC endpoint for apiv1.Add
func (v *V1) Add(args *apiv1.AddRequest, reply *apiv1.AddReply) error {
	ctx := context.Background()
	v.log.Info("Add message called")
	reply, err := v.apiv1.Add(ctx, args)
	if err != nil {
		return err
	}
	return nil
}

// Revoke is the RPC endpoint for apiv1.Revoke
func (v *V1) Revoke(args *apiv1.RevokeRequest, reply *apiv1.RevokeReply) error {
	ctx := context.Background()
	v.log.Info("Revoke message called")
	reply, err := v.apiv1.Revoke(ctx, args)
	if err != nil {
		return err
	}
	return nil
}

// Validate is the RPC endpoint for apiv1.Validate
func (v *V1) Validate(args *apiv1.ValidateRequest, reply *apiv1.ValidateReply) error {
	ctx := context.Background()
	v.log.Info("Validate message called")
	reply, err := v.apiv1.Validate(ctx, args)
	if err != nil {
		return err
	}
	return nil
}

// Status is the RPC endpoint for apiv1.Status
func (v *V1) Status(args string, reply *model.Health) error {
	ctx := context.Background()
	v.log.Info("Status message called")
	reply, err := v.apiv1.Status(ctx)
	if err != nil {
		return err
	}
	return nil
}

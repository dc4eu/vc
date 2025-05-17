package httpserver

import (
	"context"
	"vc/internal/apigw/apiv1"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
	"vc/pkg/openid4vci"
	"vc/pkg/vcclient"

	"go.opentelemetry.io/otel/codes"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointUpload(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUpload")
	defer span.End()

	request := &apiv1.UploadRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.cfg.Common.Kafka.Enabled {
		err := s.eventPublisher.Upload(request)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		return nil, nil
	}

	if err := s.apiv1.Upload(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return nil, nil
}

func (s *Service) endpointAddPIDUser(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAddPIDUser")
	defer span.End()

	request := &vcclient.AddPIDRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	err := s.apiv1.AddPIDUser(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return nil, nil
}

func (s *Service) endpointLoginPIDUser(ctx context.Context, g *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointLoginPIDUser")
	defer span.End()

	request := &vcclient.LoginPIDUserRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, g, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.LoginPIDUser(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return reply, nil
}

func (s *Service) endpointNotification(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointNotification")
	defer span.End()

	request := &apiv1.NotificationRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.Notification(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointAddDocumentIdentity(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointNotification")
	defer span.End()

	request := &apiv1.AddDocumentIdentityRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if err := s.apiv1.AddDocumentIdentity(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}

func (s *Service) endpointDeleteDocumentIdentity(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointNotification")
	defer span.End()

	request := &apiv1.DeleteDocumentIdentityRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if err := s.apiv1.DeleteDocumentIdentity(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}
func (s *Service) endpointGetDocument(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointGetDocument")
	defer span.End()

	request := &apiv1.GetDocumentRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.GetDocument(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointSearchDocuments(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSearchDocuments")
	defer span.End()

	request := &model.SearchDocumentsRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.SearchDocuments(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointRevokeDocument(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointRevokeDocument")
	defer span.End()

	request := &apiv1.RevokeDocumentRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if err := s.apiv1.RevokeDocument(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}

func (s *Service) endpointDeleteDocument(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDeleteDocument")
	defer span.End()

	request := &apiv1.DeleteDocumentRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	err := s.apiv1.DeleteDocument(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}

func (s *Service) endpointGetDocumentCollectID(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointGetDocumentAttestation")
	defer span.End()

	request := &apiv1.GetDocumentCollectIDRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.GetDocumentCollectID(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointIdentityMapping(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointIdentityMapping")
	defer span.End()

	request := &apiv1.IdentityMappingRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.IdentityMapping(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointDocumentList(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDocumentList")
	defer span.End()

	request := &apiv1.DocumentListRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.DocumentList(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointAddConsent(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointPortal")
	defer span.End()

	request := &apiv1.AddConsentRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if err := s.apiv1.AddConsent(ctx, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return nil, nil
}

func (s *Service) endpointGetConsent(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointPortal")
	defer span.End()

	request := &apiv1.GetConsentRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.GetConsent(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointHealth(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointHealth")
	defer span.End()

	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Health(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint
func (s *Service) endpointOIDCNonce(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointNonce")
	defer span.End()

	reply, err := s.apiv1.OIDCNonce(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-14.html#name-sending-credential-offer-by-
func (s *Service) endpointOIDCredentialOfferURI(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointCredential")
	defer span.End()

	request := &openid4vci.CredentialOfferURIRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.OIDCredentialOfferURI(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint
func (s *Service) endpointOIDCCredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCredential")
	defer span.End()

	request := &openid4vci.CredentialRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.OIDCCredential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoint
func (s *Service) endpointOIDCDeferredCredential(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointDeferredCredential")
	defer span.End()

	request := &openid4vci.DeferredCredentialRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.OIDCDeferredCredential(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return reply, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint
func (s *Service) endpointOIDCNotification(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointNotification")
	defer span.End()

	request := &openid4vci.NotificationRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	err := s.apiv1.OIDCNotification(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	c.Status(204)
	return nil, nil
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-issuer-metadata-
func (s *Service) endpointOIDCMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointMetadata")
	defer span.End()

	reply, err := s.apiv1.OIDCMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")
	return reply, nil
}


//func (s *Service) endpointJWKS(ctx context.Context, c *gin.Context) (any, error) {
//	ctx, span := s.tracer.Start(ctx, "httpserver:endpointJWKS")
//	defer span.End()
//
//	reply, err := s.apiv1.JWKS(ctx)
//	if err != nil {
//		span.SetStatus(codes.Error, err.Error())
//		return nil, err
//	}
//	return reply, nil
//}

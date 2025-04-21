// server/platform/service/federated_identities.go
package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log" // TODO: Replace with Dex structured logger
	"strconv"
	"strings"
	"time"

	// Ent imports
	"github.com/dexidp/dex/storage/ent/db" // Generated Ent types, error types

	// Dex storage interface
	pstorage "github.com/dexidp/dex/server/platform/storage"

	// gRPC & Protobuf
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	// Needed for AppRole conversion
	// Dex API
	api "github.com/dexidp/dex/api/v2"

	// LibPQ for error checking
	"github.com/lib/pq"
)

// platformFederatedIdentityService implements the api.PlatformFederatedIdentityServiceServer interface.
type platformFederatedIdentityService struct {
	api.UnimplementedPlatformFederatedIdentityServiceServer
	storage pstorage.PlatformStorage
	// logger dexlogger.Logger // Add logger field
}

// NewPlatformFederatedIdentityService creates a new handler for the PlatformFederatedIdentityService.
func NewPlatformFederatedIdentityService(storage pstorage.PlatformStorage) api.PlatformFederatedIdentityServiceServer {
	if storage == nil {
		log.Fatal("PlatformStorage cannot be nil for PlatformFederatedIdentityService")
	}
	return &platformFederatedIdentityService{storage: storage}
}

// GetPlatformFederatedIdentity handles retrieving a single federated identity by ID.
func (s *platformFederatedIdentityService) GetPlatformFederatedIdentity(ctx context.Context, req *api.GetPlatformFederatedIdentityRequest) (*api.GetPlatformFederatedIdentityResponse, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "federated identity ID cannot be empty")
	}
	fedID, err := stringIDToInt(req.GetId()) // Use helper
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid federated identity ID format: %v", err)
	}
	// TODO: Authorization check

	entFedId, err := s.storage.GetFederatedIdentityByID(ctx, fedID)
	if err != nil {
		var nfe *db.NotFoundError
		if errors.As(err, &nfe) {
			log.Printf("INFO: GetPlatformFederatedIdentity - not found ID %d", fedID)
			return nil, status.Errorf(codes.NotFound, "federated identity with ID '%s' not found", req.GetId())
		}
		log.Printf("ERROR: GetPlatformFederatedIdentity - storage error ID %d: %v", fedID, err)
		return nil, status.Errorf(codes.Internal, "failed to get federated identity")
	}

	protoFedId := toProtoPlatformFederatedIdentity(entFedId) // Requires helper
	if protoFedId == nil {
		log.Printf("ERROR: GetPlatformFederatedIdentity - failed convert ID %d", fedID)
		return nil, status.Errorf(codes.Internal, "failed to process federated identity data")
	}

	return &api.GetPlatformFederatedIdentityResponse{PlatformFederatedIdentity: protoFedId}, nil
}

// ListPlatformFederatedIdentities handles listing identities with pagination and filters.
func (s *platformFederatedIdentityService) ListPlatformFederatedIdentities(ctx context.Context, req *api.ListPlatformFederatedIdentitiesRequest) (*api.ListPlatformFederatedIdentitiesResponse, error) {
	// --- Pagination Setup ---
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}

	var cursorTime *time.Time
	var cursorID *int
	if req.GetPageToken() != "" {
		decodedTime, decodedID, err := decodeFedIdPageToken(req.GetPageToken()) // Use specific decoder
		if err != nil {
			log.Printf("WARN: ListPlatformFederatedIdentities - invalid page token: %v", err)
			return nil, status.Errorf(codes.InvalidArgument, "invalid page token: %v", err)
		}
		cursorTime = &decodedTime
		cursorID = &decodedID
	}

	// --- Prepare Filters ---
	filters := pstorage.FederatedIdentityFilters{}
	if userID := req.GetFilterPlatformUserId(); userID != "" {
		if _, err := stringIDToInt(userID); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid filter_platform_user_id format: %v", err)
		}
		filters.PlatformUserID = userID
	}
	if connID := req.GetFilterConnectorId(); connID != "" {
		filters.ConnectorID = connID
	}
	if subject := req.GetFilterConnectorSubject(); subject != "" {
		filters.ConnectorSubject = subject
	}
	// TODO: Authorization check

	// --- Execute Query ---
	limit := pageSize + 1
	entFedIds, err := s.storage.ListFederatedIdentitiesPaginated(ctx, limit, cursorTime, cursorID, filters)
	if err != nil {
		log.Printf("ERROR: ListPlatformFederatedIdentities - storage error: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list federated identities")
	}

	// --- Pagination Token ---
	hasNextPage := false
	if len(entFedIds) > pageSize {
		hasNextPage = true
		entFedIds = entFedIds[:pageSize]
	}

	nextPageToken := ""
	if hasNextPage && len(entFedIds) > 0 {
		lastFedId := entFedIds[len(entFedIds)-1]
		encodedToken, errEnc := encodeFedIdPageToken(*lastFedId) // Use specific encoder
		if errEnc != nil {
			log.Printf("ERROR: ListPlatformFederatedIdentities - failed encode next page token ID %d: %v", lastFedId.ID, errEnc)
		} else {
			nextPageToken = encodedToken
		}
	}

	// --- Convert Results ---
	protoFedIds := make([]*api.PlatformFederatedIdentity, 0, len(entFedIds))
	for _, entFedId := range entFedIds {
		protoFedId := toProtoPlatformFederatedIdentity(entFedId) // Requires helper
		if protoFedId != nil {
			protoFedIds = append(protoFedIds, protoFedId)
		} else {
			log.Printf("WARN: ListPlatformFederatedIdentities - failed convert ID %d", entFedId.ID)
		}
	}

	// --- Return Response ---
	return &api.ListPlatformFederatedIdentitiesResponse{
		Identities:    protoFedIds,
		NextPageToken: nextPageToken,
	}, nil
}

// DeletePlatformFederatedIdentity handles deleting a federated identity.
func (s *platformFederatedIdentityService) DeletePlatformFederatedIdentity(ctx context.Context, req *api.DeletePlatformFederatedIdentityRequest) (*emptypb.Empty, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "federated identity ID cannot be empty")
	}
	fedID, err := stringIDToInt(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid federated identity ID format: %v", err)
	}
	// TODO: Authorization check

	err = s.storage.DeleteFederatedIdentityByID(ctx, fedID)
	if err != nil {
		var nfe *db.NotFoundError
		if errors.As(err, &nfe) {
			log.Printf("INFO: DeletePlatformFederatedIdentity - not found ID %d", fedID)
			return nil, status.Errorf(codes.NotFound, "federated identity with ID '%s' not found", req.GetId())
		}
		// Add FK check? Deleting identity might fail if assignments exist depending on schema.
		log.Printf("ERROR: DeletePlatformFederatedIdentity - storage error ID %d: %v", fedID, err)
		return nil, status.Errorf(codes.Internal, "failed to delete federated identity")
	}

	log.Printf("INFO: Successfully deleted federated identity ID %d", fedID)
	return &emptypb.Empty{}, nil
}

// --- Identity Role Assignment RPC Implementations ---

func (s *platformFederatedIdentityService) AssignRoleToIdentity(ctx context.Context, req *api.AssignRoleToIdentityRequest) (*api.AssignRoleToIdentityResponse, error) {
	if req.GetPlatformFederatedIdentityId() == "" || req.GetPlatformAppRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "platform_federated_identity_id and platform_app_role_id are required")
	}
	identityID, err := stringIDToInt(req.GetPlatformFederatedIdentityId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_federated_identity_id format: %v", err)
	}
	roleID, err := stringIDToInt(req.GetPlatformAppRoleId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_app_role_id format: %v", err)
	}
	// TODO: Authorization check

	assignment, err := s.storage.AssignRoleToIdentity(ctx, identityID, roleID)
	if err != nil {
		var constraintErr *db.ConstraintError
		var pqErr *pq.Error
		if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && (pqErr.Code == "23505" || pqErr.Code == "23503")) {
			log.Printf("INFO: AssignRoleToIdentity - constraint violation identity=%d, role=%d: %v", identityID, roleID, err)
			if errors.As(err, &pqErr) && pqErr.Code == "23505" {
				return nil, status.Errorf(codes.AlreadyExists, "role %d already assigned to identity %d", roleID, identityID)
			}
			return nil, status.Errorf(codes.FailedPrecondition, "cannot assign role: identity or role not found, or assignment already exists")
		}
		log.Printf("ERROR: AssignRoleToIdentity - storage error identity=%d, role=%d: %v", identityID, roleID, err)
		return nil, status.Errorf(codes.Internal, "failed to assign role")
	}

	return &api.AssignRoleToIdentityResponse{AssignmentId: strconv.Itoa(assignment.ID)}, nil
}

func (s *platformFederatedIdentityService) RemoveRoleFromIdentity(ctx context.Context, req *api.RemoveRoleFromIdentityRequest) (*emptypb.Empty, error) {
	if req.GetPlatformFederatedIdentityId() == "" || req.GetPlatformAppRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "platform_federated_identity_id and platform_app_role_id are required")
	}
	identityID, err := stringIDToInt(req.GetPlatformFederatedIdentityId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_federated_identity_id format: %v", err)
	}
	roleID, err := stringIDToInt(req.GetPlatformAppRoleId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_app_role_id format: %v", err)
	}
	// TODO: Authorization check

	err = s.storage.RemoveRoleFromIdentity(ctx, identityID, roleID)
	if err != nil {
		// Check if it's the specific "not found" error returned by the storage layer
		if strings.Contains(err.Error(), "not found") { // TODO: Improve error checking
			log.Printf("INFO: RemoveRoleFromIdentity - assignment not found identity=%d, role=%d", identityID, roleID)
			return nil, status.Errorf(codes.NotFound, "role assignment for identity %d and role %d not found", identityID, roleID)
		}
		log.Printf("ERROR: RemoveRoleFromIdentity - storage error identity=%d, role=%d: %v", identityID, roleID, err)
		return nil, status.Errorf(codes.Internal, "failed to remove role assignment")
	}

	return &emptypb.Empty{}, nil
}

func (s *platformFederatedIdentityService) ListIdentityAssignments(ctx context.Context, req *api.ListIdentityAssignmentsRequest) (*api.ListIdentityAssignmentsResponse, error) {
	if req.GetPlatformFederatedIdentityId() == "" {
		return nil, status.Error(codes.InvalidArgument, "platform_federated_identity_id is required")
	}
	identityID, err := stringIDToInt(req.GetPlatformFederatedIdentityId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_federated_identity_id format: %v", err)
	}
	// TODO: Authorization check

	// Prepare filters for storage layer
	filters := pstorage.AssignmentFilters{}
	if req.FilterAppId != "" {
		filters.AppID = req.FilterAppId
	}
	if filter := req.GetFilterAssignmentIsActive(); filter != nil {
		tmpBool := filter.GetValue()
		filters.AssignmentIsActive = &tmpBool
	}
	if filter := req.GetFilterRoleIsActive(); filter != nil {
		tmpBool := filter.GetValue()
		filters.RoleIsActive = &tmpBool
	}
	// TODO: Add pagination if needed

	entRoles, err := s.storage.ListIdentityRoles(ctx, identityID, filters)
	if err != nil {
		log.Printf("ERROR: ListIdentityAssignments - storage error for identity=%d: %v", identityID, err)
		return nil, status.Errorf(codes.Internal, "failed to list role assignments")
	}

	// Convert Ent roles to Proto roles
	protoRoles := make([]*api.PlatformAppRole, 0, len(entRoles))
	for _, entRole := range entRoles {
		protoRole := toProtoPlatformAppRole(entRole) // Reuse helper
		if protoRole != nil {
			protoRoles = append(protoRoles, protoRole)
		} else {
			log.Printf("WARN: ListIdentityAssignments - failed to convert role (ID: %d) to proto", entRole.ID)
		}
	}

	return &api.ListIdentityAssignmentsResponse{AssignedRoles: protoRoles}, nil
}

// encodeFedIdPageToken encodes cursor information for federated identities.
func encodeFedIdPageToken(fedId db.PlatformFederatedIdentity) (string, error) {
	if fedId.ID == 0 || fedId.CreateTime.IsZero() {
		return "", errors.New("cannot encode cursor for federated identity with zero ID or CreateTime")
	}
	cursor := fmt.Sprintf("%d_%d", fedId.CreateTime.UnixNano(), fedId.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(cursor)), nil
}

// decodeFedIdPageToken decodes a page token for federated identities.
func decodeFedIdPageToken(token string) (cursorTime time.Time, cursorID int, err error) {
	if token == "" {
		err = errors.New("page token is empty")
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		err = fmt.Errorf("invalid page token encoding: %w", err)
		return
	}
	parts := strings.SplitN(string(decoded), "_", 2)
	if len(parts) != 2 {
		err = errors.New("invalid page token format")
		return
	}
	timeNano, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		err = fmt.Errorf("invalid time in page token: %w", err)
		return
	}
	cursorID, err = strconv.Atoi(parts[1])
	if err != nil || cursorID <= 0 {
		err = fmt.Errorf("invalid ID in page token: %w", err)
		return
	}
	cursorTime = time.Unix(0, timeNano).UTC()
	return
}

// toProtoPlatformFederatedIdentity converts *db.PlatformFederatedIdentity to *api.PlatformFederatedIdentity.
// Requires User edge to be loaded.
func toProtoPlatformFederatedIdentity(entFedId *db.PlatformFederatedIdentity) *api.PlatformFederatedIdentity {
	if entFedId == nil {
		return nil
	}

	var user *api.PlatformUser
	if entFedId.Edges.User != nil {
		user = toProtoPlatformUser(entFedId.Edges.User) // Reuse helper
	} else {
		log.Printf("WARN: toProtoPlatformFederatedIdentity - User edge not loaded for FedID %d", entFedId.ID)
	}

	return &api.PlatformFederatedIdentity{
		Id:               strconv.Itoa(entFedId.ID),
		User:             user,
		ConnectorId:      entFedId.ConnectorID,
		ConnectorSubject: entFedId.ConnectorSubject, // Use correct field name
		CreateTime:       timestamppb.New(entFedId.CreateTime),
		UpdateTime:       timestamppb.New(entFedId.UpdateTime),
	}
}

// --- Need these helpers if not moved yet ---
// func toProtoPlatformUser(entUser *db.PlatformUser) *api.PlatformUser { ... }
// func toProtoPlatformAppRole(entRole *db.PlatformAppRole) *api.PlatformAppRole { ... }

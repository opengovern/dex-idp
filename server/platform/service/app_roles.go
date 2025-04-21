// server/platform/service/app_roles.go
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

	// Dex API
	api "github.com/dexidp/dex/api/v2"

	// LibPQ for error checking
	"github.com/lib/pq"
)

// platformAppRoleService implements the api.PlatformAppRoleServiceServer interface.
type platformAppRoleService struct {
	api.UnimplementedPlatformAppRoleServiceServer
	storage pstorage.PlatformStorage
	// logger dexlogger.Logger // Add logger field
}

// NewPlatformAppRoleService creates a new handler for the PlatformAppRoleService.
func NewPlatformAppRoleService(storage pstorage.PlatformStorage) api.PlatformAppRoleServiceServer {
	if storage == nil {
		log.Fatal("PlatformStorage cannot be nil for PlatformAppRoleService")
	}
	return &platformAppRoleService{storage: storage}
}

// CreatePlatformAppRole handles the RPC call to create a new app role.
func (s *platformAppRoleService) CreatePlatformAppRole(ctx context.Context, req *api.CreatePlatformAppRoleRequest) (*api.CreatePlatformAppRoleResponse, error) {
	// Basic Input Validation
	appID := strings.TrimSpace(req.GetAppId())
	title := strings.TrimSpace(req.GetTitle())
	if appID == "" || title == "" {
		return nil, status.Error(codes.InvalidArgument, "app_id and title are required")
	}
	// TODO: Validate app_id format (should match a Dex client ID?)

	roleData := &db.PlatformAppRole{
		AppID: appID,
		Title: title,
		// Set defaults based on schema (e.g., IsActive=true, Weight=0)
		IsActive: true,
		Weight:   0,
	}
	if desc := req.GetDescription(); desc != nil {
		descValue := desc.GetValue()      // Get the actual string value
		roleData.Description = &descValue // Assign the ADDRESS of the string value
	}
	if weight := req.GetWeight(); weight != nil {
		roleData.Weight = int(weight.GetValue()) // Convert int32 to int
	}
	if isActive := req.GetIsActive(); isActive != nil {
		roleData.IsActive = isActive.GetValue() // Allow setting initial state
	}

	createdEntRole, err := s.storage.CreateAppRole(ctx, roleData)
	if err != nil {
		var constraintErr *db.ConstraintError
		var pqErr *pq.Error
		if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && pqErr.Code == "23505") {
			log.Printf("INFO: CreatePlatformAppRole - constraint violation app=%s, title=%s", appID, title)
			return nil, status.Errorf(codes.AlreadyExists, "role with title '%s' already exists for app '%s'", title, appID)
		}
		log.Printf("ERROR: CreatePlatformAppRole - storage error app=%s, title=%s: %v", appID, title, err)
		return nil, status.Errorf(codes.Internal, "failed to create app role")
	}

	protoRole := toProtoPlatformAppRole(createdEntRole)
	if protoRole == nil {
		log.Printf("ERROR: CreatePlatformAppRole - failed to convert role ID %d", createdEntRole.ID)
		return nil, status.Errorf(codes.Internal, "failed to process created app role data")
	}

	return &api.CreatePlatformAppRoleResponse{PlatformAppRole: protoRole}, nil
}

// GetPlatformAppRole handles retrieving a single app role by ID.
func (s *platformAppRoleService) GetPlatformAppRole(ctx context.Context, req *api.GetPlatformAppRoleRequest) (*api.GetPlatformAppRoleResponse, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "role ID cannot be empty")
	}
	roleID, err := stringIDToInt(req.GetId()) // Use helper
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role ID format: %v", err)
	}
	// TODO: Authorization check

	entRole, err := s.storage.GetAppRoleByID(ctx, roleID)
	if err != nil {
		var nfe *db.NotFoundError
		if errors.As(err, &nfe) {
			log.Printf("INFO: GetPlatformAppRole - role not found ID %d", roleID)
			return nil, status.Errorf(codes.NotFound, "app role with ID '%s' not found", req.GetId())
		}
		log.Printf("ERROR: GetPlatformAppRole - storage error ID %d: %v", roleID, err)
		return nil, status.Errorf(codes.Internal, "failed to get app role")
	}

	protoRole := toProtoPlatformAppRole(entRole)
	if protoRole == nil {
		log.Printf("ERROR: GetPlatformAppRole - failed convert role ID %d", roleID)
		return nil, status.Errorf(codes.Internal, "failed to process app role data")
	}

	return &api.GetPlatformAppRoleResponse{PlatformAppRole: protoRole}, nil
}

// ListPlatformAppRoles handles listing roles with pagination and filters.
func (s *platformAppRoleService) ListPlatformAppRoles(ctx context.Context, req *api.ListPlatformAppRolesRequest) (*api.ListPlatformAppRolesResponse, error) {
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
		decodedTime, decodedID, err := decodeAppRolePageToken(req.GetPageToken()) // Use role-specific decoder
		if err != nil {
			log.Printf("WARN: ListPlatformAppRoles - invalid page token: %v", err)
			return nil, status.Errorf(codes.InvalidArgument, "invalid page token: %v", err)
		}
		cursorTime = &decodedTime
		cursorID = &decodedID
	}

	// --- Prepare Filters ---
	filters := pstorage.AppRoleFilters{}
	if appID := req.GetFilterAppId(); appID != "" {
		filters.AppID = appID // Often a required filter
	} else {
		// Decide if AppID filter is mandatory for listing roles
		// return nil, status.Error(codes.InvalidArgument, "filter_app_id is required")
	}
	if filter := req.GetFilterIsActive(); filter != nil {
		tmpBool := filter.GetValue()
		filters.IsActive = &tmpBool
	}
	if filter := req.GetFilterTitleContains(); filter != "" {
		filters.TitleContains = strings.TrimSpace(filter)
	}
	// TODO: Authorization check (e.g., filter by apps user has access to?)

	// --- Execute Query ---
	limit := pageSize + 1 // Fetch one extra
	entRoles, err := s.storage.ListAppRolesPaginated(ctx, limit, cursorTime, cursorID, filters)
	if err != nil {
		log.Printf("ERROR: ListPlatformAppRoles - storage error: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list app roles")
	}

	// --- Pagination Token ---
	hasNextPage := false
	if len(entRoles) > pageSize {
		hasNextPage = true
		entRoles = entRoles[:pageSize] // Trim extra
	}

	nextPageToken := ""
	if hasNextPage && len(entRoles) > 0 {
		lastRole := entRoles[len(entRoles)-1]
		encodedToken, errEnc := encodeAppRolePageToken(*lastRole) // Use role-specific encoder
		if errEnc != nil {
			log.Printf("ERROR: ListPlatformAppRoles - failed encode next page token for role ID %d: %v", lastRole.ID, errEnc)
		} else {
			nextPageToken = encodedToken
		}
	}

	// --- Convert Results ---
	protoRoles := make([]*api.PlatformAppRole, 0, len(entRoles))
	for _, entRole := range entRoles {
		protoRole := toProtoPlatformAppRole(entRole)
		if protoRole != nil {
			protoRoles = append(protoRoles, protoRole)
		} else {
			log.Printf("WARN: ListPlatformAppRoles - failed convert role ID %d", entRole.ID)
		}
	}

	// --- Return Response ---
	return &api.ListPlatformAppRolesResponse{
		Roles:         protoRoles,
		NextPageToken: nextPageToken,
	}, nil
}

// UpdatePlatformAppRole handles updating an app role.
func (s *platformAppRoleService) UpdatePlatformAppRole(ctx context.Context, req *api.UpdatePlatformAppRoleRequest) (*api.UpdatePlatformAppRoleResponse, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "role ID cannot be empty")
	}
	roleID, err := stringIDToInt(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role ID format: %v", err)
	}
	// TODO: Authorization check

	updateData := make(map[string]interface{})
	hasUpdate := false
	// Title updates must be handled carefully due to unique constraint (app_id, title)
	if title := req.GetTitle(); title != nil {
		trimmedTitle := strings.TrimSpace(title.GetValue())
		if trimmedTitle == "" {
			return nil, status.Errorf(codes.InvalidArgument, "title cannot be empty")
		}
		updateData["Title"] = trimmedTitle
		hasUpdate = true
	}
	if desc := req.GetDescription(); desc != nil {
		updateData["Description"] = desc.GetValue() // Allow setting empty description
		hasUpdate = true
	}
	if weight := req.GetWeight(); weight != nil {
		updateData["Weight"] = int(weight.GetValue()) // Convert int32
		hasUpdate = true
	}
	if isActive := req.GetIsActive(); isActive != nil {
		updateData["IsActive"] = isActive.GetValue()
		hasUpdate = true
	}

	if !hasUpdate {
		return nil, status.Errorf(codes.InvalidArgument, "no fields provided for update")
	}

	updatedEntRole, err := s.storage.UpdateAppRole(ctx, roleID, updateData)
	if err != nil {
		var nfe *db.NotFoundError
		var constraintErr *db.ConstraintError
		var pqErr *pq.Error
		if errors.As(err, &nfe) {
			log.Printf("INFO: UpdatePlatformAppRole - role not found ID %d", roleID)
			return nil, status.Errorf(codes.NotFound, "app role with ID '%s' not found", req.GetId())
		} else if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && pqErr.Code == "23505") {
			log.Printf("INFO: UpdatePlatformAppRole - constraint violation for role ID %d", roleID)
			return nil, status.Errorf(codes.AlreadyExists, "update failed, title may already exist for this app")
		}
		log.Printf("ERROR: UpdatePlatformAppRole - storage error ID %d: %v", roleID, err)
		return nil, status.Errorf(codes.Internal, "failed to update app role")
	}

	protoRole := toProtoPlatformAppRole(updatedEntRole)
	if protoRole == nil {
		log.Printf("ERROR: UpdatePlatformAppRole - failed convert updated role ID %d", roleID)
		return nil, status.Errorf(codes.Internal, "failed to process updated app role data")
	}

	return &api.UpdatePlatformAppRoleResponse{PlatformAppRole: protoRole}, nil
}

// DeletePlatformAppRole handles deleting an app role.
func (s *platformAppRoleService) DeletePlatformAppRole(ctx context.Context, req *api.DeletePlatformAppRoleRequest) (*emptypb.Empty, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "role ID cannot be empty")
	}
	roleID, err := stringIDToInt(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role ID format: %v", err)
	}
	// TODO: Authorization check

	err = s.storage.DeleteAppRoleByID(ctx, roleID)
	if err != nil {
		var nfe *db.NotFoundError
		var pqErr *pq.Error
		if errors.As(err, &nfe) {
			log.Printf("INFO: DeletePlatformAppRole - role not found ID %d", roleID)
			return nil, status.Errorf(codes.NotFound, "app role with ID '%s' not found", req.GetId())
		} else if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			// Foreign key violation (role referenced by tokens or assignments)
			log.Printf("INFO: DeletePlatformAppRole - FK violation ID %d", roleID)
			return nil, status.Errorf(codes.FailedPrecondition, "cannot delete role, it is currently in use")
		}
		log.Printf("ERROR: DeletePlatformAppRole - storage error ID %d: %v", roleID, err)
		return nil, status.Errorf(codes.Internal, "failed to delete app role")
	}

	log.Printf("INFO: Successfully deleted app role ID %d", roleID)
	return &emptypb.Empty{}, nil
}

// --- Helper Functions (Consider moving to shared package) ---

// encodeAppRolePageToken encodes cursor information for app roles.
func encodeAppRolePageToken(role db.PlatformAppRole) (string, error) {
	if role.ID == 0 || role.CreateTime.IsZero() {
		return "", errors.New("cannot encode cursor for role with zero ID or CreateTime")
	}
	cursor := fmt.Sprintf("%d_%d", role.CreateTime.UnixNano(), role.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(cursor)), nil
}

// decodeAppRolePageToken decodes a page token for app roles.
func decodeAppRolePageToken(token string) (cursorTime time.Time, cursorID int, err error) {
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

// --- Need these helpers if not moved yet ---
// func toProtoPlatformUser(entUser *db.PlatformUser) *api.PlatformUser { ... }
// func toProtoPlatformFederatedIdentity(entFedId *db.PlatformFederatedIdentity) *api.PlatformFederatedIdentity { ... }

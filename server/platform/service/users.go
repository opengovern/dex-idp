// server/platform/service/users.go
package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log" // TODO: Replace with Dex structured logger if available
	"strconv"
	"strings"
	"time"

	// Ent imports
	"github.com/dexidp/dex/storage/ent/db" // Generated Ent client package (used as 'db'), defines error types

	// Dex storage interface
	pstorage "github.com/dexidp/dex/server/platform/storage" // Import platform storage interfaces

	// gRPC related imports
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	// Dex specific imports
	api "github.com/dexidp/dex/api/v2" // Use 'api' alias matching go_package

	// Postgres driver error handling (optional here, might only be needed in storage impl)
	"github.com/lib/pq"
	_ "github.com/lib/pq" // Ensure driver is imported for side effects
)

const (
	DefaultPageSize = 25
	MaxPageSize     = 100
)

// platformUserService implements the api.PlatformUserServiceServer interface.
type platformUserService struct {
	api.UnimplementedPlatformUserServiceServer
	storage pstorage.PlatformStorage // Depends on the *combined* storage interface now
	// Add logger field here if using structured logging
	// logger dexlogger.Logger
}

// NewPlatformUserService creates a new handler for the PlatformUserService.
// Accepts the PlatformStorage interface for dependency injection.
func NewPlatformUserService(storage pstorage.PlatformStorage) api.PlatformUserServiceServer { // Accept combined interface
	if storage == nil {
		log.Fatal("PlatformStorage cannot be nil for PlatformUserService") // Use Fatal for unrecoverable setup errors
	}
	return &platformUserService{storage: storage} // Assign input 'storage' to struct field 'storage'
}

// CreateUser handles the RPC call to create a new platform user.
func (s *platformUserService) CreateUser(ctx context.Context, req *api.CreatePlatformUserRequest) (*api.CreatePlatformUserResponse, error) {
	trimmedEmail := strings.TrimSpace(req.GetEmail())
	if trimmedEmail == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email cannot be empty")
	}
	// TODO: Add email format validation?

	userData := &db.PlatformUser{Email: trimmedEmail}
	if dpName := req.GetDisplayName(); dpName != nil {
		userData.DisplayName = dpName.GetValue()
	}
	if isActive := req.GetIsActive(); isActive != nil {
		userData.IsActive = isActive.GetValue() // Allow setting initial inactive state
	} else {
		userData.IsActive = true // Default to active if not specified
	}

	createdEntUser, err := s.storage.CreateUser(ctx, userData) // Call interface method
	if err != nil {
		var constraintErr *db.ConstraintError // Use generated db type
		var pqErr *pq.Error
		if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && pqErr.Code == "23505") {
			// Log potentially sensitive info only internally
			log.Printf("INFO: Constraint violation creating user %s", trimmedEmail)
			return nil, status.Errorf(codes.AlreadyExists, "user with email '%s' already exists", trimmedEmail)
		}
		log.Printf("ERROR: CreateUser - storage error: %v", err) // Log underlying error
		return nil, status.Errorf(codes.Internal, "failed to create user")
	}

	protoPlatformUser := toProtoPlatformUser(createdEntUser)
	if protoPlatformUser == nil {
		// This should ideally not happen if createdEntUser is not nil
		log.Printf("ERROR: CreateUser - failed to convert created user (ID: %d) to proto", createdEntUser.ID)
		return nil, status.Errorf(codes.Internal, "failed to process created user data")
	}

	return &api.CreatePlatformUserResponse{PlatformUser: protoPlatformUser}, nil
}

// GetUser handles the RPC call to retrieve a single platform user by ID.
func (s *platformUserService) GetUser(ctx context.Context, req *api.GetPlatformUserRequest) (*api.GetPlatformUserResponse, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID cannot be empty")
	}
	// Use helper from storage package if it exists and handles errors well
	// Or implement simple conversion here
	entID, err := strconv.Atoi(req.GetId())
	if err != nil || entID <= 0 { // Also check for positive ID
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format (must be positive integer): %s", req.GetId())
	}

	entUser, err := s.storage.GetUserByID(ctx, entID) // Call interface method
	if err != nil {
		var nfe *db.NotFoundError // Use generated db type
		if errors.As(err, &nfe) {
			// Log level INFO for not found is often appropriate
			log.Printf("INFO: GetUser - user not found for ID %d", entID)
			return nil, status.Errorf(codes.NotFound, "user with ID '%s' not found", req.GetId())
		}
		log.Printf("ERROR: GetUser - storage error getting ID %d: %v", entID, err)
		return nil, status.Errorf(codes.Internal, "failed to get user")
	}

	protoUser := toProtoPlatformUser(entUser)
	if protoUser == nil {
		log.Printf("ERROR: GetUser - failed to convert found user (ID: %d) to proto", entID)
		return nil, status.Errorf(codes.Internal, "failed to process user data")
	}

	return &api.GetPlatformUserResponse{PlatformUser: protoUser}, nil
}

// UpdateUser handles the RPC call to update an existing platform user.
func (s *platformUserService) UpdateUser(ctx context.Context, req *api.UpdatePlatformUserRequest) (*api.UpdatePlatformUserResponse, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID cannot be empty")
	}
	entID, err := strconv.Atoi(req.GetId())
	if err != nil || entID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format (must be positive integer): %s", req.GetId())
	}

	// TODO: Consider using FieldMask for partial updates if API evolves

	updateData := make(map[string]interface{})
	hasUpdate := false
	if dpName := req.GetDisplayName(); dpName != nil {
		// Allow setting empty display name if wrapper is present
		updateData["DisplayName"] = dpName.GetValue()
		hasUpdate = true
	}
	if isActive := req.GetIsActive(); isActive != nil {
		updateData["IsActive"] = isActive.GetValue()
		hasUpdate = true
	}
	// Add LastLogin update possibility? Typically login flow updates this, not manual API.
	// if lastLogin := req.GetLastLogin(); lastLogin != nil { ... }

	if !hasUpdate {
		// Return current user state if no update fields are provided? Or error?
		// Error seems more appropriate for an Update RPC with no updates.
		return nil, status.Errorf(codes.InvalidArgument, "no fields provided for update")
		// Alternative: Fetch and return current user
		// currentUser, err := s.GetUser(ctx, &api.GetPlatformUserRequest{Id: req.GetId()})
		// if err != nil { return nil, err } // Propagate GetUser error
		// return &api.UpdatePlatformUserResponse{PlatformUser: currentUser.PlatformUser}, nil
	}

	updatedEntUser, err := s.storage.UpdateUser(ctx, entID, updateData) // Call interface method
	if err != nil {
		var nfe *db.NotFoundError  // Use generated db type
		var ce *db.ConstraintError // Use generated db type
		var pqErr *pq.Error
		if errors.As(err, &nfe) {
			log.Printf("INFO: UpdateUser - user not found for ID %d", entID)
			return nil, status.Errorf(codes.NotFound, "user with ID '%s' not found", req.GetId())
		} else if errors.As(err, &ce) || (errors.As(err, &pqErr) && pqErr.Code == "23505") {
			// This could happen if trying to update email to a duplicate, if email updates were allowed
			log.Printf("INFO: UpdateUser - constraint violation for user ID %d", entID)
			return nil, status.Errorf(codes.FailedPrecondition, "update resulted in constraint violation") // Or AlreadyExists?
		}
		log.Printf("ERROR: UpdateUser - storage error updating ID %d: %v", entID, err)
		return nil, status.Errorf(codes.Internal, "failed to update user")
	}

	protoUser := toProtoPlatformUser(updatedEntUser)
	if protoUser == nil {
		log.Printf("ERROR: UpdateUser - failed to convert updated user (ID: %d) to proto", entID)
		return nil, status.Errorf(codes.Internal, "failed to process updated user data")
	}

	return &api.UpdatePlatformUserResponse{PlatformUser: protoUser}, nil
}

// DeleteUser handles the RPC call to delete a platform user.
func (s *platformUserService) DeleteUser(ctx context.Context, req *api.DeletePlatformUserRequest) (*emptypb.Empty, error) { // Correct return type
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID cannot be empty")
	}
	entID, err := strconv.Atoi(req.GetId())
	if err != nil || entID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format (must be positive integer): %s", req.GetId())
	}

	err = s.storage.DeleteUserByID(ctx, entID) // Call interface method
	if err != nil {
		var nfe *db.NotFoundError // Use generated db type
		var pqErr *pq.Error
		if errors.As(err, &nfe) {
			log.Printf("INFO: DeleteUser - user not found for ID %d", entID)
			return nil, status.Errorf(codes.NotFound, "user with ID '%s' not found", req.GetId())
		} else if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			// Foreign key violation - e.g., user owns tokens, identities, etc.
			log.Printf("INFO: DeleteUser - cannot delete user ID %d due to foreign key constraint: %v", entID, err)
			return nil, status.Errorf(codes.FailedPrecondition, "cannot delete user, it is referenced by other resources")
		}
		log.Printf("ERROR: DeleteUser - storage error deleting ID %d: %v", entID, err)
		return nil, status.Errorf(codes.Internal, "failed to delete user")
	}

	log.Printf("INFO: Successfully deleted user ID %d", entID)
	return &emptypb.Empty{}, nil // Return empty proto on success
}

// ListUsers handles the RPC call to list platform users with pagination and filtering.
func (s *platformUserService) ListUsers(ctx context.Context, req *api.ListPlatformUsersRequest) (*api.ListPlatformUsersResponse, error) {
	// --- 1. Pagination Setup ---
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
		decodedTime, decodedID, err := decodePageToken(req.GetPageToken())
		if err != nil {
			log.Printf("WARN: ListUsers - invalid page token provided: %v", err)
			// Treat invalid token as starting from the beginning? Or return error?
			// Returning error is safer.
			return nil, status.Errorf(codes.InvalidArgument, "invalid page token: %v", err)
		}
		cursorTime = &decodedTime
		cursorID = &decodedID
	}

	// --- 2. Prepare Filters ---
	// Use the storage filter type directly
	filters := pstorage.UserFilters{}
	if filter := req.GetFilterIsActive(); filter != nil {
		tmpBool := filter.GetValue()
		filters.IsActive = &tmpBool
	}
	if filter := req.GetFilterEmailContains(); filter != "" {
		filters.EmailContains = strings.TrimSpace(filter)
	}

	// --- 3. Get Total Count (Optional, can be expensive) ---
	// Decide if calculating total size is necessary for the API.
	// If not, skip this step and remove TotalSize from response proto.
	// totalSize, err := s.storage.CountUsers(ctx, filters)
	// if err != nil {
	//  log.Printf("ERROR: ListUsers - failed to count users with filters via storage: %v", err)
	//  return nil, status.Errorf(codes.Internal, "failed to count users")
	// }

	// --- 4. Execute Paginated List Query ---
	limit := pageSize + 1 // Fetch one extra
	entUsers, err := s.storage.ListUsersPaginated(ctx, limit, cursorTime, cursorID, filters)
	if err != nil {
		log.Printf("ERROR: ListUsers - failed to list users with pagination/filters via storage: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list users")
	}

	// --- 5. Determine Next Page Token ---
	hasNextPage := false
	if len(entUsers) > pageSize {
		hasNextPage = true
		entUsers = entUsers[:pageSize] // Trim extra item
	}

	nextPageToken := ""
	if hasNextPage && len(entUsers) > 0 {
		lastUser := entUsers[len(entUsers)-1]
		// Need pointer to lastUser for encodePageToken if it takes pointer
		// Assuming encodePageToken takes value:
		encodedToken, errEnc := encodePageToken(*lastUser)
		if errEnc != nil {
			log.Printf("ERROR: ListUsers - failed to encode next page token for user ID %d: %v", lastUser.ID, errEnc)
			// Don't return token if encoding fails
		} else {
			nextPageToken = encodedToken
		}
	}

	// --- 6. Convert Results to Protobuf ---
	protoUsers := make([]*api.PlatformUser, 0, len(entUsers))
	for _, entUser := range entUsers {
		protoUser := toProtoPlatformUser(entUser)
		if protoUser != nil {
			protoUsers = append(protoUsers, protoUser)
		} else {
			log.Printf("WARN: ListUsers - failed to convert listed user (ID: %d) to proto", entUser.ID)
			// Skip user or return internal error? Skipping seems safer.
		}
	}

	// --- 7. Return Response ---
	return &api.ListPlatformUsersResponse{
		Users:         protoUsers,
		NextPageToken: nextPageToken,
		// TotalSize removed to match final proto
		// TotalPages removed to match final proto
	}, nil
}

// --- User Role Assignment RPC Implementations ---

func (s *platformUserService) AssignRoleToUser(ctx context.Context, req *api.AssignRoleToUserRequest) (*api.AssignRoleToUserResponse, error) {
	if req.GetPlatformUserId() == "" || req.GetPlatformAppRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "platform_user_id and platform_app_role_id are required")
	}
	userID, err := strconv.Atoi(req.GetPlatformUserId())
	if err != nil || userID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_user_id format")
	}
	roleID, err := strconv.Atoi(req.GetPlatformAppRoleId())
	if err != nil || roleID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_app_role_id format")
	}

	assignment, err := s.storage.AssignRoleToUser(ctx, userID, roleID)
	if err != nil {
		var constraintErr *db.ConstraintError
		var pqErr *pq.Error
		if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && (pqErr.Code == "23505" || pqErr.Code == "23503")) {
			// 23505 = unique violation (already assigned)
			// 23503 = foreign key violation (user or role doesn't exist)
			log.Printf("INFO: AssignRoleToUser - constraint violation user=%d, role=%d: %v", userID, roleID, err)
			// Provide more specific error based on code?
			if errors.As(err, &pqErr) && pqErr.Code == "23505" {
				return nil, status.Errorf(codes.AlreadyExists, "role %d already assigned to user %d", roleID, userID)
			}
			return nil, status.Errorf(codes.FailedPrecondition, "cannot assign role: user or role not found, or assignment already exists")
		}
		log.Printf("ERROR: AssignRoleToUser - storage error user=%d, role=%d: %v", userID, roleID, err)
		return nil, status.Errorf(codes.Internal, "failed to assign role")
	}

	return &api.AssignRoleToUserResponse{AssignmentId: strconv.Itoa(assignment.ID)}, nil
}

func (s *platformUserService) RemoveRoleFromUser(ctx context.Context, req *api.RemoveRoleFromUserRequest) (*emptypb.Empty, error) {
	if req.GetPlatformUserId() == "" || req.GetPlatformAppRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "platform_user_id and platform_app_role_id are required")
	}
	userID, err := strconv.Atoi(req.GetPlatformUserId())
	if err != nil || userID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_user_id format")
	}
	roleID, err := strconv.Atoi(req.GetPlatformAppRoleId())
	if err != nil || roleID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_app_role_id format")
	}

	err = s.storage.RemoveRoleFromUser(ctx, userID, roleID)
	if err != nil {
		// Check if it's the specific "not found" error returned by the storage layer
		// Assuming storage returns a formatted error string for now
		// TODO: Use structured errors from storage if possible
		if strings.Contains(err.Error(), "not found") {
			log.Printf("INFO: RemoveRoleFromUser - assignment not found user=%d, role=%d", userID, roleID)
			return nil, status.Errorf(codes.NotFound, "role assignment for user %d and role %d not found", userID, roleID)
		}
		log.Printf("ERROR: RemoveRoleFromUser - storage error user=%d, role=%d: %v", userID, roleID, err)
		return nil, status.Errorf(codes.Internal, "failed to remove role assignment")
	}

	return &emptypb.Empty{}, nil
}

func (s *platformUserService) ListUserAssignments(ctx context.Context, req *api.ListUserAssignmentsRequest) (*api.ListUserAssignmentsResponse, error) {
	if req.GetPlatformUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "platform_user_id is required")
	}
	userID, err := strconv.Atoi(req.GetPlatformUserId())
	if err != nil || userID <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid platform_user_id format")
	}

	// Prepare filters for storage layer
	filters := pstorage.AssignmentFilters{} // Use storage filter type
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
	// TODO: Add pagination to storage interface & implementation if needed

	entRoles, err := s.storage.ListUserRoles(ctx, userID, filters)
	if err != nil {
		log.Printf("ERROR: ListUserAssignments - storage error for user=%d: %v", userID, err)
		return nil, status.Errorf(codes.Internal, "failed to list role assignments")
	}

	// Convert Ent roles to Proto roles
	protoRoles := make([]*api.PlatformAppRole, 0, len(entRoles))
	for _, entRole := range entRoles {
		protoRole := toProtoPlatformAppRole(entRole) // Need this helper
		if protoRole != nil {
			protoRoles = append(protoRoles, protoRole)
		} else {
			log.Printf("WARN: ListUserAssignments - failed to convert role (ID: %d) to proto", entRole.ID)
		}
	}

	return &api.ListUserAssignmentsResponse{AssignedRoles: protoRoles}, nil
}

// --- Helper Functions ---

// encodePageToken encodes cursor information into a base64 string.
// Uses CreateTime (nanoseconds) and ID for consistent ordering.
func encodePageToken(user db.PlatformUser) (string, error) { // Changed to value receiver for simplicity
	if user.ID == 0 {
		return "", errors.New("cannot encode cursor for user with zero ID")
	}
	// Ensure CreateTime is not zero before using UnixNano
	if user.CreateTime.IsZero() {
		return "", errors.New("cannot encode cursor for user with zero CreateTime")
	}
	token := fmt.Sprintf("%d_%d", user.CreateTime.UnixNano(), user.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(token)), nil // Use Raw URL encoding
}

// decodePageToken decodes a base64 page token back into time and ID.
func decodePageToken(token string) (cursorTime time.Time, cursorID int, err error) {
	if token == "" {
		err = errors.New("page token is empty")
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token) // Use Raw URL encoding
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
	if err != nil || cursorID <= 0 { // Also validate ID is positive
		err = fmt.Errorf("invalid ID (%s) in page token: %w", parts[1], err)
		return
	}
	cursorTime = time.Unix(0, timeNano).UTC() // Store time as UTC
	return
}

// toProtoPlatformUser converts an Ent *db.PlatformUser to an *api.PlatformUser.
func toProtoPlatformUser(entUser *db.PlatformUser) *api.PlatformUser {
	if entUser == nil {
		return nil
	}
	proto := &api.PlatformUser{
		Id:         strconv.Itoa(entUser.ID),
		Email:      entUser.Email,
		IsActive:   entUser.IsActive,
		CreateTime: timestamppb.New(entUser.CreateTime),
		UpdateTime: timestamppb.New(entUser.UpdateTime),
	}
	if entUser.DisplayName != "" {
		proto.DisplayName = wrapperspb.String(entUser.DisplayName)
	}
	// Handle nillable LastLogin
	if entUser.LastLogin != nil && !entUser.LastLogin.IsZero() {
		proto.LastLogin = timestamppb.New(*entUser.LastLogin)
	}
	return proto
}

// toProtoPlatformAppRole converts an Ent *db.PlatformAppRole to an *api.PlatformAppRole.
func toProtoPlatformAppRole(entRole *db.PlatformAppRole) *api.PlatformAppRole {
	if entRole == nil {
		return nil
	}
	proto := &api.PlatformAppRole{
		Id:         strconv.Itoa(entRole.ID),
		AppId:      entRole.AppID,
		Title:      entRole.Title,
		Weight:     int32(entRole.Weight), // Convert int to int32
		IsActive:   entRole.IsActive,
		CreateTime: timestamppb.New(entRole.CreateTime),
		UpdateTime: timestamppb.New(entRole.UpdateTime),
	}
	// --- CORRECTED HANDLING for *string ---
	if entRole.Description != nil { // Check if pointer is not nil
		proto.Description = wrapperspb.String(*entRole.Description) // Dereference pointer
	}
	// --- END CORRECTION ---
	return proto
}

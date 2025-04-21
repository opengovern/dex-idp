package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log" // Using standard log, replace if Dex has a structured logger available
	"math"
	"strconv"
	"strings"
	"time"

	// Ent imports
	// Needed for ent.Cursor type
	"github.com/dexidp/dex/storage/ent/db" // Generated Ent client package (used as 'db'), defines error types

	// storage "github.com/dexidp/dex/storage" // Not needed directly if using UserStorage interface

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

// --- Interface Definitions ---

// UserFilters defines parameters for filtering user lists.
type UserFilters struct {
	IsActive      *bool // Use pointer to distinguish between not set, true, and false
	EmailContains string
}

// UserStorage defines the database operations required by the PlatformUserService.
// This decouples the service from the concrete Ent client for testing.
type UserStorage interface {
	// Get methods
	GetUserByID(ctx context.Context, id int) (*db.PlatformUser, error)
	// GetUserByEmail(ctx context.Context, email string) (*db.PlatformUser, error) // Add if needed

	// Create method
	CreateUser(ctx context.Context, data *db.PlatformUser) (*db.PlatformUser, error)

	// Update method (Using map for easier mocking, implementation handles parsing)
	UpdateUser(ctx context.Context, id int, updateData map[string]interface{}) (*db.PlatformUser, error)

	// Delete method
	DeleteUserByID(ctx context.Context, id int) error

	// List/Count methods
	CountUsers(ctx context.Context, filters UserFilters) (int, error)
	// Service handles token encoding/decoding, passes cursor object to storage
	ListUsersPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters UserFilters) ([]*db.PlatformUser, error) // <<<< Use *time.Time, *int
}

// --- Service Implementation ---

type platformUserService struct {
	api.UnimplementedPlatformUserServiceServer
	storage UserStorage // Depends on the storage interface
}

// NewPlatformUserService creates a new handler for the PlatformUserService.
// Accepts the UserStorage interface for dependency injection.
func NewPlatformUserService(storage UserStorage) api.PlatformUserServiceServer { // Accept interface
	if storage == nil { // Check the input parameter 'storage'
		log.Fatal("UserStorage cannot be nil for PlatformUserService")
	}
	return &platformUserService{storage: storage} // Assign input 'storage' to struct field 'storage'
}

// CreateUser handles the RPC call to create a new platform user.
func (s *platformUserService) CreateUser(ctx context.Context, req *api.CreatePlatformUserRequest) (*api.CreatePlatformUserResponse, error) {
	trimmedEmail := strings.TrimSpace(req.GetEmail())
	if trimmedEmail == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email cannot be empty")
	}

	userData := &db.PlatformUser{Email: trimmedEmail}
	if dpName := req.GetDisplayName(); dpName != nil {
		userData.DisplayName = dpName.GetValue()
	}

	createdEntUser, err := s.storage.CreateUser(ctx, userData) // Call interface method
	if err != nil {
		var constraintErr *db.ConstraintError // Use generated db type
		var pqErr *pq.Error
		if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && pqErr.Code == "23505") {
			log.Printf("Constraint violation creating user %s: %v", trimmedEmail, err)
			return nil, status.Errorf(codes.AlreadyExists, "user with email '%s' already exists", trimmedEmail)
		}
		log.Printf("Error creating user %s via storage: %v", trimmedEmail, err)
		return nil, status.Errorf(codes.Internal, "failed to create user")
	}

	protoPlatformUser := toProtoPlatformUser(createdEntUser)
	if protoPlatformUser == nil {
		log.Printf("Error converting created user (ID: %d) to proto", createdEntUser.ID)
		return nil, status.Errorf(codes.Internal, "failed to process created user data")
	}

	return &api.CreatePlatformUserResponse{PlatformUser: protoPlatformUser}, nil
}

// GetUser handles the RPC call to retrieve a single platform user by ID.
func (s *platformUserService) GetUser(ctx context.Context, req *api.GetPlatformUserRequest) (*api.GetPlatformUserResponse, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID cannot be empty")
	}
	entID, err := strconv.Atoi(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format: %v", err)
	}

	entUser, err := s.storage.GetUserByID(ctx, entID) // Call interface method
	if err != nil {
		var nfe *db.NotFoundError // Use generated db type
		if errors.As(err, &nfe) {
			log.Printf("User not found for ID %d: %v", entID, err)
			return nil, status.Errorf(codes.NotFound, "user with ID '%s' not found", req.GetId())
		}
		log.Printf("Error getting user ID %d via storage: %v", entID, err)
		return nil, status.Errorf(codes.Internal, "failed to get user")
	}

	protoUser := toProtoPlatformUser(entUser)
	if protoUser == nil {
		log.Printf("Error converting found user (ID: %d) to proto", entID)
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
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format: %v", err)
	}

	updateData := make(map[string]interface{})
	hasUpdate := false
	if dpName := req.GetDisplayName(); dpName != nil {
		updateData["DisplayName"] = dpName.GetValue()
		hasUpdate = true
	}
	if isActive := req.GetIsActive(); isActive != nil {
		updateData["IsActive"] = isActive.GetValue()
		hasUpdate = true
	}
	if !hasUpdate {
		return nil, status.Errorf(codes.InvalidArgument, "no fields provided for update")
	}

	updatedEntUser, err := s.storage.UpdateUser(ctx, entID, updateData) // Call interface method
	if err != nil {
		var nfe *db.NotFoundError  // Use generated db type
		var ce *db.ConstraintError // Use generated db type
		var pqErr *pq.Error
		if errors.As(err, &nfe) {
			log.Printf("User not found for update ID %d: %v", entID, err)
			return nil, status.Errorf(codes.NotFound, "user with ID '%s' not found", req.GetId())
		} else if errors.As(err, &ce) || (errors.As(err, &pqErr) && pqErr.Code == "23505") {
			log.Printf("Constraint violation updating user ID %d: %v", entID, err)
			return nil, status.Errorf(codes.AlreadyExists, "update resulted in constraint violation")
		}
		log.Printf("Error updating user ID %d via storage: %v", entID, err)
		return nil, status.Errorf(codes.Internal, "failed to update user")
	}

	protoUser := toProtoPlatformUser(updatedEntUser)
	if protoUser == nil {
		log.Printf("Error converting updated user (ID: %d) to proto", entID)
		return nil, status.Errorf(codes.Internal, "failed to process updated user data")
	}

	return &api.UpdatePlatformUserResponse{PlatformUser: protoUser}, nil
}

// DeleteUser handles the RPC call to delete a platform user.
func (s *platformUserService) DeleteUser(ctx context.Context, req *api.DeletePlatformUserRequest) (*api.DeletePlatformUserResponse, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID cannot be empty")
	}
	entID, err := strconv.Atoi(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format: %v", err)
	}

	err = s.storage.DeleteUserByID(ctx, entID) // Call interface method
	if err != nil {
		var nfe *db.NotFoundError // Use generated db type
		if errors.As(err, &nfe) {
			log.Printf("User not found for delete ID %d: %v", entID, err)
			return nil, status.Errorf(codes.NotFound, "user with ID '%s' not found", req.GetId())
		}
		log.Printf("Error deleting user ID %d via storage: %v", entID, err)
		return nil, status.Errorf(codes.Internal, "failed to delete user")
	}

	log.Printf("Successfully deleted user ID %d", entID)
	return &api.DeletePlatformUserResponse{Placeholder: &emptypb.Empty{}}, nil
}

// --- Helper Functions ---

func encodePageToken(cursor db.PlatformUser) (string, error) {
	if cursor.ID == 0 {
		return "", errors.New("cannot encode cursor for user with zero ID")
	}
	token := fmt.Sprintf("%d_%d", cursor.CreateTime.UnixNano(), cursor.ID)
	return base64.StdEncoding.EncodeToString([]byte(token)), nil
}

func decodePageToken(token string) (cursorTime time.Time, cursorID int, err error) {
	if token == "" {
		err = errors.New("page token is empty")
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(token)
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
	if err != nil {
		err = fmt.Errorf("invalid ID in page token: %w", err)
		return
	}
	cursorTime = time.Unix(0, timeNano)
	return
}

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
	if entUser.LastLogin != nil {
		proto.LastLogin = timestamppb.New(*entUser.LastLogin)
	}
	return proto
}

// ListUsers handles the RPC call to list platform users with pagination and filtering.
// This version passes decoded cursor values (*time.Time, *int) to the storage layer.
func (s *platformUserService) ListUsers(ctx context.Context, req *api.ListPlatformUsersRequest) (*api.ListPlatformUsersResponse, error) {
	// --- 1. Pagination Setup ---
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}

	// Decode page token into primitive values (time and ID)
	// Use pointers so we know if a cursor was actually provided (nil means first page)
	var cursorTime *time.Time // Pointer for optional time value
	var cursorID *int         // Pointer for optional ID value

	if req.GetPageToken() != "" {
		decodedTime, decodedID, err := decodePageToken(req.GetPageToken()) // Use helper
		if err != nil {
			log.Printf("WARN: ListUsers - invalid page token provided: %v", err)
			return nil, status.Errorf(codes.InvalidArgument, "invalid page token: %v", err)
		}
		// Assign address of decoded values to pointers
		cursorTime = &decodedTime
		cursorID = &decodedID
		// REMOVED: var afterCursor *ent.Cursor and related assignment
	}

	// --- 2. Prepare Filters ---
	filters := UserFilters{} // Assumes UserFilters struct is defined in package server
	if filter := req.GetFilterIsActive(); filter != nil {
		tmpBool := filter.GetValue() // Correctly get value from wrapper
		filters.IsActive = &tmpBool  // Assign pointer
	}
	if filter := req.GetFilterEmailContains(); filter != "" {
		filters.EmailContains = filter
	}

	// --- 3. Get Total Count (Matching Filters) ---
	totalSize, err := s.storage.CountUsers(ctx, filters) // Call storage interface
	if err != nil {
		log.Printf("ERROR: ListUsers - failed to count users with filters via storage: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to count users")
	}

	// --- 4. Execute Paginated List Query ---
	// Fetch one extra item (limit = pageSize + 1) to determine if there's a next page
	limit := pageSize + 1
	// Call storage layer, passing the decoded time/ID pointers (or nil if no token)
	entUsers, err := s.storage.ListUsersPaginated(ctx, limit, cursorTime, cursorID, filters) // <<<< CORRECTED CALL
	if err != nil {
		log.Printf("ERROR: ListUsers - failed to list users with pagination/filters via storage: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list users")
	}

	// --- 5. Determine Next Page Token ---
	hasNextPage := false
	if len(entUsers) > pageSize {
		hasNextPage = true
		entUsers = entUsers[:pageSize] // Trim the extra item used only for the check
	}

	nextPageToken := ""
	if hasNextPage && len(entUsers) > 0 {
		lastUser := entUsers[len(entUsers)-1]
		nextPageToken, err = encodePageToken(*lastUser) // Use helper here
		if err != nil {
			log.Printf("ERROR: ListUsers - failed to encode next page token for user ID %d: %v", lastUser.ID, err)
			nextPageToken = "" // Omit token on encoding error
		}
	}

	// --- 6. Convert Results to Protobuf ---
	protoUsers := make([]*api.PlatformUser, 0, len(entUsers))
	for _, entUser := range entUsers {
		protoUser := toProtoPlatformUser(entUser) // Use the helper
		if protoUser != nil {
			protoUsers = append(protoUsers, protoUser)
		} else {
			log.Printf("ERROR: ListUsers - failed to convert listed user (ID: %d) to proto", entUser.ID)
		}
	}

	// --- 7. Calculate Total Pages ---
	totalPages := int32(0)
	if pageSize > 0 {
		totalPages = int32(math.Ceil(float64(totalSize) / float64(pageSize)))
	}

	// --- 8. Return Response ---
	return &api.ListPlatformUsersResponse{
		Users:         protoUsers,
		NextPageToken: nextPageToken,
		TotalSize:     int32(totalSize),
		TotalPages:    totalPages,
	}, nil
}

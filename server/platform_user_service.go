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
	// Used for error types like *ent.Cursor, potentially NotFoundError check
	"entgo.io/ent/dialect/sql"                          // Needed for sql.OrderDesc/Asc options
	"github.com/dexidp/dex/storage/ent/db"              // Generated Ent client package (used as 'db')
	"github.com/dexidp/dex/storage/ent/db/platformuser" // Generated predicates/constants for PlatformUser

	// gRPC related imports
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb" // For DeletePlatformUser response
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	// Dex specific imports (adjust paths if necessary)
	api "github.com/dexidp/dex/api/v2" // Use 'api' alias matching go_package

	// Postgres driver error handling
	"github.com/lib/pq"
	_ "github.com/lib/pq" // Ensure driver is imported for side effects
)

const (
	// DefaultPageSize is the default number of items per page for List requests.
	DefaultPageSize = 25
	// MaxPageSize is the maximum allowed number of items per page.
	MaxPageSize = 100
)

// platformUserService implements the api.PlatformUserServiceServer interface.
type platformUserService struct {
	// Embed the correct unimplemented server type from the generated code
	api.UnimplementedPlatformUserServiceServer

	// Direct dependency on the Ent client (minimal change approach)
	entClient *db.Client
}

// NewPlatformUserService creates a new handler for the PlatformUserService.
// Accepts the concrete Ent client directly.
func NewPlatformUserService(client *db.Client) api.PlatformUserServiceServer {
	if client == nil {
		// Consider using injected structured logger in production code instead of log.Fatal
		log.Fatal("Ent client cannot be nil for PlatformUserService")
	}
	return &platformUserService{entClient: client}
}

// CreateUser handles the RPC call to create a new platform user.
func (s *platformUserService) CreateUser(ctx context.Context, req *api.CreatePlatformUserRequest) (*api.CreatePlatformUserResponse, error) {
	// --- 1. Validation ---
	trimmedEmail := strings.TrimSpace(req.GetEmail())
	if trimmedEmail == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email cannot be empty")
	}
	// Add more sophisticated email validation if desired

	// --- 2. Prepare Ent Create Operation ---
	createOp := s.entClient.PlatformUser.Create().
		SetEmail(trimmedEmail)

	if dpName := req.GetDisplayName(); dpName != nil {
		createOp.SetDisplayName(dpName.GetValue())
	}
	// Add other optional fields from request here if needed (e.g., initial IsActive status)

	createdEntUser, err := createOp.Save(ctx)

	// --- 3. Error Handling ---
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pq.ErrorCode("23505") { // unique_violation
			log.Printf("Constraint violation creating user %s: %v", trimmedEmail, err)
			return nil, status.Errorf(codes.AlreadyExists, "user with email '%s' already exists", trimmedEmail)
		}
		// Consider checking for other ent validation errors if fields have validators
		log.Printf("Error creating user %s: %v", trimmedEmail, err)
		return nil, status.Errorf(codes.Internal, "failed to create user")
	}

	// --- 4. Convert to Protobuf and Return Response ---
	log.Printf("Successfully created user ID %d with email %s", createdEntUser.ID, createdEntUser.Email)
	protoPlatformUser := toProtoPlatformUser(createdEntUser)
	if protoPlatformUser == nil {
		// This case should ideally not happen if Save() succeeded without error
		log.Printf("Error converting created user (ID: %d) to proto", createdEntUser.ID)
		return nil, status.Errorf(codes.Internal, "failed to process created user data")
	}

	return &api.CreatePlatformUserResponse{PlatformUser: protoPlatformUser}, nil
}

// GetUser handles the RPC call to retrieve a single platform user by ID.
func (s *platformUserService) GetUser(ctx context.Context, req *api.GetPlatformUserRequest) (*api.GetPlatformUserResponse, error) {
	// --- 1. Validation ---
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID cannot be empty")
	}
	entID, err := strconv.Atoi(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format: %v", err)
	}

	// --- 2. Ent Logic ---
	entUser, err := s.entClient.PlatformUser.Get(ctx, entID)

	// --- 3. Error Handling ---
	if err != nil {
		// Use errors.As with the generated error type *db.NotFoundError
		var nfe *db.NotFoundError
		if errors.As(err, &nfe) {
			log.Printf("User not found for ID %d: %v", entID, err)
			return nil, status.Errorf(codes.NotFound, "user with ID '%s' not found", req.GetId())
		}
		// Log other unexpected storage errors
		log.Printf("Error getting user ID %d: %v", entID, err)
		return nil, status.Errorf(codes.Internal, "failed to get user")
	}

	// --- 4. Convert and Respond ---
	protoUser := toProtoPlatformUser(entUser)
	if protoUser == nil {
		log.Printf("Error converting found user (ID: %d) to proto", entID)
		return nil, status.Errorf(codes.Internal, "failed to process user data")
	}

	return &api.GetPlatformUserResponse{PlatformUser: protoUser}, nil
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

	var cursorTime time.Time
	var cursorID int
	useCursor := false
	if req.GetPageToken() != "" {
		var err error
		cursorTime, cursorID, err = decodePageToken(req.GetPageToken())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid page token: %v", err)
		}
		useCursor = true
	}

	// --- 2. Build Query & Apply Filters ---
	query := s.entClient.PlatformUser.Query()

	if filter := req.GetFilterIsActive(); filter != nil {
		query = query.Where(platformuser.IsActiveEQ(filter.GetValue()))
	}
	if filter := req.GetFilterEmailContains(); filter != "" {
		query = query.Where(platformuser.EmailContainsFold(filter)) // Case-insensitive substring
	}

	// --- 3. Get Total Count ---
	totalSize, err := query.Clone().Count(ctx) // Clone to apply filters correctly
	if err != nil {
		log.Printf("Error counting users with filters: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to count users")
	}

	// --- 4. Apply Ordering and Keyset Pagination ---
	// Define a stable order: CreateTime DESC, then ID ASC
	query = query.Order(
		platformuser.ByCreateTime(sql.OrderDesc()), // Use generated func + sql option
		platformuser.ByID(sql.OrderAsc()),          // Use generated func + sql option
	)

	if useCursor {
		// Keyset pagination condition for (CreateTime DESC, ID ASC):
		// (create_time < cursorTime) OR (create_time == cursorTime AND id > cursorID)
		query = query.Where(platformuser.Or(
			platformuser.CreateTimeLT(cursorTime),
			platformuser.And(
				platformuser.CreateTimeEQ(cursorTime),
				platformuser.IDGT(cursorID),
			),
		))
	}

	// --- 5. Execute Paginated Query ---
	entUsers, err := query.Limit(pageSize + 1).All(ctx) // Fetch one extra
	if err != nil {
		log.Printf("Error listing users with pagination/filters: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to list users")
	}

	// --- 6. Determine Next Page Token ---
	hasNextPage := false
	if len(entUsers) > pageSize {
		hasNextPage = true
		entUsers = entUsers[:pageSize] // Trim the extra item
	}

	nextPageToken := ""
	if hasNextPage && len(entUsers) > 0 {
		lastUser := entUsers[len(entUsers)-1]
		nextPageToken, err = encodePageToken(*lastUser)
		if err != nil {
			log.Printf("Error encoding next page token for user ID %d: %v", lastUser.ID, err)
			nextPageToken = "" // Omit token on encoding error
		}
	}

	// --- 7. Convert Results ---
	protoUsers := make([]*api.PlatformUser, 0, len(entUsers))
	for _, u := range entUsers {
		protoUser := toProtoPlatformUser(u)
		if protoUser != nil {
			protoUsers = append(protoUsers, protoUser)
		} else {
			log.Printf("Error converting listed user (ID: %d) to proto", u.ID)
		}
	}

	// --- 8. Calculate Total Pages ---
	totalPages := int32(0)
	if pageSize > 0 {
		totalPages = int32(math.Ceil(float64(totalSize) / float64(pageSize)))
	}

	// --- 9. Return Response ---
	return &api.ListPlatformUsersResponse{
		Users:         protoUsers,
		NextPageToken: nextPageToken,
		TotalSize:     int32(totalSize),
		TotalPages:    totalPages,
	}, nil
}

// UpdateUser handles the RPC call to update an existing platform user.
func (s *platformUserService) UpdateUser(ctx context.Context, req *api.UpdatePlatformUserRequest) (*api.UpdatePlatformUserResponse, error) {
	// --- 1. Validation ---
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID cannot be empty")
	}
	entID, err := strconv.Atoi(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format: %v", err)
	}

	hasUpdate := false
	if req.DisplayName != nil || req.IsActive != nil {
		hasUpdate = true
	}
	if !hasUpdate {
		return nil, status.Errorf(codes.InvalidArgument, "no fields provided for update")
	}

	// --- 2. Prepare and Execute Ent Update ---
	updateOp := s.entClient.PlatformUser.UpdateOneID(entID)

	if dpName := req.GetDisplayName(); dpName != nil {
		updateOp.SetDisplayName(dpName.GetValue())
	}
	if isActive := req.GetIsActive(); isActive != nil {
		updateOp.SetIsActive(isActive.GetValue())
	}
	// Add other updatable fields if defined in request proto

	updatedEntUser, err := updateOp.Save(ctx)

	// --- 3. Error Handling ---
	if err != nil {
		// Use errors.As to check for NotFoundError
		var nfe *db.NotFoundError // Use generated type
		if errors.As(err, &nfe) {
			log.Printf("User not found for update ID %d: %v", entID, err)
			return nil, status.Errorf(codes.NotFound, "user with ID '%s' not found", req.GetId())
		}
		// Check for constraint errors if unique fields were updatable
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pq.ErrorCode("23505") {
			log.Printf("Constraint violation updating user ID %d: %v", entID, err)
			return nil, status.Errorf(codes.AlreadyExists, "update resulted in constraint violation")
		}
		log.Printf("Error updating user ID %d: %v", entID, err)
		return nil, status.Errorf(codes.Internal, "failed to update user")
	}

	// --- 4. Convert and Respond ---
	protoUser := toProtoPlatformUser(updatedEntUser)
	if protoUser == nil {
		log.Printf("Error converting updated user (ID: %d) to proto", entID)
		return nil, status.Errorf(codes.Internal, "failed to process updated user data")
	}

	return &api.UpdatePlatformUserResponse{PlatformUser: protoUser}, nil
}

// DeleteUser handles the RPC call to delete a platform user.
func (s *platformUserService) DeleteUser(ctx context.Context, req *api.DeletePlatformUserRequest) (*api.DeletePlatformUserResponse, error) {
	// --- 1. Validation ---
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID cannot be empty")
	}
	entID, err := strconv.Atoi(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format: %v", err)
	}

	// --- 2. Ent Logic ---
	err = s.entClient.PlatformUser.DeleteOneID(entID).Exec(ctx)

	// --- 3. Error Handling ---
	if err != nil {
		// Use errors.As to check for NotFoundError
		var nfe *db.NotFoundError // Use generated type
		if errors.As(err, &nfe) {
			log.Printf("User not found for delete ID %d: %v", entID, err)
			return nil, status.Errorf(codes.NotFound, "user with ID '%s' not found", req.GetId())
		}
		log.Printf("Error deleting user ID %d: %v", entID, err)
		return nil, status.Errorf(codes.Internal, "failed to delete user")
	}

	// --- 4. Respond ---
	log.Printf("Successfully deleted user ID %d", entID)
	return &api.DeletePlatformUserResponse{Placeholder: &emptypb.Empty{}}, nil
}

// --- Helper Functions ---

// encodePageToken creates an opaque token from the last item's cursor values (CreateTime nanos, ID).
func encodePageToken(cursor db.PlatformUser) (string, error) {
	if cursor.ID == 0 {
		return "", errors.New("cannot encode cursor for user with zero ID")
	}
	token := fmt.Sprintf("%d_%d", cursor.CreateTime.UnixNano(), cursor.ID)
	return base64.StdEncoding.EncodeToString([]byte(token)), nil
}

// decodePageToken parses the opaque token back into cursor values (time, ID).
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

// toProtoPlatformUser converts an Ent *db.PlatformUser to the protobuf *api.PlatformUser message.
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

	// Handle optional fields
	if entUser.DisplayName != "" {
		proto.DisplayName = wrapperspb.String(entUser.DisplayName)
	}
	if entUser.LastLogin != nil { // Check pointer before dereferencing
		proto.LastLogin = timestamppb.New(*entUser.LastLogin)
	}

	return proto
}

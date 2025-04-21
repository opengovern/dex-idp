package server

import (
	"context"
	"errors"
	"log" // Using standard log, replace if Dex has a structured logger available
	"strconv"
	"strings"

	// Needed for IsZero time check
	// gRPC related imports
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	// Dex specific imports (adjust paths if necessary)
	// Use 'api' alias now to match go_package option
	api "github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/storage"        // Needed for constructor parameter
	"github.com/dexidp/dex/storage/ent/db" // Generated Ent client

	// Postgres driver error handling
	"github.com/lib/pq"
	// _ "github.com/lib/pq" // Driver should be imported by the storage setup
)

// platformUserService implements the api.PlatformUserServiceServer interface.
type platformUserService struct {
	// Embed the correct unimplemented server type from the generated code
	api.UnimplementedPlatformUserServiceServer

	// Direct dependency on the Ent client
	entClient *db.Client
}

// Interface used to extract Ent Client from storage.Storage safely.
// The concrete storage implementation (e.g., from storage/sql or storage/ent) must implement this.
type clientProvider interface {
	EntClient() *db.Client
}

// NewPlatformUserService creates a new handler for the PlatformUserService.
// Accepts storage.Storage and extracts the Ent client.
// Returns the correct generated interface type: api.PlatformUserServiceServer.
func NewPlatformUserService(st storage.Storage) api.PlatformUserServiceServer {
	var entClient *db.Client
	// Attempt to get the Ent client using the interface
	if provider, ok := st.(clientProvider); ok {
		entClient = provider.EntClient()
		if entClient == nil {
			log.Fatalf("EntClient() method returned a nil client for PlatformUserService. Storage type: %T", st)
		}
	} else {
		// Fallback or error if the storage type doesn't provide the client
		// Adjust this block if using type assertion instead of an interface method
		log.Fatalf("Ent client could not be obtained from storage for PlatformUserService. Storage type %T does not implement clientProvider interface.", st)
	}

	// Defensive check
	if entClient == nil {
		log.Fatal("Ent client is nil after check for PlatformUserService")
	}

	return &platformUserService{entClient: entClient}
}

// CreateUser handles the RPC call to create a new platform user.
// Uses corrected request/response types from the 'api' package.
func (s *platformUserService) CreateUser(ctx context.Context, req *api.CreateUserRequest) (*api.CreateUserResponse, error) {
	// --- 1. Validation ---
	trimmedEmail := strings.TrimSpace(req.GetEmail())
	if trimmedEmail == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email cannot be empty")
	}

	// --- 2. Prepare and Execute Ent Create Operation ---
	createOp := s.entClient.PlatformUser.Create().
		SetEmail(trimmedEmail)

	if dpName := req.GetDisplayName(); dpName != nil {
		createOp.SetDisplayName(dpName.GetValue())
	}

	createdEntUser, err := createOp.Save(ctx)

	// --- 3. Error Handling ---
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pq.ErrorCode("23505") {
			log.Printf("Constraint violation creating user %s: %v", trimmedEmail, err)
			return nil, status.Errorf(codes.AlreadyExists, "user with email '%s' already exists", trimmedEmail)
		}
		log.Printf("Error creating user %s: %v", trimmedEmail, err)
		return nil, status.Errorf(codes.Internal, "failed to create user")
	}

	// --- 4. Convert to Protobuf and Return Response ---
	log.Printf("Successfully created user ID %d with email %s", createdEntUser.ID, createdEntUser.Email)
	// Call renamed helper function
	protoPlatformUser := toProtoPlatformUser(createdEntUser)
	if protoPlatformUser == nil {
		log.Printf("Error converting created user (ID: %d) to proto", createdEntUser.ID)
		return nil, status.Errorf(codes.Internal, "failed to process created user data")
	}

	// Use corrected response type and field name from proto definition
	return &api.CreateUserResponse{PlatformUser: protoPlatformUser}, nil
}

// GetUser (Stub) - Implement later
// Uses corrected request/response types from the 'api' package.
func (s *platformUserService) GetUser(ctx context.Context, req *api.GetUserRequest) (*api.GetUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUser not implemented")
}

// UpdateUser (Stub) - Implement later
// Uses corrected request/response types from the 'api' package.
func (s *platformUserService) UpdateUser(ctx context.Context, req *api.UpdateUserRequest) (*api.UpdateUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUser not implemented")
}

// DeleteUser (Stub) - Implement later
// Uses corrected request/response types from the 'api' package.
func (s *platformUserService) DeleteUser(ctx context.Context, req *api.DeleteUserRequest) (*api.DeleteUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUser not implemented")
}

// --- Helper Functions ---

// toProtoPlatformUser converts an Ent *db.PlatformUser to the protobuf *api.PlatformUser message.
// Renamed function and updated return type.
func toProtoPlatformUser(entUser *db.PlatformUser) *api.PlatformUser {
	if entUser == nil {
		return nil
	}

	// Use corrected proto message type 'api.PlatformUser'
	proto := &api.PlatformUser{
		Id:         strconv.Itoa(entUser.ID),
		Email:      entUser.Email,
		IsActive:   entUser.IsActive,
		CreateTime: timestamppb.New(entUser.CreateTime), // Use correct field name
		UpdateTime: timestamppb.New(entUser.UpdateTime), // Use correct field name
	}

	// Handle optional fields
	if entUser.DisplayName != "" {
		proto.DisplayName = wrapperspb.String(entUser.DisplayName)
	}
	// Check for zero time before converting optional timestamp
	if !entUser.LastLogin.IsZero() {
		proto.LastLogin = timestamppb.New(entUser.LastLogin)
	}
	if entUser.FirstConnectorID != "" {
		// Use correct proto field name (CamelCase)
		proto.FirstConnectorId = wrapperspb.String(entUser.FirstConnectorID)
	}
	if entUser.FirstFederatedUserID != "" {
		// Use correct proto field name (CamelCase)
		proto.FirstFederatedUserId = wrapperspb.String(entUser.FirstFederatedUserID)
	}

	return proto
}

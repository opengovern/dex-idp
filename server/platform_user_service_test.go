package server_test // Use _test package convention

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"testing"
	"time"

	// Mocking

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	// Testcontainers & DB
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	// Ent & Generated Code
	"entgo.io/ent"
	"github.com/dexidp/dex/storage/ent/db"

	// "github.com/dexidp/dex/storage/ent/db/enttest" // Can use for simpler SQLite tests
	"github.com/lib/pq"
	_ "github.com/lib/pq" // Postgres driver

	// gRPC & Proto
	api "github.com/dexidp/dex/api/v2" // Use 'api' alias
	"github.com/dexidp/dex/server"     // Import your server package
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/wrapperspb"
	// Import specific ent predicate package if needed for mock argument matchers
	// "github.com/dexidp/dex/storage/ent/db/platformuser"
)

// --- Mock Storage for Unit Tests ---
// ###############################################################################
// ## CRITICAL NOTE:                                                            ##
// ## This MockUserStorage struct and the Test..._Unit functions below WILL NOT ##
// ## COMPILE or WORK unless you refactor server/platform_user_service.go       ##
// ## so that platformUserService depends on a `UserStorage` INTERFACE          ##
// ## instead of the concrete `*db.Client`.                                     ##
// ## If you are NOT doing that refactor, DELETE this section and rely on the   ##
// ## Integration Tests further down.                                         ##
// ###############################################################################

// UserStorage interface definition (example - should match your actual interface)
// Place this in the appropriate package (e.g., server or storage) if refactoring.
type UserStorage interface {
	GetUserByID(ctx context.Context, id int) (*db.PlatformUser, error)
	GetUserByEmail(ctx context.Context, email string) (*db.PlatformUser, error)
	CreateUser(ctx context.Context, user *db.PlatformUser) (*db.PlatformUser, error)
	// Use simplified Update signature for easier mocking if needed
	UpdateUser(ctx context.Context, id int, updateData map[string]interface{}) (*db.PlatformUser, error)
	DeleteUserByID(ctx context.Context, id int) error
	CountUsers(ctx context.Context, filters UserFilters) (int, error)
	ListUsersPaginated(ctx context.Context, cursor *ent.Cursor, limit int, filters UserFilters) ([]*db.PlatformUser, error)
}

// UserFilters definition (example - should match your actual definition)
// Place this in the appropriate package (e.g., server).
type UserFilters struct {
	IsActive      *bool
	EmailContains string
}

// MockUserStorage is a mock implementation of the UserStorage interface.
type MockUserStorage struct {
	mock.Mock
	UserStorage // Embed the interface
}

// Implement methods needed for mocking
func (m *MockUserStorage) GetUserByID(ctx context.Context, id int) (*db.PlatformUser, error) {
	args := m.Called(ctx, id)
	if user := args.Get(0); user != nil {
		return user.(*db.PlatformUser), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockUserStorage) GetUserByEmail(ctx context.Context, email string) (*db.PlatformUser, error) {
	args := m.Called(ctx, email)
	if user := args.Get(0); user != nil {
		return user.(*db.PlatformUser), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockUserStorage) CreateUser(ctx context.Context, user *db.PlatformUser) (*db.PlatformUser, error) {
	args := m.Called(ctx, user)
	if created := args.Get(0); created != nil {
		return created.(*db.PlatformUser), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockUserStorage) UpdateUser(ctx context.Context, id int, updateData map[string]interface{}) (*db.PlatformUser, error) {
	args := m.Called(ctx, id, updateData)
	if updated := args.Get(0); updated != nil {
		return updated.(*db.PlatformUser), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockUserStorage) DeleteUserByID(ctx context.Context, id int) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockUserStorage) CountUsers(ctx context.Context, filters UserFilters) (int, error) {
	args := m.Called(ctx, filters)
	return args.Int(0), args.Error(1)
}
func (m *MockUserStorage) ListUsersPaginated(ctx context.Context, cursor *ent.Cursor, limit int, filters UserFilters) ([]*db.PlatformUser, error) {
	args := m.Called(ctx, cursor, limit, filters)
	if users := args.Get(0); users != nil {
		return users.([]*db.PlatformUser), args.Error(1)
	}
	return nil, args.Error(1)
}

// --- Unit Tests ---
// NOTE: These tests depend on the service refactor mentioned above.

// Helper function to create service with mock for unit tests
// Returns nil if service cannot be instantiated (e.g., due to missing interface)
func newTestServiceWithMock(storageMock server.UserStorage) api.PlatformUserServiceServer {
	// This relies on NewPlatformUserService accepting the interface.
	// If it still takes *db.Client, this setup needs adjustment or skipping.
	// For now, assume it takes the interface for the mock tests.
	// You might need a type assertion if the constructor returns the concrete type.
	// return server.NewPlatformUserService(storageMock).(api.PlatformUserServiceServer)

	// Let's return nil to force skipping if not refactored. Replace with above line after refactor.
	return nil
}

func TestCreateUser_Unit(t *testing.T) {
	mockStorage := new(MockUserStorage)
	service := newTestServiceWithMock(mockStorage)
	if service == nil {
		t.Skip("Skipping unit tests: Service requires refactoring for UserStorage interface")
	}

	ctx := context.Background()
	validEmail := "test@example.com"
	displayName := "Test User"
	validRequest := &api.CreatePlatformUserRequest{
		Email:       validEmail,
		DisplayName: wrapperspb.String(displayName),
	}
	// Use mock.AnythingOfType or a more specific matcher if needed
	expectedEntUserMatcher := mock.AnythingOfType("*db.PlatformUser")
	createdUser := &db.PlatformUser{ID: 1, Email: validEmail, DisplayName: displayName, IsActive: true, CreateTime: time.Now(), UpdateTime: time.Now()}

	t.Run("Success", func(t *testing.T) {
		mockStorage.On("CreateUser", ctx, expectedEntUserMatcher).Return(createdUser, nil).Once()
		resp, err := service.CreateUser(ctx, validRequest)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.PlatformUser)
		require.Equal(t, "1", resp.PlatformUser.Id)
		require.Equal(t, validEmail, resp.PlatformUser.Email)
		mockStorage.AssertExpectations(t)
	})

	t.Run("InvalidInput_EmptyEmail", func(t *testing.T) {
		req := &api.CreatePlatformUserRequest{Email: ""}
		resp, err := service.CreateUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.InvalidArgument, st.Code())
		mockStorage.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})

	t.Run("StorageError_AlreadyExists", func(t *testing.T) {
		// Simulate a constraint error satisfying errors.As(err, &pqErr)
		// Note: Creating actual pq.Error might be complex, often mocking specific error check is easier.
		// Let's assume the service maps constraint errors to codes.AlreadyExists correctly.
		// Here we return a generic error that the service logic should map.
		// A better mock would return an error that satisfies the errors.As check if possible.
		constraintErr := &pq.Error{Code: "23505"} // Simulate pq error
		mockStorage.On("CreateUser", ctx, expectedEntUserMatcher).Return(nil, constraintErr).Once()
		resp, err := service.CreateUser(ctx, validRequest)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.AlreadyExists, st.Code()) // Check if service maps correctly
		mockStorage.AssertExpectations(t)
	})

	t.Run("StorageError_Internal", func(t *testing.T) {
		internalErr := errors.New("db down")
		mockStorage.On("CreateUser", ctx, expectedEntUserMatcher).Return(nil, internalErr).Once()
		resp, err := service.CreateUser(ctx, validRequest)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.Internal, st.Code())
		mockStorage.AssertExpectations(t)
	})
}

func TestGetUser_Unit(t *testing.T) {
	mockStorage := new(MockUserStorage)
	service := newTestServiceWithMock(mockStorage)
	if service == nil {
		t.Skip("Skipping unit tests: Service requires refactoring for UserStorage interface")
	}

	ctx := context.Background()
	userID := 123
	userIDStr := "123"
	foundUser := &db.PlatformUser{ID: userID, Email: "get@example.com", IsActive: true, CreateTime: time.Now(), UpdateTime: time.Now()}

	t.Run("Success", func(t *testing.T) {
		mockStorage.On("GetUserByID", ctx, userID).Return(foundUser, nil).Once()
		req := &api.GetPlatformUserRequest{Id: userIDStr}
		resp, err := service.GetUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.PlatformUser)
		require.Equal(t, userIDStr, resp.PlatformUser.Id)
		require.Equal(t, foundUser.Email, resp.PlatformUser.Email)
		mockStorage.AssertExpectations(t)
	})

	t.Run("NotFound", func(t *testing.T) {
		mockStorage.On("GetUserByID", ctx, userID).Return(nil, &ent.NotFoundError{}).Once()
		req := &api.GetPlatformUserRequest{Id: userIDStr}
		resp, err := service.GetUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.NotFound, st.Code())
		mockStorage.AssertExpectations(t)
	})

	t.Run("InvalidID", func(t *testing.T) {
		req := &api.GetPlatformUserRequest{Id: "not-a-number"}
		resp, err := service.GetUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.InvalidArgument, st.Code())
		mockStorage.AssertNotCalled(t, "GetUserByID", mock.Anything, mock.Anything)
	})

	t.Run("StorageError_Internal", func(t *testing.T) {
		internalErr := errors.New("db down")
		mockStorage.On("GetUserByID", ctx, userID).Return(nil, internalErr).Once()
		req := &api.GetPlatformUserRequest{Id: userIDStr}
		resp, err := service.GetUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.Internal, st.Code())
		mockStorage.AssertExpectations(t)
	})
}

func TestListUsers_Unit(t *testing.T) {
	mockStorage := new(MockUserStorage)
	service := newTestServiceWithMock(mockStorage)
	if service == nil {
		t.Skip("Skipping unit tests: Service requires refactoring for UserStorage interface")
	}

	ctx := context.Background()
	pageSize := int(server.DefaultPageSize) // Use exported constant
	limitCheck := pageSize + 1
	filters := server.UserFilters{} // Empty filters for basic list

	usersPage1 := []*db.PlatformUser{
		{ID: 1, Email: "user1@example.com", CreateTime: time.Now().Add(-1 * time.Hour)},
		{ID: 2, Email: "user2@example.com", CreateTime: time.Now().Add(-2 * time.Hour)},
	}

	t.Run("Success_FirstPage", func(t *testing.T) {
		mockStorage.On("CountUsers", ctx, filters).Return(len(usersPage1), nil).Once()
		// Mock ListUsersPaginated - cursor is nil for first page
		mockStorage.On("ListUsersPaginated", ctx, (*ent.Cursor)(nil), limitCheck, filters).Return(usersPage1, nil).Once()

		req := &api.ListPlatformUsersRequest{PageSize: int32(pageSize)}
		resp, err := service.ListUsers(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.Users, len(usersPage1))
		require.EqualValues(t, len(usersPage1), resp.TotalSize)
		require.EqualValues(t, 1, resp.TotalPages) // Only one page expected
		require.Empty(t, resp.NextPageToken)       // No next page
		mockStorage.AssertExpectations(t)
	})

	// TODO: Add more ListUsers unit tests:
	// - Requesting second page (mock needs to handle cursor arg, return different user set)
	// - Applying filters (check filters arg passed to mock, mock returns filtered count/users)
	// - Empty results
	// - Errors from CountUsers or ListUsersPaginated
}

func TestUpdateUser_Unit(t *testing.T) {
	mockStorage := new(MockUserStorage)
	service := newTestServiceWithMock(mockStorage)
	if service == nil {
		t.Skip("Skipping unit tests: Service requires refactoring for UserStorage interface")
	}

	ctx := context.Background()
	userID := 456
	userIDStr := "456"
	newName := "Updated Name Unit"
	newActive := false
	updateMap := map[string]interface{}{"DisplayName": newName, "IsActive": newActive} // Simplified map for mock matching
	updatedUser := &db.PlatformUser{ID: userID, Email: "update@example.com", DisplayName: newName, IsActive: newActive, CreateTime: time.Now(), UpdateTime: time.Now()}

	t.Run("Success", func(t *testing.T) {
		// Use mock.AnythingOfType for the func arg or refine UpdateUser mock signature
		mockStorage.On("UpdateUser", ctx, userID, mock.AnythingOfType("map[string]interface {}")).Return(updatedUser, nil).Once()

		req := &api.UpdatePlatformUserRequest{
			Id:          userIDStr,
			DisplayName: wrapperspb.String(newName),
			IsActive:    wrapperspb.Bool(newActive),
		}
		resp, err := service.UpdateUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.PlatformUser)
		require.Equal(t, newName, resp.PlatformUser.DisplayName.GetValue())
		require.Equal(t, newActive, resp.PlatformUser.IsActive)
		mockStorage.AssertExpectations(t)
	})

	// TODO: Add more UpdateUser unit tests:
	// - Not found
	// - Invalid ID
	// - No update fields provided
	// - Internal storage error
}

func TestDeleteUser_Unit(t *testing.T) {
	mockStorage := new(MockUserStorage)
	service := newTestServiceWithMock(mockStorage)
	if service == nil {
		t.Skip("Skipping unit tests: Service requires refactoring for UserStorage interface")
	}

	ctx := context.Background()
	userID := 789
	userIDStr := "789"

	t.Run("Success", func(t *testing.T) {
		mockStorage.On("DeleteUserByID", ctx, userID).Return(nil).Once()
		req := &api.DeletePlatformUserRequest{Id: userIDStr}
		resp, err := service.DeleteUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Placeholder) // Check for empty proto
		mockStorage.AssertExpectations(t)
	})

	// TODO: Add more DeleteUser unit tests:
	// - Not found
	// - Invalid ID
	// - Internal storage error
}

// --- Integration Tests Setup ---

const integrationBufSize = 1024 * 1024

var integrationLis *bufconn.Listener

func setupTestPostgresIntegration(t *testing.T) (*db.Client, func()) {
	ctx := context.Background()
	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(1*time.Minute),
		),
	)
	require.NoError(t, err, "Integration: Failed to start postgres container")

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "Integration: Failed to get connection string")

	client, err := db.Open("postgres", dsn)
	require.NoError(t, err, "Integration: Failed to connect to test postgres with ent client")
	require.NotNil(t, client, "Integration: Ent client should not be nil")

	migrateCtx, migrateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer migrateCancel()
	err = client.Schema.Create(migrateCtx)
	require.NoError(t, err, "Integration: Failed to run ent migrations")

	cleanup := func() {
		if errC := client.Close(); errC != nil {
			t.Logf("Integration WARN: Failed to close ent client: %v", errC)
		}
		if errT := pgContainer.Terminate(ctx); errT != nil {
			t.Logf("Integration WARN: Failed to terminate postgres container: %v", errT)
		}
	}
	return client, cleanup
}

func startTestGrpcServerIntegration(t *testing.T, client *db.Client) (*grpc.Server, func()) {
	integrationLis = bufconn.Listen(integrationBufSize)
	srv := grpc.NewServer()
	platformUserSvc := server.NewPlatformUserService(client)    // Use direct constructor
	api.RegisterPlatformUserServiceServer(srv, platformUserSvc) // Use correct name
	go func() {
		if err := srv.Serve(integrationLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Fatalf("Integration Server exited with error: %v", err)
		}
	}()
	cleanup := func() {
		srv.GracefulStop()
		integrationLis.Close()
	}
	return srv, cleanup
}

func integrationBufDialer(context.Context, string) (net.Conn, error) {
	return integrationLis.Dial()
}

// --- Integration Tests ---

func TestPlatformUserService_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	entClient, dbCleanup := setupTestPostgresIntegration(t)
	defer dbCleanup()

	_, serverCleanup := startTestGrpcServerIntegration(t, entClient)
	defer serverCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(integrationBufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "Integration: Failed to dial bufnet")
	defer conn.Close()

	userClient := api.NewPlatformUserServiceClient(conn)

	var createdUserID string
	var createdUserEmail = "integ-main@example.com"

	t.Run("Integration_CreateUserSuccess", func(t *testing.T) {
		req := &api.CreatePlatformUserRequest{
			Email:       createdUserEmail,
			DisplayName: wrapperspb.String("Integ Main User"),
		}
		resp, err := userClient.CreateUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.PlatformUser)
		createdUserID = resp.PlatformUser.Id
		require.NotEmpty(t, createdUserID)
		require.Equal(t, req.Email, resp.PlatformUser.Email)
		require.Equal(t, req.DisplayName.GetValue(), resp.PlatformUser.DisplayName.GetValue())
		require.True(t, resp.PlatformUser.IsActive)
		t.Logf("Integration: Created user ID %s", createdUserID)
	})

	t.Run("Integration_CreateUserDuplicate", func(t *testing.T) {
		require.NotEmpty(t, createdUserID)
		req := &api.CreatePlatformUserRequest{Email: createdUserEmail}
		resp, err := userClient.CreateUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.AlreadyExists, st.Code())
	})

	t.Run("Integration_GetUserSuccess", func(t *testing.T) {
		require.NotEmpty(t, createdUserID)
		req := &api.GetPlatformUserRequest{Id: createdUserID}
		resp, err := userClient.GetUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.PlatformUser)
		require.Equal(t, createdUserID, resp.PlatformUser.Id)
		require.Equal(t, createdUserEmail, resp.PlatformUser.Email)
		require.Equal(t, "Integ Main User", resp.PlatformUser.DisplayName.GetValue())
	})

	t.Run("Integration_GetUserNotFound", func(t *testing.T) {
		req := &api.GetPlatformUserRequest{Id: "9999999"}
		resp, err := userClient.GetUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("Integration_ListUsersPaginatedAndFiltered", func(t *testing.T) {
		// Setup: Create more users
		prefix := "integ-list-"
		count := 30
		var createdListUserIDs []string
		for i := 1; i <= count; i++ {
			resp, err := userClient.CreateUser(ctx, &api.CreatePlatformUserRequest{
				Email:    fmt.Sprintf("%s%d@example.com", prefix, i),
				IsActive: wrapperspb.Bool(i%2 == 0), // Alternate active status
			})
			require.NoError(t, err, "Failed to create user for list test %d", i)
			createdListUserIDs = append(createdListUserIDs, resp.PlatformUser.Id)
		}
		t.Cleanup(func() {
			for _, idStr := range createdListUserIDs {
				_, _ = userClient.DeleteUser(context.Background(), &api.DeletePlatformUserRequest{Id: idStr})
			}
		})

		// Test 1: First page, size 10
		pageSize1 := int32(10)
		listReq1 := &api.ListPlatformUsersRequest{PageSize: pageSize1}
		listResp1, err := userClient.ListUsers(ctx, listReq1)
		require.NoError(t, err)
		require.NotNil(t, listResp1)
		require.Len(t, listResp1.Users, 10)
		require.NotEmpty(t, listResp1.NextPageToken)
		require.EqualValues(t, count+1, listResp1.TotalSize)
		require.EqualValues(t, int(math.Ceil(float64(count+1)/float64(pageSize1))), listResp1.TotalPages)
		firstPageLastUser := listResp1.Users[9]

		// Test 2: Second page, size 10
		listReq2 := &api.ListPlatformUsersRequest{PageSize: pageSize1, PageToken: listResp1.NextPageToken}
		listResp2, err := userClient.ListUsers(ctx, listReq2)
		require.NoError(t, err)
		require.NotNil(t, listResp2)
		require.Len(t, listResp2.Users, 10)
		require.NotEmpty(t, listResp2.NextPageToken)
		require.EqualValues(t, count+1, listResp2.TotalSize)
		// Check sorting - user on page 2 should be created earlier (or same time + higher ID) than last user on page 1
		require.True(t, listResp2.Users[0].CreateTime.AsTime().Before(firstPageLastUser.CreateTime.AsTime()) ||
			(listResp2.Users[0].CreateTime.AsTime().Equal(firstPageLastUser.CreateTime.AsTime()) && listResp2.Users[0].Id > firstPageLastUser.Id),
			"Page 2 results should come after Page 1 based on CreateTime DESC, ID ASC order")

		// Test 3: Filter active users (page 1)
		activeFilter := wrapperspb.Bool(true)
		listReqActive := &api.ListPlatformUsersRequest{FilterIsActive: activeFilter}
		listRespActive, err := userClient.ListUsers(ctx, listReqActive)
		require.NoError(t, err)
		expectedActive := (count / 2) + 1 // Half of list users + the initial one
		require.EqualValues(t, expectedActive, listRespActive.TotalSize)
		require.True(t, len(listRespActive.Users) > 0)
		for _, u := range listRespActive.Users {
			require.True(t, u.IsActive)
		}

		// Test 4: Filter email contains
		emailFilter := "list-1" // Should match list-1, list-10..list-19 -> 11 users
		listReqEmail := &api.ListPlatformUsersRequest{FilterEmailContains: emailFilter}
		listRespEmail, err := userClient.ListUsers(ctx, listReqEmail)
		require.NoError(t, err)
		require.EqualValues(t, 11, listRespEmail.TotalSize)
		if len(listRespEmail.Users) < 11 {
			require.NotEmpty(t, listRespEmail.NextPageToken)
		}
		for _, u := range listRespEmail.Users {
			require.Contains(t, u.Email, emailFilter)
		}
	})

	t.Run("Integration_UpdateUser", func(t *testing.T) {
		require.NotEmpty(t, createdUserID)
		newName := "Main User Updated"
		newActive := false
		req := &api.UpdatePlatformUserRequest{
			Id:          createdUserID,
			DisplayName: wrapperspb.String(newName),
			IsActive:    wrapperspb.Bool(newActive),
		}
		updateResp, err := userClient.UpdateUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, updateResp.PlatformUser)
		require.Equal(t, newName, updateResp.PlatformUser.DisplayName.GetValue())
		require.Equal(t, newActive, updateResp.PlatformUser.IsActive)

		// Verify with Get
		getResp, err := userClient.GetUser(ctx, &api.GetPlatformUserRequest{Id: createdUserID})
		require.NoError(t, err)
		require.Equal(t, newName, getResp.PlatformUser.DisplayName.GetValue())
		require.Equal(t, newActive, getResp.PlatformUser.IsActive)
	})

	t.Run("Integration_UpdateUserNotFound", func(t *testing.T) {
		req := &api.UpdatePlatformUserRequest{
			Id:       "9999999",
			IsActive: wrapperspb.Bool(false),
		}
		resp, err := userClient.UpdateUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("Integration_DeleteUserSuccess", func(t *testing.T) {
		// Recreate user to ensure it exists before delete test
		createResp, err := userClient.CreateUser(ctx, &api.CreatePlatformUserRequest{Email: "delete-me-integ@example.com"})
		require.NoError(t, err)
		deleteID := createResp.PlatformUser.Id

		req := &api.DeletePlatformUserRequest{Id: deleteID}
		delResp, err := userClient.DeleteUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, delResp)
		require.NotNil(t, delResp.Placeholder)

		// Verify with Get
		getResp, err := userClient.GetUser(ctx, &api.GetPlatformUserRequest{Id: deleteID})
		require.Error(t, err)
		require.Nil(t, getResp)
		st := status.Convert(err)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("Integration_DeleteUserNotFound", func(t *testing.T) {
		req := &api.DeletePlatformUserRequest{Id: "9999999"}
		delResp, err := userClient.DeleteUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, delResp)
		st := status.Convert(err)
		require.Equal(t, codes.NotFound, st.Code())
	})
}

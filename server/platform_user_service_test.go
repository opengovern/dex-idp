package server_test // Use _test package convention

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	// Test Requirements
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Testcontainers & DB
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	// Ent & Generated Code
	// Still potentially needed for error checking
	"github.com/dexidp/dex/storage/ent/db" // Generated client types, error types
	_ "github.com/lib/pq"                  // Postgres driver for side effects

	// gRPC & Proto
	api "github.com/dexidp/dex/api/v2" // Use 'api' alias
	"github.com/dexidp/dex/server"     // Import your server package
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn" // For Delete Response check
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// --- Integration Tests Setup ---

const integrationBufSize = 1024 * 1024

var integrationLis *bufconn.Listener // Global listener for integration tests

// setupTestPostgresIntegration starts postgres, runs migrations, returns client and cleanup func.
func setupTestPostgresIntegration(t *testing.T) (*db.Client, func()) {
	t.Helper()
	ctx := context.Background()
	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2*time.Minute), // Slightly longer timeout
		),
	)
	require.NoError(t, err, "Integration: Failed to start postgres container")

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "Integration: Failed to get connection string")

	// Use regular Open for integration tests
	client, err := db.Open("postgres", dsn)
	require.NoError(t, err, "Integration: Failed to connect to test postgres with ent client")
	require.NotNil(t, client, "Integration: Ent client should not be nil")

	// Run migrations explicitly
	migrateCtx, migrateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer migrateCancel()
	// Use Create for a fresh schema in tests
	err = client.Schema.Create(migrateCtx)
	require.NoError(t, err, "Integration: Failed to run ent migrations")

	cleanup := func() {
		fmt.Println("Cleaning up Postgres test container (integration test)...")
		if errC := client.Close(); errC != nil {
			t.Logf("Integration WARN: Failed to close ent client: %v", errC)
		}
		termCtx, termCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer termCancel()
		if errT := pgContainer.Terminate(termCtx); errT != nil {
			t.Logf("Integration WARN: Failed to terminate postgres container: %v", errT)
		}
		fmt.Println("Cleanup complete (integration test).")
	}
	return client, cleanup
}

// startTestGrpcServerIntegration starts the gRPC server on the bufconn listener.
func startTestGrpcServerIntegration(t *testing.T, client *db.Client) (*grpc.Server, func()) {
	t.Helper()
	integrationLis = bufconn.Listen(integrationBufSize)
	srv := grpc.NewServer()

	// Instantiate the real service implementation directly with the client
	platformUserSvc := server.NewPlatformUserService(client)

	// Register the service using the final correct name
	api.RegisterPlatformUserServiceServer(srv, platformUserSvc)

	go func() {
		if err := srv.Serve(integrationLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			// Use t.Errorf for test logging, log.Fatalf exits test prematurely
			t.Errorf("Integration Server exited with error: %v", err)
		}
	}()

	cleanup := func() {
		srv.GracefulStop()
		integrationLis.Close()
	}
	return srv, cleanup
}

// integrationBufDialer provides the dialer for the bufconn client.
func integrationBufDialer(context.Context, string) (net.Conn, error) {
	return integrationLis.Dial()
}

// --- Integration Tests ---

// TestPlatformUserService_Integration runs integration tests against a real Postgres DB via gRPC.
// Add //go:build integration build tag at top of file if running separately is desired.
func TestPlatformUserService_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	// Add Docker check here if desired to provide a clearer skip message

	entClient, dbCleanup := setupTestPostgresIntegration(t)
	defer dbCleanup() // Ensure DB container is terminated

	_, serverCleanup := startTestGrpcServerIntegration(t, entClient)
	defer serverCleanup() // Ensure gRPC server is stopped

	// Setup: Create gRPC client connection to buffer
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second) // Timeout for test setup/calls
	defer cancel()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(integrationBufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "Integration: Failed to dial bufnet")
	defer conn.Close()

	// Create client stub for the service
	userClient := api.NewPlatformUserServiceClient(conn)

	// --- Test Cases ---
	var createdUserID string // Store ID for subsequent tests
	var createdUserEmail = "integ-main@example.com"

	t.Run("Integration_CreateUserSuccess", func(t *testing.T) {
		req := &api.CreatePlatformUserRequest{ // Use correct type
			Email:       createdUserEmail,
			DisplayName: wrapperspb.String("Integ Main User"),
		}
		resp, err := userClient.CreateUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.PlatformUser)
		createdUserID = resp.PlatformUser.Id
		require.NotEmpty(t, createdUserID)
		assert.Equal(t, req.Email, resp.PlatformUser.Email)
		assert.Equal(t, req.DisplayName.GetValue(), resp.PlatformUser.DisplayName.GetValue())
		assert.True(t, resp.PlatformUser.IsActive)
		assert.NotNil(t, resp.PlatformUser.CreateTime)
		assert.NotNil(t, resp.PlatformUser.UpdateTime)
		t.Logf("Integration: Created user ID %s", createdUserID)
	})

	t.Run("Integration_CreateUserDuplicate", func(t *testing.T) {
		require.NotEmpty(t, createdUserID, "Cannot run duplicate test without successful creation first")
		req := &api.CreatePlatformUserRequest{Email: createdUserEmail} // Use correct type
		resp, err := userClient.CreateUser(ctx, req)
		require.Error(t, err, "Should get error for duplicate email")
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.AlreadyExists, st.Code())
	})

	t.Run("Integration_GetUserSuccess", func(t *testing.T) {
		require.NotEmpty(t, createdUserID, "Cannot run get test without successful creation first")
		req := &api.GetPlatformUserRequest{Id: createdUserID} // Use correct type
		resp, err := userClient.GetUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.PlatformUser)
		assert.Equal(t, createdUserID, resp.PlatformUser.Id)
		assert.Equal(t, createdUserEmail, resp.PlatformUser.Email)
		assert.Equal(t, "Integ Main User", resp.PlatformUser.DisplayName.GetValue())
	})

	t.Run("Integration_GetUserNotFound", func(t *testing.T) {
		req := &api.GetPlatformUserRequest{Id: "9999999"} // Use correct type
		resp, err := userClient.GetUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, resp)
		st := status.Convert(err)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("Integration_ListUsersPaginatedAndFiltered", func(t *testing.T) {
		// Setup: Create more users for list tests
		prefix := "integ-list-"
		count := 30 // Create 30 additional users
		var createdListUserIDs []string
		initialUserCount := 1 // Account for the user created earlier

		for i := 1; i <= count; i++ {
			resp, err := userClient.CreateUser(ctx, &api.CreatePlatformUserRequest{ // Use correct type
				Email:       fmt.Sprintf("%s%d@example.com", prefix, i),
				DisplayName: wrapperspb.String(fmt.Sprintf("List User %d", i)),
				// IsActive field removed from request
			})
			// Update some users to be inactive for filter test
			if i%3 == 0 { // Make every 3rd user inactive
				_, updateErr := userClient.UpdateUser(ctx, &api.UpdatePlatformUserRequest{
					Id:       resp.PlatformUser.Id,
					IsActive: wrapperspb.Bool(false),
				})
				require.NoError(t, updateErr, "Failed to update user active status for list test %d", i)
			}
			require.NoError(t, err, "Failed to create user for list test %d", i)
			createdListUserIDs = append(createdListUserIDs, resp.PlatformUser.Id)
		}
		// Ensure cleanup happens for users created in this subtest
		t.Cleanup(func() {
			cleanupCtx := context.Background() // Use background context for cleanup
			for _, idStr := range createdListUserIDs {
				_, _ = userClient.DeleteUser(cleanupCtx, &api.DeletePlatformUserRequest{Id: idStr}) // Ignore cleanup errors
			}
			t.Logf("Cleaned up %d list test users", len(createdListUserIDs))
		})

		// Test 1: First page, size 10
		pageSize1 := int32(10)
		listReq1 := &api.ListPlatformUsersRequest{PageSize: pageSize1} // Use correct type
		listResp1, err := userClient.ListUsers(ctx, listReq1)
		require.NoError(t, err)
		require.NotNil(t, listResp1)
		assert.Len(t, listResp1.Users, 10, "Page 1 should have 10 users")
		assert.NotEmpty(t, listResp1.NextPageToken, "Page 1 should have next page token")
		expectedTotal := initialUserCount + count
		assert.EqualValues(t, expectedTotal, listResp1.TotalSize, "Total size mismatch")
		assert.EqualValues(t, int(math.Ceil(float64(expectedTotal)/float64(pageSize1))), listResp1.TotalPages, "Total pages mismatch")
		firstPageLastUser := listResp1.Users[9] // Keep track of last user for ordering check

		// Test 2: Second page, size 10
		listReq2 := &api.ListPlatformUsersRequest{PageSize: pageSize1, PageToken: listResp1.NextPageToken} // Use correct type
		listResp2, err := userClient.ListUsers(ctx, listReq2)
		require.NoError(t, err)
		require.NotNil(t, listResp2)
		assert.Len(t, listResp2.Users, 10, "Page 2 should have 10 users")
		assert.NotEmpty(t, listResp2.NextPageToken, "Page 2 should have next page token")
		assert.EqualValues(t, expectedTotal, listResp2.TotalSize)
		// Check sort order (CreateTime DESC, ID ASC)
		assert.True(t, listResp2.Users[0].CreateTime.AsTime().Before(firstPageLastUser.CreateTime.AsTime()) ||
			(listResp2.Users[0].CreateTime.AsTime().Equal(firstPageLastUser.CreateTime.AsTime()) && listResp2.Users[0].Id > firstPageLastUser.Id),
			"Page 2 ordering check failed")

		// Test 3: Last page (size 10, should have remaining users)
		listReq3 := &api.ListPlatformUsersRequest{PageSize: pageSize1, PageToken: listResp2.NextPageToken} // Use correct type
		listResp3, err := userClient.ListUsers(ctx, listReq3)
		require.NoError(t, err)
		require.NotNil(t, listResp3)
		expectedLastPageSize := expectedTotal % int(pageSize1)
		if expectedLastPageSize == 0 {
			expectedLastPageSize = int(pageSize1)
		} // Handle exact multiple
		assert.Len(t, listResp3.Users, expectedLastPageSize, "Last page size mismatch")
		assert.Empty(t, listResp3.NextPageToken, "Last page should have no next page token")
		assert.EqualValues(t, expectedTotal, listResp3.TotalSize)

		// Test 4: Filter active=true users
		activeFilter := wrapperspb.Bool(true)
		listReqActive := &api.ListPlatformUsersRequest{FilterIsActive: activeFilter} // Use correct type
		listRespActive, err := userClient.ListUsers(ctx, listReqActive)
		require.NoError(t, err)
		require.NotNil(t, listRespActive)
		// Calculate expected active count: initial user (active) + 2/3 of created users
		expectedActiveCount := initialUserCount + (count - (count / 3))
		assert.EqualValues(t, expectedActiveCount, listRespActive.TotalSize, "Total active count mismatch")
		require.True(t, len(listRespActive.Users) > 0, "Should find active users")
		for _, u := range listRespActive.Users {
			assert.True(t, u.IsActive, "Filtered user should be active")
		}

		// Test 5: Filter active=false users
		inactiveFilter := wrapperspb.Bool(false)
		listReqInactive := &api.ListPlatformUsersRequest{FilterIsActive: inactiveFilter} // Use correct type
		listRespInactive, err := userClient.ListUsers(ctx, listReqInactive)
		require.NoError(t, err)
		require.NotNil(t, listRespInactive)
		expectedInactiveCount := count / 3 // Only created users could be inactive
		assert.EqualValues(t, expectedInactiveCount, listRespInactive.TotalSize, "Total inactive count mismatch")
		if listRespInactive.TotalSize > 0 {
			require.True(t, len(listRespInactive.Users) > 0, "Should find inactive users")
			for _, u := range listRespInactive.Users {
				assert.False(t, u.IsActive, "Filtered user should be inactive")
			}
		}

		// Test 6: Filter email contains
		emailFilter := "list-1"                                                         // Should match list-1, list-10..list-19 -> 11 users
		listReqEmail := &api.ListPlatformUsersRequest{FilterEmailContains: emailFilter} // Use correct type
		listRespEmail, err := userClient.ListUsers(ctx, listReqEmail)
		require.NoError(t, err)
		require.EqualValues(t, 11, listRespEmail.TotalSize)
		if len(listRespEmail.Users) < 11 {
			require.NotEmpty(t, listRespEmail.NextPageToken)
		}
		for _, u := range listRespEmail.Users {
			assert.Contains(t, u.Email, emailFilter)
		}
	})

	t.Run("Integration_UpdateUser", func(t *testing.T) {
		require.NotEmpty(t, createdUserID, "Update test needs user ID")
		newName := "Main User Updated"
		newActive := false
		req := &api.UpdatePlatformUserRequest{ // Use correct type
			Id:          createdUserID,
			DisplayName: wrapperspb.String(newName),
			IsActive:    wrapperspb.Bool(newActive),
		}
		updateResp, err := userClient.UpdateUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, updateResp)
		require.NotNil(t, updateResp.PlatformUser)
		assert.Equal(t, newName, updateResp.PlatformUser.DisplayName.GetValue())
		assert.Equal(t, newActive, updateResp.PlatformUser.IsActive)

		// Verify with Get
		getResp, err := userClient.GetUser(ctx, &api.GetPlatformUserRequest{Id: createdUserID}) // Use correct type
		require.NoError(t, err)
		require.NotNil(t, getResp.PlatformUser)
		assert.Equal(t, newName, getResp.PlatformUser.DisplayName.GetValue())
		assert.Equal(t, newActive, getResp.PlatformUser.IsActive)
	})

	t.Run("Integration_UpdateUserNotFound", func(t *testing.T) {
		req := &api.UpdatePlatformUserRequest{ // Use correct type
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
		require.NotNil(t, createResp.PlatformUser)
		deleteID := createResp.PlatformUser.Id

		req := &api.DeletePlatformUserRequest{Id: deleteID} // Use correct type
		delResp, err := userClient.DeleteUser(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, delResp)
		require.NotNil(t, delResp.Placeholder) // Check for empty proto

		// Verify with Get
		getResp, err := userClient.GetUser(ctx, &api.GetPlatformUserRequest{Id: deleteID}) // Use correct type
		require.Error(t, err)
		require.Nil(t, getResp)
		st := status.Convert(err)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("Integration_DeleteUserNotFound", func(t *testing.T) {
		req := &api.DeletePlatformUserRequest{Id: "9999999"} // Use correct type
		delResp, err := userClient.DeleteUser(ctx, req)
		require.Error(t, err)
		require.Nil(t, delResp)
		st := status.Convert(err)
		require.Equal(t, codes.NotFound, st.Code())
	})
}

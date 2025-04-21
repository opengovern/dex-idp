package sql_test // Use '_test' suffix for package name

import (
	"context"
	"errors" // Import errors package
	"fmt"
	"testing"
	"time" // Needed for context timeouts

	// Import testify/require for robust assertions
	"github.com/stretchr/testify/require"

	// Import testcontainers-go for managing Docker containers
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	// Import the generated Ent client for your project
	"github.com/dexidp/dex/storage/ent/db"              // Adjust import path if your Ent 'db' dir is elsewhere
	"github.com/dexidp/dex/storage/ent/db/platformuser" // Import for predicates/constants

	// Postgres driver and error types
	"github.com/lib/pq"   // Import pq for error checking
	_ "github.com/lib/pq" // Import Postgres driver (needed by Ent)
	// Or use pgx: _ "github.com/jackc/pgx/v5/stdlib"
	// NOTE: Removed unused import: ent "entgo.io/ent"
)

// setupTestPostgres spins up a postgres container, runs migrations, and returns a connected Ent client.
// It also returns a cleanup function to terminate the container and close the client.
func setupTestPostgres(t *testing.T) (*db.Client, func()) {
	ctx := context.Background()

	// Define Postgres container request
	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(1*time.Minute),
		),
	)
	require.NoError(t, err, "Failed to start postgres container")
	require.NotNil(t, pgContainer, "Postgres container should not be nil")

	// Get connection string (DSN)
	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "Failed to get connection string")

	// Open Ent client connection
	client, err := db.Open("postgres", dsn)
	require.NoError(t, err, "Failed to connect to test postgres with ent client")
	require.NotNil(t, client, "Ent client should not be nil")

	// Run migrations
	migrateCtx, migrateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer migrateCancel()
	err = client.Schema.Create(migrateCtx)
	require.NoError(t, err, "Failed to run ent migrations")

	// Define cleanup function
	cleanup := func() {
		fmt.Println("Cleaning up Postgres test container...")
		if err := client.Close(); err != nil {
			t.Errorf("Failed to close ent client: %v", err)
		}
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Errorf("Failed to terminate postgres container: %v", err)
		}
		fmt.Println("Cleanup complete.")
	}

	return client, cleanup
}

// TestPlatformUserEntStorage performs end-to-end tests for PlatformUser storage via Ent.
func TestPlatformUserEntStorage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping docker dependent test in short mode")
	}

	client, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	// --- Test Case 1: Successful Creation ---
	t.Run("CreateUserSuccess", func(t *testing.T) {
		email1 := "test.user1@example.com"
		displayName1 := "Test User One"

		createdUser, err := client.PlatformUser.Create().
			SetEmail(email1).
			SetDisplayName(displayName1).
			Save(ctx)

		require.NoError(t, err, "Failed to create user")
		require.NotNil(t, createdUser)
		require.NotEmpty(t, createdUser.ID, "Created user should have an ID")
		require.Equal(t, email1, createdUser.Email)
		require.Equal(t, displayName1, createdUser.DisplayName)
		require.True(t, createdUser.IsActive, "User should be active by default")
		// --- CORRECTION: Use CreateTime / UpdateTime ---
		require.NotZero(t, createdUser.CreateTime, "CreateTime should be set")
		require.NotZero(t, createdUser.UpdateTime, "UpdateTime should be set")
		// --- END CORRECTION ---
		require.Zero(t, createdUser.LastLogin)
		require.Empty(t, createdUser.FirstConnectorID)
		require.Empty(t, createdUser.FirstFederatedUserID)
	})

	// --- Test Case 2: Unique Email Constraint Violation ---
	t.Run("CreateUserDuplicateEmail", func(t *testing.T) {
		emailDuplicate := "duplicate.user@example.com"
		_, err := client.PlatformUser.Create().
			SetEmail(emailDuplicate).
			SetDisplayName("First Duplicate").
			Save(ctx)
		require.NoError(t, err, "Setup: Failed to create initial user for duplicate test")

		_, err = client.PlatformUser.Create().
			SetEmail(emailDuplicate).
			SetDisplayName("Second Duplicate").
			Save(ctx)

		require.Error(t, err, "Should fail to create user with duplicate email")
		// --- CORRECTION: Check for pq specific constraint error ---
		var pqErr *pq.Error
		isPqErr := errors.As(err, &pqErr)
		require.True(t, isPqErr, "Error should be a pq.Error for constraint violation")
		require.NotNil(t, pqErr, "pqErr should not be nil")
		require.Equal(t, pq.ErrorCode("23505"), pqErr.Code, "Error code should be 23505 (unique_violation)")
		// --- END CORRECTION ---
	})

	// --- Test Case 3: Creation with Optional Fields ---
	t.Run("CreateUserOptionalFields", func(t *testing.T) {
		email3 := "test.user3@example.com"
		connectorID := "conn-google"
		fedUserID := "1234567890"
		lastLoginTime := time.Now().Truncate(time.Second)

		createdUser, err := client.PlatformUser.Create().
			SetEmail(email3).
			SetFirstConnectorID(connectorID).
			SetFirstFederatedUserID(fedUserID).
			SetLastLogin(lastLoginTime).
			SetIsActive(false).
			Save(ctx)

		require.NoError(t, err, "Failed to create user with optional fields")
		require.NotNil(t, createdUser)
		require.Equal(t, email3, createdUser.Email)
		require.False(t, createdUser.IsActive, "User should be inactive")
		require.Equal(t, connectorID, createdUser.FirstConnectorID)
		require.Equal(t, fedUserID, createdUser.FirstFederatedUserID)
		require.WithinDuration(t, lastLoginTime, createdUser.LastLogin, time.Second, "LastLogin time mismatch")
		require.Empty(t, createdUser.DisplayName)
	})

	// --- Test Case 4: Querying User ---
	t.Run("QueryUser", func(t *testing.T) {
		email4 := "test.user4@example.com"
		displayName4 := "Query Me"
		initialUser, err := client.PlatformUser.Create().
			SetEmail(email4).
			SetDisplayName(displayName4).
			Save(ctx)
		require.NoError(t, err, "Setup: Failed to create user for query test")

		queriedUser, err := client.PlatformUser.Query().
			Where(platformuser.EmailEQ(email4)).
			Only(ctx)

		require.NoError(t, err, "Failed to query user by email")
		require.NotNil(t, queriedUser)
		require.Equal(t, initialUser.ID, queriedUser.ID)
		require.Equal(t, initialUser.Email, queriedUser.Email)
		require.Equal(t, initialUser.DisplayName, queriedUser.DisplayName)
		require.Equal(t, initialUser.IsActive, queriedUser.IsActive)
		// --- CORRECTION: Use CreateTime ---
		require.Equal(t, initialUser.CreateTime.Unix(), queriedUser.CreateTime.Unix()) // Compare Unix timestamp
		// --- END CORRECTION ---
	})

	// Add more test cases as needed (e.g., Update, Delete, specific queries)
}

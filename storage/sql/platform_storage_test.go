// storage/sql/platform_storage_test.go
package sql_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	// Test Requirements
	"github.com/stretchr/testify/require"

	// Testcontainers & DB
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	// Ent & Generated Code
	"github.com/dexidp/dex/storage/ent/db" // Use 'db' alias

	// Import sub-packages for predicates/field constants & edges
	"github.com/dexidp/dex/storage/ent/db/platformapprole"
	"github.com/dexidp/dex/storage/ent/db/platformfederatedidentity"
	"github.com/dexidp/dex/storage/ent/db/platformtoken"
	"github.com/dexidp/dex/storage/ent/db/platformuser"

	// Postgres driver and error types
	"github.com/lib/pq"
	_ "github.com/lib/pq" // Postgres driver for Ent

	// Import the package under test
	platformsql "github.com/dexidp/dex/storage/sql"
)

// setupTestPostgres starts a postgres container, runs migrations, and returns a connected Ent client.
// It also returns a cleanup function to terminate the container and close the client.
func setupTestPostgres(t *testing.T) (*db.Client, func()) {
	ctx := context.Background()
	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(1*time.Minute),
		),
		//testcontainers.WithRyuk(), // Enable Ryuk if needed for resource cleanup
	)
	require.NoError(t, err, "Failed to start postgres container")
	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "Failed to get connection string")
	client, err := db.Open("postgres", dsn)
	require.NoError(t, err, "Failed to connect to test postgres with ent client")
	require.NotNil(t, client, "Ent client should not be nil")
	migrateCtx, migrateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer migrateCancel()
	// Use Create instead of Migrate for tests usually, ensures clean state.
	// Use Migrate().Create() if you need schema diffing features during tests.
	err = client.Schema.Create(migrateCtx)
	require.NoError(t, err, "Failed to run ent migrations")
	cleanup := func() {
		fmt.Println("Cleaning up Postgres test container (storage test)...")
		if errC := client.Close(); errC != nil {
			t.Logf("WARN: Failed to close ent client: %v", errC)
		}
		termCtx, termCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer termCancel()
		if errT := pgContainer.Terminate(termCtx); errT != nil {
			t.Logf("WARN: Failed to terminate postgres container: %v", errT)
		}
		fmt.Println("Cleanup complete (storage test).")
	}
	return client, cleanup
}

// isPqConstraintError checks if an error is a specific pq constraint error.
func isPqConstraintError(err error, code pq.ErrorCode) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == code
}

// TestPlatformStorageEnt runs storage-level tests for all custom platform entities.
func TestPlatformStorageEnt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping docker dependent test in short mode")
	}

	client, cleanup := setupTestPostgres(t)
	defer cleanup()

	// Instantiate the storage implementation using the test client
	storage := platformsql.NewEntStorage(client)
	require.NotNil(t, storage, "Storage implementation should not be nil")

	ctx := context.Background()

	// Define variables in the outer scope to share between sub-tests if needed
	var testUser1 *db.PlatformUser
	var testRole1 *db.PlatformAppRole
	var testRoleNew *db.PlatformAppRole // For token role update test

	t.Run("PlatformUser_CRUD", func(t *testing.T) {
		email1 := "user1-storage@example.com"
		email2 := "user2-storage@example.com"
		displayName := "Test User 1 Storage"
		var err error

		// Create Success
		testUser1, err = client.PlatformUser.Create().
			SetEmail(email1).
			SetDisplayName(displayName).
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testUser1)
		require.Equal(t, email1, testUser1.Email)
		require.True(t, testUser1.IsActive) // Default
		require.Nil(t, testUser1.LastLogin) // Default is nil pointer

		// Create Duplicate Email
		_, err = client.PlatformUser.Create().SetEmail(email1).Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"), "Expected unique constraint violation")

		// Get Found
		fetchedU1, err := client.PlatformUser.Get(ctx, testUser1.ID)
		require.NoError(t, err)
		require.Equal(t, testUser1.ID, fetchedU1.ID)

		// Get Not Found
		_, err = client.PlatformUser.Get(ctx, 999999)
		require.Error(t, err)
		var nfe *db.NotFoundError
		require.True(t, errors.As(err, &nfe), "Error should be *db.NotFoundError")

		// Update using map through the storage implementation
		newDisplayName := "Updated Name Storage"
		now := time.Now().UTC().Truncate(time.Microsecond) // Ensure UTC and truncate for DB comparison
		updateMap := map[string]interface{}{
			"DisplayName": newDisplayName,
			"IsActive":    false,
			"LastLogin":   now, // Pass time.Time value
		}
		updatedU1, err := storage.UpdateUser(ctx, testUser1.ID, updateMap)
		require.NoError(t, err)
		require.Equal(t, newDisplayName, updatedU1.DisplayName)
		require.False(t, updatedU1.IsActive)
		require.NotNil(t, updatedU1.LastLogin)
		require.WithinDuration(t, now, *updatedU1.LastLogin, time.Second) // Compare truncated times
		require.True(t, updatedU1.UpdateTime.After(testUser1.UpdateTime))

		// List (Basic) - Using client directly for simple queries
		testUser2, err := client.PlatformUser.Create().SetEmail(email2).SetIsActive(false).Save(ctx)
		require.NoError(t, err)
		activeUsers, err := client.PlatformUser.Query().Where(platformuser.IsActiveEQ(true)).All(ctx)
		require.NoError(t, err)
		require.Empty(t, activeUsers) // u1 updated to inactive
		inactiveUsers, err := client.PlatformUser.Query().Where(platformuser.IsActiveEQ(false)).All(ctx)
		require.NoError(t, err)
		require.Len(t, inactiveUsers, 2) // u1 and u2

		// Delete (Leave user1 for FK tests) - Using client directly
		err = client.PlatformUser.DeleteOneID(testUser2.ID).Exec(ctx)
		require.NoError(t, err)
		_, err = client.PlatformUser.Get(ctx, testUser2.ID)
		require.Error(t, err)
		require.True(t, errors.As(err, &nfe), "Error after delete should be *db.NotFoundError")
	})

	t.Run("PlatformAppRole_CRUD", func(t *testing.T) {
		appID1 := "app-storage-1"
		appID2 := "app-storage-2"
		titleAdmin := "admin-storage"
		var err error
		var testRole2 *db.PlatformAppRole // Define locally if only needed here

		// Create Success
		testRole1, err = client.PlatformAppRole.Create(). // Assign to outer scope variable
									SetAppID(appID1).
									SetTitle(titleAdmin).
									SetDescription("App1 Admin Role Storage").
									Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testRole1)
		require.Equal(t, appID1, testRole1.AppID)

		// Create Duplicate (same app_id, same title)
		_, err = client.PlatformAppRole.Create().SetAppID(appID1).SetTitle(titleAdmin).Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"), "Expected unique constraint violation")

		// Create OK (different app_id, same title)
		testRole2, err = client.PlatformAppRole.Create().SetAppID(appID2).SetTitle(titleAdmin).Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testRole2)

		// Create Role for Token Update Test
		testRoleNew, err = client.PlatformAppRole.Create().SetAppID(appID1).SetTitle("new-role-storage").Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testRoleNew)

		// Get
		fetchedRole, err := client.PlatformAppRole.Get(ctx, testRole1.ID)
		require.NoError(t, err)
		require.Equal(t, testRole1.Title, fetchedRole.Title)

		// Update - using storage implementation
		updateMap := map[string]interface{}{
			"IsActive": false,
			"Weight":   10,
		}
		updatedRole, err := storage.UpdateAppRole(ctx, fetchedRole.ID, updateMap)
		require.NoError(t, err)
		require.False(t, updatedRole.IsActive)
		require.Equal(t, 10, updatedRole.Weight)

		// List by App ID - Using client directly
		roles, err := client.PlatformAppRole.Query().Where(platformapprole.AppIDEQ(appID1)).All(ctx)
		require.NoError(t, err)
		// Should have 2 roles now: testRole1 and testRoleNew
		require.Len(t, roles, 2)

		// Delete (leave role1 and roleNew for later FK tests) - Using client directly
		err = client.PlatformAppRole.DeleteOneID(testRole2.ID).Exec(ctx)
		require.NoError(t, err)
	})

	t.Run("PlatformToken_CRUD_FK_UpdateRole", func(t *testing.T) {
		require.NotNil(t, testUser1, "Token test needs user1 from outer scope")
		require.NotNil(t, testRole1, "Token test needs role1 from outer scope")
		require.NotNil(t, testRoleNew, "Token test needs roleNew from outer scope") // Need the new role

		publicID1 := "pub_abc123_storage"
		publicID2 := "pub_def456_storage"
		hash1 := "$argon2id$v=19$m=65536,t=3,p=2$U0FMVFNUT1JBR0U=$SEFTSEFCR0VORVJBVElPTg==" // Example valid format hash
		var err error
		var testToken1 *db.PlatformToken

		// Create Success (with expiry) - using client directly
		expiryTime := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Microsecond)
		testToken1, err = client.PlatformToken.Create().
			SetPublicID(publicID1).
			SetSecretHash(hash1).
			SetOwner(testUser1). // Use SetOwner
			SetRole(testRole1).  // Use edge setter
			SetExpiresAt(expiryTime).
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testToken1)
		require.NotNil(t, testToken1.ExpiresAt)                                   // Check pointer not nil
		require.WithinDuration(t, expiryTime, *testToken1.ExpiresAt, time.Second) // Check value

		// Create Success (no expiry) - using client directly
		testToken2, err := client.PlatformToken.Create().
			SetPublicID(publicID2).
			SetSecretHash(hash1).
			SetOwner(testUser1). // Use SetOwner
			SetRole(testRole1).
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testToken2)
		require.Nil(t, testToken2.ExpiresAt, "Token created without expiry should have nil ExpiresAt field")

		// Create Duplicate Public ID - using client directly
		_, err = client.PlatformToken.Create().
			SetPublicID(publicID1).SetSecretHash("newhash").SetOwner(testUser1).SetRole(testRole1).
			Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"), "Expected unique constraint violation")

		// Query by Public ID, eager load edges - using client directly
		fetchedToken1, err := client.PlatformToken.Query().
			Where(platformtoken.PublicIDEQ(publicID1)).
			WithOwner(). // Eager load owner
			WithRole().  // Eager load role
			Only(ctx)
		require.NoError(t, err)
		require.Equal(t, testToken1.ID, fetchedToken1.ID)
		require.NotNil(t, fetchedToken1.Edges.Owner)
		require.NotNil(t, fetchedToken1.Edges.Role)
		require.Equal(t, testUser1.ID, fetchedToken1.Edges.Owner.ID)
		require.Equal(t, testRole1.ID, fetchedToken1.Edges.Role.ID)
		require.Equal(t, testRole1.AppID, fetchedToken1.Edges.Role.AppID)
		require.Equal(t, testRole1.Title, fetchedToken1.Edges.Role.Title)

		// --- Test Update Role using Storage Implementation ---
		updatedTokenRole, err := storage.UpdateTokenRole(ctx, fetchedToken1.ID, testRoleNew.ID)
		require.NoError(t, err)
		require.NotNil(t, updatedTokenRole)
		// Verify the returned token has the new role ID (Edges should be loaded by GetTokenByID inside UpdateTokenRole)
		require.NotNil(t, updatedTokenRole.Edges.Role, "Role edge should be loaded after update")
		require.Equal(t, testRoleNew.ID, updatedTokenRole.Edges.Role.ID, "Token role ID should be updated")
		require.Equal(t, testRoleNew.Title, updatedTokenRole.Edges.Role.Title, "Token role title should reflect the new role")
		// Verify other fields didn't change unexpectedly (check one)
		require.Equal(t, fetchedToken1.Edges.Owner.ID, updatedTokenRole.Edges.Owner.ID) // Owner should be same

		// --- Test FK Constraints ---
		// Test FK Constraint (Role Deletion - RESTRICT)
		// Try deleting the *new* role that a token points to
		err = client.PlatformAppRole.DeleteOneID(testRoleNew.ID).Exec(ctx)
		require.Error(t, err, "Should not be able to delete role referenced by token")
		require.True(t, isPqConstraintError(err, "23503"), "Expected foreign key violation")

		// Delete tokens first (using client directly for simplicity here)
		// Delete token pointing to testRoleNew
		err = client.PlatformToken.DeleteOneID(updatedTokenRole.ID).Exec(ctx)
		require.NoError(t, err)
		// Delete token pointing to testRole1
		err = client.PlatformToken.DeleteOneID(testToken2.ID).Exec(ctx)
		require.NoError(t, err)

		// Now try deleting roles again
		err = client.PlatformAppRole.DeleteOneID(testRole1.ID).Exec(ctx)
		require.NoError(t, err, "Should succeed deleting role1 now")
		err = client.PlatformAppRole.DeleteOneID(testRoleNew.ID).Exec(ctx)
		require.NoError(t, err, "Should succeed deleting roleNew now")

		// Test FK Constraint (User Deletion - ON DELETE behavior depends on schema - Assume RESTRICT or SET NULL)
		// Recreate role and token with user testUser1
		testRole1, err = client.PlatformAppRole.Create().SetAppID(testRole1.AppID).SetTitle(testRole1.Title).Save(ctx) // Recreate role
		require.NoError(t, err)
		testToken1, err = client.PlatformToken.Create().
			SetPublicID(publicID1).SetSecretHash(hash1).SetOwner(testUser1).SetRole(testRole1).
			Save(ctx) // Recreate token
		require.NoError(t, err)

		// Verify initial Owner edge
		require.Equal(t, testUser1.ID, testToken1.QueryOwner().OnlyIDX(ctx)) // Check FK initially set

		// Delete the user
		err = client.PlatformUser.DeleteOneID(testUser1.ID).Exec(ctx)

		// Check outcome based on FK constraint (typically RESTRICT or SET NULL for required FK)
		// If RESTRICT: Deletion should fail
		// If SET NULL: Deletion succeeds, token's owner_id becomes NULL
		// Ent default for Required edge is RESTRICT. If you changed it to Optional() + SET NULL:
		if err == nil { // Assumes SET NULL or CASCADE (less likely for user)
			t.Log("User deletion succeeded, checking token owner edge (expecting nil if SET NULL)")
			refetchedToken, errGet := client.PlatformToken.Query().
				Where(platformtoken.IDEQ(testToken1.ID)).
				WithOwner(). // Attempt to load owner
				Only(ctx)
			require.NoError(t, errGet)
			require.Nil(t, refetchedToken.Edges.Owner, "Owner edge should be nil after user deletion (if SET NULL)")
		} else { // Assumes RESTRICT (Ent default for Required edge)
			t.Logf("User deletion failed as expected (RESTRICT): %v", err)
			require.Error(t, err, "User deletion should fail due to token FK constraint (RESTRICT)")
			require.True(t, isPqConstraintError(err, "23503"), "Expected foreign key violation on user delete")
			// Cleanup token before test ends if user delete failed
			_ = client.PlatformToken.DeleteOneID(testToken1.ID).Exec(ctx)
		}
	})

	t.Run("PlatformFederatedIdentity_CRUD_FK", func(t *testing.T) {
		fedUser, err := client.PlatformUser.Create().SetEmail("fed-user@example.com").Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, fedUser)

		connID1 := "google-fed"
		fedSubject1 := "google-sub-fed-111" // Changed name
		connID2 := "ldap-fed"
		var testFedId1, testFedId2 *db.PlatformFederatedIdentity

		// Create Success
		testFedId1, err = client.PlatformFederatedIdentity.Create().
			SetUser(fedUser).
			SetConnectorID(connID1).
			SetConnectorSubject(fedSubject1). // Use SetConnectorSubject
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testFedId1)

		// Create Duplicate (same connector_id, same connector_subject)
		_, err = client.PlatformFederatedIdentity.Create().
			SetUser(fedUser).
			SetConnectorID(connID1).
			SetConnectorSubject(fedSubject1). // Use SetConnectorSubject
			Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"), "Expected unique constraint violation")

		// Create OK (same user, different connector)
		testFedId2, err = client.PlatformFederatedIdentity.Create().
			SetUser(fedUser).
			SetConnectorID(connID2).
			SetConnectorSubject("ldap-user-fed-111"). // Use SetConnectorSubject
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testFedId2)

		// List by User
		identities, err := client.PlatformFederatedIdentity.Query().
			Where(platformfederatedidentity.HasUserWith(platformuser.IDEQ(fedUser.ID))).
			All(ctx)
		require.NoError(t, err)
		require.Len(t, identities, 2)

		// Delete one
		err = client.PlatformFederatedIdentity.DeleteOneID(testFedId1.ID).Exec(ctx)
		require.NoError(t, err)

		// Test FK Cascade (Delete User) - Assuming ON DELETE CASCADE was set on schema edge 'user'
		err = client.PlatformUser.DeleteOneID(fedUser.ID).Exec(ctx)
		require.NoError(t, err)

		// Verify federated identity was deleted
		_, err = client.PlatformFederatedIdentity.Get(ctx, testFedId2.ID)
		require.Error(t, err)
		var nfe *db.NotFoundError
		require.True(t, errors.As(err, &nfe), "Federated identity should be cascade deleted")
	})

	t.Run("AssignmentTables", func(t *testing.T) {
		// Setup fresh user, role, identity for isolated assignment tests
		assignUser, _ := client.PlatformUser.Create().SetEmail("assign-user@example.com").Save(ctx)
		assignRole, _ := client.PlatformAppRole.Create().SetAppID("assign-app").SetTitle("assign-role").Save(ctx)                                                    // Use unique title
		assignFedId, _ := client.PlatformFederatedIdentity.Create().SetUser(assignUser).SetConnectorID("assign-conn").SetConnectorSubject("assign-fed-id").Save(ctx) // Use SetConnectorSubject

		t.Run("UserRoleAssignment", func(t *testing.T) {
			assign1, err := client.PlatformUserRoleAssignment.Create().
				SetUser(assignUser).SetRole(assignRole).
				Save(ctx)
			require.NoError(t, err)
			require.True(t, assign1.IsActive)

			// Test duplicate assignment
			_, err = client.PlatformUserRoleAssignment.Create().SetUserID(assignUser.ID).SetRoleID(assignRole.ID).Save(ctx)
			require.Error(t, err)
			require.True(t, isPqConstraintError(err, "23505"), "Expected unique constraint violation")

			// Test update (e.g., deactivate)
			updatedAssign1, err := assign1.Update().SetIsActive(false).Save(ctx)
			require.NoError(t, err)
			require.False(t, updatedAssign1.IsActive)

			// Test delete
			err = client.PlatformUserRoleAssignment.DeleteOneID(assign1.ID).Exec(ctx)
			require.NoError(t, err)
		})

		t.Run("IdentityRoleAssignment", func(t *testing.T) {
			assign2, err := client.PlatformIdentityRoleAssignment.Create().
				SetIdentity(assignFedId).SetRole(assignRole).
				Save(ctx)
			require.NoError(t, err)
			require.True(t, assign2.IsActive)

			// Test duplicate assignment
			_, err = client.PlatformIdentityRoleAssignment.Create().SetIdentityID(assignFedId.ID).SetRoleID(assignRole.ID).Save(ctx)
			require.Error(t, err)
			require.True(t, isPqConstraintError(err, "23505"), "Expected unique constraint violation")

			// Test update
			updatedAssign2, err := assign2.Update().SetIsActive(false).Save(ctx)
			require.NoError(t, err)
			require.False(t, updatedAssign2.IsActive)

			// Test delete
			err = client.PlatformIdentityRoleAssignment.DeleteOneID(assign2.ID).Exec(ctx)
			require.NoError(t, err)
		})

		// Test Token Role Assignment (Implicit via FK on Token) is now covered
		// by the UpdateTokenRole test within PlatformToken_CRUD_FK_UpdateRole
	})
} // End TestPlatformStorageEnt

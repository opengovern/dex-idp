package sql_test // Testing code in the storage/sql package directory

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
	"entgo.io/ent"
	"github.com/dexidp/dex/storage/ent/db" // Adjust import path if needed

	// Import sub-packages for predicates/field constants
	"github.com/dexidp/dex/storage/ent/db/platformapprole"
	"github.com/dexidp/dex/storage/ent/db/platformfederatedidentity" // Import for query traversal if needed later
	"github.com/dexidp/dex/storage/ent/db/platformtoken"
	"github.com/dexidp/dex/storage/ent/db/platformuser"

	// Import for query traversal if needed later
	// Postgres driver and error types
	"github.com/lib/pq"
	_ "github.com/lib/pq" // Postgres driver for Ent
)

// setupTestPostgres starts a postgres container, runs migrations, and returns a connected Ent client.
// It also returns a cleanup function to terminate the container and close the client.
func setupTestPostgres(t *testing.T) (*db.Client, func()) {
	ctx := context.Background()

	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2). // Wait for initialization to complete
				WithStartupTimeout(1*time.Minute),
		),
	)
	require.NoError(t, err, "Failed to start postgres container")

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "Failed to get connection string")

	// Use db.Open directly for explicit migration control in storage tests
	client, err := db.Open("postgres", dsn)
	require.NoError(t, err, "Failed to connect to test postgres with ent client")
	require.NotNil(t, client, "Ent client should not be nil")

	// Run migrations explicitly to set up the schema
	migrateCtx, migrateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer migrateCancel()
	err = client.Schema.Create(migrateCtx) // Creates tables based on Ent schemas
	require.NoError(t, err, "Failed to run ent migrations")

	// Define cleanup function
	cleanup := func() {
		fmt.Println("Cleaning up Postgres test container (storage test)...")
		if errC := client.Close(); errC != nil {
			t.Logf("WARN: Failed to close ent client: %v", errC)
		}
		if errT := pgContainer.Terminate(ctx); errT != nil {
			t.Logf("WARN: Failed to terminate postgres container: %v", errT)
		}
		fmt.Println("Cleanup complete (storage test).")
	}

	return client, cleanup
}

// isPqConstraintError checks if an error is a specific pq constraint error.
func isPqConstraintError(err error, code pq.ErrorCode) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == code
	}
	return false
}

// TestPlatformStorageEnt runs storage-level tests for all custom platform entities.
func TestPlatformStorageEnt(t *testing.T) {
	// Skip test if running in short mode or if Docker is unavailable locally
	if testing.Short() {
		t.Skip("Skipping docker dependent test in short mode")
	}

	client, cleanup := setupTestPostgres(t)
	defer cleanup() // Ensure DB container is terminated

	ctx := context.Background()

	// --- PlatformUser Tests ---
	var testUser1 *db.PlatformUser
	var testUser2 *db.PlatformUser
	t.Run("PlatformUser_CRUD", func(t *testing.T) {
		email1 := "user1-storage@example.com"
		email2 := "user2-storage@example.com"
		displayName := "Test User 1 Storage"
		var err error // Declare err

		// Create Success
		testUser1, err = client.PlatformUser.Create().
			SetEmail(email1).
			SetDisplayName(displayName).
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testUser1)
		require.Equal(t, email1, testUser1.Email)
		require.Equal(t, displayName, testUser1.DisplayName)
		require.True(t, testUser1.IsActive)            // Check default
		require.False(t, testUser1.LastLogin.IsZero()) // Should default to zero/null

		// Create Duplicate Email
		_, err = client.PlatformUser.Create().
			SetEmail(email1). // Same email
			Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"), "Error should be unique_violation (23505)")

		// Get Found
		fetchedU1, err := client.PlatformUser.Get(ctx, testUser1.ID)
		require.NoError(t, err)
		require.Equal(t, testUser1.ID, fetchedU1.ID)

		// Get Not Found
		_, err = client.PlatformUser.Get(ctx, 999999)
		require.Error(t, err)
		require.True(t, ent.IsNotFound(err))

		// Update
		newDisplayName := "Updated Name Storage"
		now := time.Now().UTC().Truncate(time.Microsecond)
		updatedU1, err := testUser1.Update().
			SetDisplayName(newDisplayName).
			SetIsActive(false).
			SetLastLogin(now).
			Save(ctx)
		require.NoError(t, err)
		require.Equal(t, newDisplayName, updatedU1.DisplayName)
		require.False(t, updatedU1.IsActive)
		require.WithinDuration(t, now, updatedU1.LastLogin, time.Second)
		require.True(t, updatedU1.UpdateTime.After(testUser1.UpdateTime))

		// List (Basic)
		testUser2, err = client.PlatformUser.Create().SetEmail(email2).SetIsActive(false).Save(ctx)
		require.NoError(t, err)
		activeUsers, err := client.PlatformUser.Query().Where(platformuser.IsActiveEQ(true)).All(ctx)
		require.NoError(t, err)
		require.Len(t, activeUsers, 0) // u1 was updated to inactive, u2 created inactive
		inactiveUsers, err := client.PlatformUser.Query().Where(platformuser.IsActiveEQ(false)).All(ctx)
		require.NoError(t, err)
		require.Len(t, inactiveUsers, 2)

		// Delete (Leave one user for FK tests later)
		err = client.PlatformUser.DeleteOneID(testUser2.ID).Exec(ctx)
		require.NoError(t, err)
		_, err = client.PlatformUser.Get(ctx, testUser2.ID) // Verify Not Found
		require.Error(t, err)
		require.True(t, ent.IsNotFound(err))
	})

	// --- PlatformAppRole Tests ---
	var testRole1 *db.PlatformAppRole
	var testRole2 *db.PlatformAppRole
	t.Run("PlatformAppRole_CRUD", func(t *testing.T) {
		appID1 := "app-storage-1"
		appID2 := "app-storage-2"
		titleAdmin := "admin-storage"
		var err error

		// Create Success
		testRole1, err = client.PlatformAppRole.Create().
			SetAppID(appID1).
			SetTitle(titleAdmin).
			SetDescription("App1 Admin Role Storage").
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testRole1)
		require.Equal(t, appID1, testRole1.AppID)

		// Create Duplicate (same app_id, same title)
		_, err = client.PlatformAppRole.Create().
			SetAppID(appID1).
			SetTitle(titleAdmin).
			Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"), "Duplicate app_id/title should fail")

		// Create OK (different app_id, same title)
		testRole2, err = client.PlatformAppRole.Create().
			SetAppID(appID2).
			SetTitle(titleAdmin).
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testRole2)

		// Get
		fetchedRole, err := client.PlatformAppRole.Get(ctx, testRole1.ID)
		require.NoError(t, err)
		require.Equal(t, testRole1.Title, fetchedRole.Title)

		// Update
		updatedRole, err := fetchedRole.Update().SetIsActive(false).SetWeight(10).Save(ctx)
		require.NoError(t, err)
		require.False(t, updatedRole.IsActive)
		require.Equal(t, 10, updatedRole.Weight)

		// List by App ID
		roles, err := client.PlatformAppRole.Query().Where(platformapprole.AppIDEQ(appID1)).All(ctx)
		require.NoError(t, err)
		require.Len(t, roles, 1)
		require.Equal(t, titleAdmin, roles[0].Title)

		// Delete (leave role1 for later FK tests)
		err = client.PlatformAppRole.DeleteOneID(testRole2.ID).Exec(ctx)
		require.NoError(t, err)
	})

	// --- PlatformToken Tests ---
	var testToken1 *db.PlatformToken
	t.Run("PlatformToken_CRUD_FK", func(t *testing.T) {
		// Prerequisites
		require.NotNil(t, testUser1, "Token test needs user")
		require.NotNil(t, testRole1, "Token test needs role")

		publicID1 := "pub_abc123_storage"
		publicID2 := "pub_def456_storage"
		hash1 := "$argon2id$v=19$m=65536,t=3,p=2$SALTSTORAGE==$HASHSTORAGEABCDEF=="
		var err error

		// Create Success (with expiry)
		expiryTime := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Microsecond)
		testToken1, err = client.PlatformToken.Create().
			SetPublicID(publicID1).
			SetSecretHash(hash1).
			SetCreatorID(testUser1.ID).
			SetRoleID(testRole1.ID).
			SetExpiresAt(expiryTime).
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testToken1)
		require.True(t, testToken1.ExpiresAt.Equal(expiryTime))

		// Create Success (no expiry)
		_, err = client.PlatformToken.Create().
			SetPublicID(publicID2).
			SetSecretHash(hash1).
			SetCreator(testUser1).
			SetRole(testRole1).
			Save(ctx)
		require.NoError(t, err)

		// Create Duplicate Public ID
		_, err = client.PlatformToken.Create().
			SetPublicID(publicID1).
			SetSecretHash("newhash").
			SetCreatorID(testUser1.ID).
			SetRoleID(testRole1.ID).
			Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"), "Duplicate public_id should fail")

		// Query by Public ID
		fetchedToken1, err := client.PlatformToken.Query().
			Where(platformtoken.PublicIDEQ(publicID1)).
			Only(ctx)
		require.NoError(t, err)
		require.Equal(t, testToken1.ID, fetchedToken1.ID)

		// Update
		updatedToken1, err := fetchedToken1.Update().
			SetIsActive(false).
			ClearExpiresAt().
			Save(ctx)
		require.NoError(t, err)
		require.False(t, updatedToken1.IsActive)
		require.True(t, updatedToken1.ExpiresAt.IsZero())

		// Test FK Constraint (Role Deletion - RESTRICT)
		err = client.PlatformAppRole.DeleteOneID(testRole1.ID).Exec(ctx)
		require.Error(t, err, "Should fail to delete role due to RESTRICT constraint")
		require.True(t, isPqConstraintError(err, "23503"), "Error should be foreign_key_violation (23503)")

		// Delete token first
		err = client.PlatformToken.DeleteOneID(testToken1.ID).Exec(ctx)
		require.NoError(t, err)
		// Now try deleting role again (assuming token with publicID2 is also deleted or uses different role)
		token2, err := client.PlatformToken.Query().Where(platformtoken.PublicIDEQ(publicID2)).Only(ctx)
		if err == nil { // If token2 exists
			err = client.PlatformToken.DeleteOneID(token2.ID).Exec(ctx)
			require.NoError(t, err)
		}
		err = client.PlatformAppRole.DeleteOneID(testRole1.ID).Exec(ctx) // Now should succeed
		require.NoError(t, err)

		// Test FK Constraint (User Deletion - SET NULL)
		// Recreate role and create token with user testUser1
		testRole1, err = client.PlatformAppRole.Create().SetAppID(appID1).SetTitle(titleAdmin).Save(ctx) // Recreate role
		require.NoError(t, err)
		testToken1, err = client.PlatformToken.Create().SetPublicID(publicID1).SetSecretHash(hash1).SetCreatorID(testUser1.ID).SetRoleID(testRole1.ID).Save(ctx) // Recreate token
		require.NoError(t, err)
		require.Equal(t, testUser1.ID, testToken1.CreatorID)

		// Delete the user
		err = client.PlatformUser.DeleteOneID(testUser1.ID).Exec(ctx)
		require.NoError(t, err)

		// Refetch token and check creator_id
		refetchedToken, err := client.PlatformToken.Get(ctx, testToken1.ID)
		require.NoError(t, err)
		require.Equal(t, 0, refetchedToken.CreatorID, "CreatorID should be 0 representing NULL")
	})

	// --- PlatformFederatedIdentity Tests ---
	var testFedId1 *db.PlatformFederatedIdentity
	t.Run("PlatformFederatedIdentity_CRUD_FK", func(t *testing.T) {
		// Prerequisite: Need a user
		fedUser, err := client.PlatformUser.Create().SetEmail("fed-user@example.com").Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, fedUser)

		connID1 := "google-fed"
		fedUserID1 := "google-sub-fed-111"
		connID2 := "ldap-fed"
		var testFedId2 *db.PlatformFederatedIdentity // Declare for later use

		// Create Success
		testFedId1, err = client.PlatformFederatedIdentity.Create().
			SetUserID(fedUser.ID).
			SetConnectorID(connID1).
			SetFederatedUserID(fedUserID1).
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testFedId1)

		// Create Duplicate (same connector_id, same federated_user_id)
		_, err = client.PlatformFederatedIdentity.Create().
			SetUserID(fedUser.ID).
			SetConnectorID(connID1).
			SetFederatedUserID(fedUserID1).
			Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"), "Duplicate connector/fed_id should fail")

		// Create OK (same user, different connector)
		testFedId2, err = client.PlatformFederatedIdentity.Create().
			SetUserID(fedUser.ID).
			SetConnectorID(connID2).
			SetFederatedUserID("ldap-user-fed-111").
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

		// Test FK Cascade (Delete User)
		err = client.PlatformUser.DeleteOneID(fedUser.ID).Exec(ctx) // Delete the user
		require.NoError(t, err)

		// Verify federated identity was deleted
		_, err = client.PlatformFederatedIdentity.Get(ctx, testFedId2.ID)
		require.Error(t, err)
		require.True(t, ent.IsNotFound(err), "Federated identity should be cascade deleted")
	})

	// --- Assignment Table Tests ---
	t.Run("AssignmentTables", func(t *testing.T) {
		// Setup fresh user, role, identity, token for isolated assignment tests
		assignUser, _ := client.PlatformUser.Create().SetEmail("assign-user@example.com").Save(ctx)
		assignRole, _ := client.PlatformAppRole.Create().SetAppID("assign-app").SetTitle("assign-role-2").Save(ctx)
		assignFedId, _ := client.PlatformFederatedIdentity.Create().SetUser(assignUser).SetConnectorID("assign-conn-2").SetFederatedUserID("assign-fed-id-2").Save(ctx)
		assignToken, _ := client.PlatformToken.Create().SetPublicID("assign-pub-id").SetSecretHash("h").SetCreator(assignUser).SetRole(assignRole).Save(ctx) // Token needs a role

		// Test User Role Assignments
		t.Run("UserRoleAssignment", func(t *testing.T) {
			assign1, err := client.PlatformUserRoleAssignment.Create().
				SetUser(assignUser).
				SetRole(assignRole).
				Save(ctx)
			require.NoError(t, err)
			require.True(t, assign1.IsActive)

			_, err = client.PlatformUserRoleAssignment.Create().
				SetUserID(assignUser.ID).
				SetRoleID(assignRole.ID).
				Save(ctx)
			require.Error(t, err) // Duplicate
			require.True(t, isPqConstraintError(err, "23505"))

			updatedAssign1, err := assign1.Update().SetIsActive(false).Save(ctx)
			require.NoError(t, err)
			require.False(t, updatedAssign1.IsActive)

			err = client.PlatformUserRoleAssignment.DeleteOneID(assign1.ID).Exec(ctx)
			require.NoError(t, err)
		})

		// Test Identity Role Assignments
		t.Run("IdentityRoleAssignment", func(t *testing.T) {
			assign2, err := client.PlatformIdentityRoleAssignment.Create().
				SetIdentity(assignFedId). // Use Edge
				SetRole(assignRole).
				Save(ctx)
			require.NoError(t, err)
			require.True(t, assign2.IsActive)

			_, err = client.PlatformIdentityRoleAssignment.Create().
				SetIdentityID(assignFedId.ID). // Use ID
				SetRoleID(assignRole.ID).
				Save(ctx)
			require.Error(t, err) // Duplicate
			require.True(t, isPqConstraintError(err, "23505"))

			updatedAssign2, err := assign2.Update().SetIsActive(false).Save(ctx)
			require.NoError(t, err)
			require.False(t, updatedAssign2.IsActive)

			err = client.PlatformIdentityRoleAssignment.DeleteOneID(assign2.ID).Exec(ctx)
			require.NoError(t, err)
		})

		// Test Token Role Assignment (Implicit via FK on Token)
		t.Run("TokenRoleFK", func(t *testing.T) {
			// Verify token has the role ID set
			fetchedToken, err := client.PlatformToken.Get(ctx, assignToken.ID)
			require.NoError(t, err)
			require.Equal(t, assignRole.ID, fetchedToken.AppRoleID)

			// Test changing the role (Update)
			newRole, _ := client.PlatformAppRole.Create().SetAppID("assign-app").SetTitle("new-assign-role").Save(ctx)
			updatedToken, err := fetchedToken.Update().SetRoleID(newRole.ID).Save(ctx)
			require.NoError(t, err)
			require.Equal(t, newRole.ID, updatedToken.AppRoleID)
		})

	})

}

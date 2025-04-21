// storage/sql/platform_ent_test.go
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
	// "entgo.io/ent" // Not needed directly for these fixes
	"github.com/dexidp/dex/storage/ent/db" // Use 'db' alias

	// Import sub-packages for predicates/field constants & edges
	"github.com/dexidp/dex/storage/ent/db/platformapprole"
	"github.com/dexidp/dex/storage/ent/db/platformfederatedidentity"
	"github.com/dexidp/dex/storage/ent/db/platformtoken"
	"github.com/dexidp/dex/storage/ent/db/platformuser"

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
				WithOccurrence(2).WithStartupTimeout(1*time.Minute),
		),
		//testcontainers.WithRyuk(),
	)
	require.NoError(t, err, "Failed to start postgres container")
	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "Failed to get connection string")
	client, err := db.Open("postgres", dsn)
	require.NoError(t, err, "Failed to connect to test postgres with ent client")
	require.NotNil(t, client, "Ent client should not be nil")
	migrateCtx, migrateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer migrateCancel()
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

	ctx := context.Background()

	// Define variables in the outer scope to share between sub-tests if needed
	var testUser1 *db.PlatformUser
	var testRole1 *db.PlatformAppRole

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
		require.True(t, testUser1.IsActive)                                         // Default
		require.True(t, testUser1.LastLogin == nil || testUser1.LastLogin.IsZero()) // Default

		// Create Duplicate Email
		_, err = client.PlatformUser.Create().SetEmail(email1).Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"))

		// Get Found
		fetchedU1, err := client.PlatformUser.Get(ctx, testUser1.ID)
		require.NoError(t, err)
		require.Equal(t, testUser1.ID, fetchedU1.ID)

		// Get Not Found
		_, err = client.PlatformUser.Get(ctx, 999999)
		require.Error(t, err)
		// --- FIX: Use errors.As with generated type ---
		var nfe *db.NotFoundError
		require.True(t, errors.As(err, &nfe), "Error should be *db.NotFoundError")

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
		// --- FIX: Check for nil and dereference *time.Time ---
		require.NotNil(t, updatedU1.LastLogin)
		require.WithinDuration(t, now, *updatedU1.LastLogin, time.Second) // Dereference pointer
		require.True(t, updatedU1.UpdateTime.After(testUser1.UpdateTime))

		// List (Basic)
		testUser2, err := client.PlatformUser.Create().SetEmail(email2).SetIsActive(false).Save(ctx)
		require.NoError(t, err)
		activeUsers, err := client.PlatformUser.Query().Where(platformuser.IsActiveEQ(true)).All(ctx)
		require.NoError(t, err)
		require.Empty(t, activeUsers) // u1 updated to inactive
		inactiveUsers, err := client.PlatformUser.Query().Where(platformuser.IsActiveEQ(false)).All(ctx)
		require.NoError(t, err)
		require.Len(t, inactiveUsers, 2) // u1 and u2

		// Delete (Leave user1 for FK tests)
		err = client.PlatformUser.DeleteOneID(testUser2.ID).Exec(ctx)
		require.NoError(t, err)
		_, err = client.PlatformUser.Get(ctx, testUser2.ID)
		require.Error(t, err)
		// --- FIX: Use errors.As with generated type ---
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
		require.True(t, isPqConstraintError(err, "23505"))

		// Create OK (different app_id, same title)
		testRole2, err = client.PlatformAppRole.Create().SetAppID(appID2).SetTitle(titleAdmin).Save(ctx)
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

	t.Run("PlatformToken_CRUD_FK", func(t *testing.T) {
		require.NotNil(t, testUser1, "Token test needs user1 from outer scope")
		require.NotNil(t, testRole1, "Token test needs role1 from outer scope")

		publicID1 := "pub_abc123_storage"
		publicID2 := "pub_def456_storage"
		hash1 := "$argon2id$v=19$m=65536,t=3,p=2$SALTSTORAGE==$HASHSTORAGEABCDEF=="
		var err error
		var testToken1 *db.PlatformToken

		// Create Success (with expiry)
		expiryTime := time.Now().Add(1 * time.Hour).UTC().Truncate(time.Microsecond)
		testToken1, err = client.PlatformToken.Create().
			SetPublicID(publicID1).
			SetSecretHash(hash1).
			SetCreator(testUser1). // Use edge setter
			SetRole(testRole1).    // Use edge setter
			SetExpiresAt(expiryTime).
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testToken1)
		require.True(t, testToken1.ExpiresAt.Equal(expiryTime))

		// Create Success (no expiry)
		testToken2, err := client.PlatformToken.Create().
			SetPublicID(publicID2).
			SetSecretHash(hash1).
			SetCreator(testUser1).
			SetRole(testRole1).
			Save(ctx)
		require.NoError(t, err) // Ensure fetching worked
		require.NotNil(t, testToken2)
		// Correct Assertion: Check that ExpiresAt on token2 IS nil
		require.Nil(t, testToken2.ExpiresAt, "Token created without expiry should have nil ExpiresAt field")

		// Create Duplicate Public ID
		_, err = client.PlatformToken.Create().
			SetPublicID(publicID1).SetSecretHash("newhash").SetCreator(testUser1).SetRole(testRole1).
			Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"))

		// Query by Public ID, eager load edges
		fetchedToken1, err := client.PlatformToken.Query().
			Where(platformtoken.PublicIDEQ(publicID1)).
			WithCreator(). // Eager load creator
			WithRole().    // Eager load role
			Only(ctx)
		require.NoError(t, err)
		require.Equal(t, testToken1.ID, fetchedToken1.ID)
		// --- FIX: Check FK via Edges ---
		require.NotNil(t, fetchedToken1.Edges.Creator)
		require.NotNil(t, fetchedToken1.Edges.Role)
		require.Equal(t, testUser1.ID, fetchedToken1.Edges.Creator.ID)
		require.Equal(t, testRole1.ID, fetchedToken1.Edges.Role.ID)
		// --- FIX: Use testRole1 from outer scope for assertion ---
		require.Equal(t, testRole1.AppID, fetchedToken1.Edges.Role.AppID)
		require.Equal(t, testRole1.Title, fetchedToken1.Edges.Role.Title)

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
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23503"))

		// Delete tokens first
		_, err = client.PlatformToken.Delete().Where(platformtoken.HasRoleWith(platformapprole.IDEQ(testRole1.ID))).Exec(ctx)
		require.NoError(t, err)

		// Now try deleting role again
		err = client.PlatformAppRole.DeleteOneID(testRole1.ID).Exec(ctx)
		require.NoError(t, err) // Now should succeed

		// Test FK Constraint (User Deletion - SET NULL)
		// Recreate role and token with user testUser1
		testRole1, err = client.PlatformAppRole.Create().SetAppID(testRole1.AppID).SetTitle(testRole1.Title).Save(ctx) // Recreate role
		require.NoError(t, err)
		testToken1, err = client.PlatformToken.Create().
			SetPublicID(publicID1).SetSecretHash(hash1).SetCreator(testUser1).SetRole(testRole1).
			Save(ctx) // Recreate token
		require.NoError(t, err)

		// --- FIX: Verify initial Creator edge ---
		require.Equal(t, testUser1.ID, testToken1.QueryCreator().OnlyIDX(ctx)) // Check FK initially set

		// Delete the user
		err = client.PlatformUser.DeleteOneID(testUser1.ID).Exec(ctx)
		require.NoError(t, err)

		// Refetch token and check creator edge is now missing (due to SET NULL)
		refetchedToken, err := client.PlatformToken.Query().
			Where(platformtoken.IDEQ(testToken1.ID)).
			WithCreator(). // Attempt to load creator
			Only(ctx)
		require.NoError(t, err)
		require.Nil(t, refetchedToken.Edges.Creator, "Creator edge should be nil after user deletion (SET NULL)")
	})

	t.Run("PlatformFederatedIdentity_CRUD_FK", func(t *testing.T) {
		fedUser, err := client.PlatformUser.Create().SetEmail("fed-user@example.com").Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, fedUser)

		connID1 := "google-fed"
		fedUserID1 := "google-sub-fed-111"
		connID2 := "ldap-fed"
		var testFedId1, testFedId2 *db.PlatformFederatedIdentity

		// Create Success
		testFedId1, err = client.PlatformFederatedIdentity.Create().
			SetUser(fedUser).SetConnectorID(connID1).SetFederatedUserID(fedUserID1).
			Save(ctx)
		require.NoError(t, err)
		require.NotNil(t, testFedId1)

		// Create Duplicate (same connector_id, same federated_user_id)
		_, err = client.PlatformFederatedIdentity.Create().
			SetUser(fedUser).SetConnectorID(connID1).SetFederatedUserID(fedUserID1).
			Save(ctx)
		require.Error(t, err)
		require.True(t, isPqConstraintError(err, "23505"))

		// Create OK (same user, different connector)
		testFedId2, err = client.PlatformFederatedIdentity.Create().
			SetUser(fedUser).SetConnectorID(connID2).SetFederatedUserID("ldap-user-fed-111").
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
		err = client.PlatformUser.DeleteOneID(fedUser.ID).Exec(ctx)
		require.NoError(t, err)

		// Verify federated identity was deleted
		_, err = client.PlatformFederatedIdentity.Get(ctx, testFedId2.ID)
		require.Error(t, err)
		// --- FIX: Use errors.As with generated type ---
		var nfe *db.NotFoundError
		require.True(t, errors.As(err, &nfe), "Federated identity should be cascade deleted")
	})

	t.Run("AssignmentTables", func(t *testing.T) {
		// Setup fresh user, role, identity for isolated assignment tests
		assignUser, _ := client.PlatformUser.Create().SetEmail("assign-user@example.com").Save(ctx)
		assignRole, _ := client.PlatformAppRole.Create().SetAppID("assign-app").SetTitle("assign-role").Save(ctx) // Use unique title
		assignFedId, _ := client.PlatformFederatedIdentity.Create().SetUser(assignUser).SetConnectorID("assign-conn").SetFederatedUserID("assign-fed-id").Save(ctx)

		t.Run("UserRoleAssignment", func(t *testing.T) {
			assign1, err := client.PlatformUserRoleAssignment.Create().
				SetUser(assignUser).SetRole(assignRole).
				Save(ctx)
			require.NoError(t, err)
			require.True(t, assign1.IsActive)

			_, err = client.PlatformUserRoleAssignment.Create().SetUserID(assignUser.ID).SetRoleID(assignRole.ID).Save(ctx)
			require.Error(t, err)
			require.True(t, isPqConstraintError(err, "23505"))

			updatedAssign1, err := assign1.Update().SetIsActive(false).Save(ctx)
			require.NoError(t, err)
			require.False(t, updatedAssign1.IsActive)

			err = client.PlatformUserRoleAssignment.DeleteOneID(assign1.ID).Exec(ctx)
			require.NoError(t, err)
		})

		t.Run("IdentityRoleAssignment", func(t *testing.T) {
			assign2, err := client.PlatformIdentityRoleAssignment.Create().
				SetIdentity(assignFedId).SetRole(assignRole).
				Save(ctx)
			require.NoError(t, err)
			require.True(t, assign2.IsActive)

			_, err = client.PlatformIdentityRoleAssignment.Create().SetIdentityID(assignFedId.ID).SetRoleID(assignRole.ID).Save(ctx)
			require.Error(t, err)
			require.True(t, isPqConstraintError(err, "23505"))

			updatedAssign2, err := assign2.Update().SetIsActive(false).Save(ctx)
			require.NoError(t, err)
			require.False(t, updatedAssign2.IsActive)

			err = client.PlatformIdentityRoleAssignment.DeleteOneID(assign2.ID).Exec(ctx)
			require.NoError(t, err)
		})

		// Test Token Role Assignment (Implicit via FK on Token)
		t.Run("TokenRoleFK", func(t *testing.T) {
			assignToken, err := client.PlatformToken.Create().
				SetPublicID("assign-pub-id").SetSecretHash("h").SetCreator(assignUser).SetRole(assignRole). // Assign role on create
				Save(ctx)
			require.NoError(t, err)

			// Verify token has the role ID set via edge
			fetchedToken, err := client.PlatformToken.Query().
				Where(platformtoken.IDEQ(assignToken.ID)).
				WithRole(). // Eager load role
				Only(ctx)
			require.NoError(t, err)
			require.NotNil(t, fetchedToken.Edges.Role)
			// --- FIX: Check FK via Edges ---
			require.Equal(t, assignRole.ID, fetchedToken.Edges.Role.ID)

			// Test changing the role (Update)
			newRole, _ := client.PlatformAppRole.Create().SetAppID("assign-app").SetTitle("new-assign-role").Save(ctx)
			// Update token to point to new role
			updatedToken, err := fetchedToken.Update().SetRole(newRole).Save(ctx)
			require.NoError(t, err)

			// Verify updated token points to new role
			reFetchedToken, err := client.PlatformToken.Query().
				Where(platformtoken.IDEQ(updatedToken.ID)).
				WithRole().
				Only(ctx)
			require.NoError(t, err)
			require.NotNil(t, reFetchedToken.Edges.Role)
			// --- FIX: Check FK via Edges ---
			require.Equal(t, newRole.ID, reFetchedToken.Edges.Role.ID)
		})
	})
} // End TestPlatformStorageEnt

// storage/sql/platform_storage.go
package sql

import (
	"context"
	"errors" // Import for standard errors
	"fmt"
	"strconv"
	"time" // Ensure time package is imported

	// For sql.OrderDesc/Asc
	"entgo.io/ent/dialect/sql"
	// Import server's storage interface definitions
	pstorage "github.com/dexidp/dex/server/platform/storage"
	// Import generated Ent client package alias 'db'
	"github.com/dexidp/dex/storage/ent/db"
	// Import specific entity packages for constants and predicates
	"github.com/dexidp/dex/storage/ent/db/platformapprole"
	"github.com/dexidp/dex/storage/ent/db/platformfederatedidentity"
	"github.com/dexidp/dex/storage/ent/db/platformidentityroleassignment"
	"github.com/dexidp/dex/storage/ent/db/platformtoken"
	"github.com/dexidp/dex/storage/ent/db/platformuser"
	"github.com/dexidp/dex/storage/ent/db/platformuserroleassignment"

	// Import predicate type if needed for assignment filters
	"github.com/dexidp/dex/storage/ent/db/predicate"

	// Import pq driver for error code checking
	"github.com/lib/pq"
)

// ErrInvalidID represents an error for non-positive IDs.
var ErrInvalidID = errors.New("ID must be a positive integer")

// entStorage implements the platform storage interfaces using an Ent client.
type entStorage struct {
	client *db.Client
}

// NewEntStorage creates a new storage implementation backed by Ent.
// It returns the combined PlatformStorage interface.
func NewEntStorage(client *db.Client) pstorage.PlatformStorage { // Return the combined interface
	if client == nil {
		// Use panic here as this indicates a programming error during setup
		panic("ent client cannot be nil for entStorage implementation")
	}
	return &entStorage{client: client}
}

// Compile-time check that entStorage implements the combined interface.
// This ensures UpdateTokenRole is implemented if TokenStorage requires it.
var _ pstorage.PlatformStorage = (*entStorage)(nil)

// --- Helper: ID Conversion ---

// internal helper to convert string ID from proto/filters to int for Ent.
// Validates that the ID is a positive integer.
func stringIDToInt(idStr string) (int, error) {
	if idStr == "" {
		return 0, fmt.Errorf("ID cannot be empty")
	}
	idInt64, err := strconv.ParseInt(idStr, 10, 0) // Use ParseInt to easily check range
	if err != nil {
		return 0, fmt.Errorf("invalid integer ID format '%s': %w", idStr, err)
	}
	idInt := int(idInt64)
	if idInt <= 0 {
		return 0, fmt.Errorf("%w: received '%s'", ErrInvalidID, idStr)
	}
	return idInt, nil
}

// internal helper to validate standard integer IDs.
func validatePositiveID(id int) error {
	if id <= 0 {
		return fmt.Errorf("%w: received %d", ErrInvalidID, id)
	}
	return nil
}

// --- UserStorage Implementation ---

func (s *entStorage) GetUserByID(ctx context.Context, id int) (*db.PlatformUser, error) {
	if err := validatePositiveID(id); err != nil {
		return nil, err
	}
	user, err := s.client.PlatformUser.Get(ctx, id)
	if err != nil {
		// Let service layer decide how to handle db.NotFoundError vs other errors
		return nil, fmt.Errorf("failed to get user by ID %d: %w", id, err)
	}
	return user, nil
}

func (s *entStorage) CreateUser(ctx context.Context, data *db.PlatformUser) (*db.PlatformUser, error) {
	createOp := s.client.PlatformUser.Create().
		SetEmail(data.Email)

	// Ent usually handles default values based on schema.
	// Only set fields if they are explicitly provided and differ from default.
	if data.DisplayName != "" { // Check if DisplayName was provided
		createOp.SetDisplayName(data.DisplayName)
	}
	// Rely on schema default (true) unless explicitly false
	// Assumes data.IsActive is false only if intentionally set false by caller
	if !data.IsActive {
		createOp.SetIsActive(false)
	}

	user, err := createOp.Save(ctx)
	if err != nil {
		// db.ConstraintError could be returned here on duplicate email etc.
		return nil, fmt.Errorf("failed to create user with email %s: %w", data.Email, err)
	}
	return user, nil
}

// UpdateUser uses a map for flexibility. Consider dedicated Update structs in the service
// layer for better type safety if complexity grows.
func (s *entStorage) UpdateUser(ctx context.Context, id int, updateData map[string]interface{}) (*db.PlatformUser, error) {
	if err := validatePositiveID(id); err != nil {
		return nil, err
	}
	updateOp := s.client.PlatformUser.UpdateOneID(id)
	setAny := false

	if val, ok := updateData["DisplayName"]; ok {
		if strVal, okStr := val.(string); okStr {
			updateOp.SetDisplayName(strVal) // Allow setting empty string
			setAny = true
		} else {
			return nil, fmt.Errorf("invalid type for DisplayName update for user %d: expected string, got %T", id, val)
		}
	}
	if val, ok := updateData["IsActive"]; ok {
		if boolVal, okBool := val.(bool); okBool {
			updateOp.SetIsActive(boolVal)
			setAny = true
		} else {
			return nil, fmt.Errorf("invalid type for IsActive update for user %d: expected bool, got %T", id, val)
		}
	}
	// NOTE: Assumes LastLogin field in schema is nillable (*time.Time or Optional)
	if val, ok := updateData["LastLogin"]; ok {
		if val == nil {
			updateOp.ClearLastLogin()
			setAny = true
		} else if timeVal, okTime := val.(time.Time); okTime {
			// Allow setting zero time if necessary
			updateOp.SetLastLogin(timeVal)
			setAny = true
		} else if timeValPtr, okTimePtr := val.(*time.Time); okTimePtr {
			if timeValPtr != nil {
				updateOp.SetLastLogin(*timeValPtr)
			} else {
				updateOp.ClearLastLogin()
			}
			setAny = true
		} else {
			return nil, fmt.Errorf("invalid type for LastLogin update for user %d: expected time.Time, *time.Time or nil, got %T", id, val)
		}
	}

	if !setAny {
		// No valid update fields found, return current state without hitting DB save.
		return s.GetUserByID(ctx, id)
	}

	user, err := updateOp.Save(ctx)
	if err != nil {
		// Could be db.NotFoundError if ID doesn't exist, or ConstraintError.
		return nil, fmt.Errorf("failed to update user %d: %w", id, err)
	}
	return user, nil
}

func (s *entStorage) DeleteUserByID(ctx context.Context, id int) error {
	if err := validatePositiveID(id); err != nil {
		return err
	}
	err := s.client.PlatformUser.DeleteOneID(id).Exec(ctx)
	if err != nil {
		// Let service layer handle db.NotFoundError if needed (e.g., for idempotency).
		// Also check for FK constraint errors if needed (pqErr.Code == "23503")
		return fmt.Errorf("failed to delete user %d: %w", id, err)
	}
	return nil
}

func (s *entStorage) CountUsers(ctx context.Context, filters pstorage.UserFilters) (int, error) {
	query := s.client.PlatformUser.Query()
	query = applyUserFilters(query, filters) // Apply filters
	count, err := query.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}
	return count, nil
}

func (s *entStorage) ListUsersPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters pstorage.UserFilters) ([]*db.PlatformUser, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}
	query := s.client.PlatformUser.Query()
	query = applyUserFilters(query, filters)

	// Apply standard ordering for cursor pagination consistency
	query = query.Order(
		platformuser.ByCreateTime(sql.OrderDesc()),
		platformuser.ByID(sql.OrderAsc()),
	)

	// Apply WHERE clause for cursor pagination IF cursor values were provided
	if afterTime != nil && afterID != nil {
		if err := validatePositiveID(*afterID); err != nil {
			return nil, fmt.Errorf("invalid afterID in cursor: %w", err)
		}
		query = query.Where(platformuser.Or(
			platformuser.CreateTimeLT(*afterTime),
			platformuser.And(
				platformuser.CreateTimeEQ(*afterTime),
				platformuser.IDGT(*afterID),
			),
		))
	}

	users, err := query.Limit(limit).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users paginated: %w", err)
	}
	return users, nil
}

// --- AppRoleStorage Implementation ---

func (s *entStorage) GetAppRoleByID(ctx context.Context, id int) (*db.PlatformAppRole, error) {
	if err := validatePositiveID(id); err != nil {
		return nil, err
	}
	role, err := s.client.PlatformAppRole.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get app role by ID %d: %w", id, err)
	}
	return role, nil
}

func (s *entStorage) CreateAppRole(ctx context.Context, data *db.PlatformAppRole) (*db.PlatformAppRole, error) {
	createOp := s.client.PlatformAppRole.Create().
		SetAppID(data.AppID).
		SetTitle(data.Title)

	// Corrected handling for nillable *string Description
	if data.Description != nil {
		createOp.SetDescription(*data.Description)
	}

	if data.Weight != 0 {
		createOp.SetWeight(data.Weight)
	}
	// Rely on schema default (true) unless explicitly false
	if !data.IsActive {
		createOp.SetIsActive(false)
	}

	role, err := createOp.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create app role with title '%s' for app '%s': %w", data.Title, data.AppID, err)
	}
	return role, nil
}

// UpdateAppRole uses a map. Consider dedicated Update structs in the service layer.
func (s *entStorage) UpdateAppRole(ctx context.Context, id int, updateData map[string]interface{}) (*db.PlatformAppRole, error) {
	if err := validatePositiveID(id); err != nil {
		return nil, err
	}
	updateOp := s.client.PlatformAppRole.UpdateOneID(id)
	setAny := false

	if val, ok := updateData["Title"]; ok {
		if strVal, okStr := val.(string); okStr && strVal != "" {
			updateOp.SetTitle(strVal)
			setAny = true
		} else if !okStr {
			return nil, fmt.Errorf("invalid type for Title update for role %d: expected string, got %T", id, val)
		} else {
			return nil, fmt.Errorf("title cannot be empty for role %d", id)
		}
	}

	// Corrected handling for nillable *string Description update
	if _, ok := updateData["Description"]; ok {
		val := updateData["Description"]
		if val == nil {
			updateOp.ClearDescription() // Use Clear<Field> for nillable fields
			setAny = true
		} else if strVal, okStr := val.(string); okStr {
			updateOp.SetDescription(strVal)
			setAny = true
		} else {
			return nil, fmt.Errorf("invalid type for Description update for role %d: expected string or nil, got %T", id, val)
		}
	}

	if val, ok := updateData["Weight"]; ok {
		var weightInt int
		validType := false
		switch v := val.(type) {
		case int:
			weightInt = v
			validType = true
		case int32:
			weightInt = int(v)
			validType = true
		case float64:
			weightInt = int(v)
			if float64(weightInt) != v {
				return nil, fmt.Errorf("invalid non-integer value for Weight update for role %d: got %f", id, v)
			}
			validType = true
		}
		if validType {
			updateOp.SetWeight(weightInt)
			setAny = true
		} else {
			return nil, fmt.Errorf("invalid type for Weight update for role %d: expected numeric, got %T", id, val)
		}
	}
	if val, ok := updateData["IsActive"]; ok {
		if boolVal, okBool := val.(bool); okBool {
			updateOp.SetIsActive(boolVal)
			setAny = true
		} else {
			return nil, fmt.Errorf("invalid type for IsActive update for role %d: expected bool, got %T", id, val)
		}
	}

	if !setAny {
		return s.GetAppRoleByID(ctx, id)
	}
	role, err := updateOp.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update app role %d: %w", id, err)
	}
	return role, nil
}

func (s *entStorage) DeleteAppRoleByID(ctx context.Context, id int) error {
	if err := validatePositiveID(id); err != nil {
		return err
	}
	err := s.client.PlatformAppRole.DeleteOneID(id).Exec(ctx)
	if err != nil {
		// Check for FK constraint violation (pq.ErrorCode("23503")) if specific handling needed
		return fmt.Errorf("failed to delete app role %d: %w", id, err)
	}
	return nil
}

func (s *entStorage) CountAppRoles(ctx context.Context, filters pstorage.AppRoleFilters) (int, error) {
	query := s.client.PlatformAppRole.Query()
	query = applyAppRoleFilters(query, filters)
	count, err := query.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count app roles: %w", err)
	}
	return count, nil
}

func (s *entStorage) ListAppRolesPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters pstorage.AppRoleFilters) ([]*db.PlatformAppRole, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}
	query := s.client.PlatformAppRole.Query()
	query = applyAppRoleFilters(query, filters)

	query = query.Order(
		platformapprole.ByCreateTime(sql.OrderDesc()),
		platformapprole.ByID(sql.OrderAsc()),
	)

	if afterTime != nil && afterID != nil {
		if err := validatePositiveID(*afterID); err != nil {
			return nil, fmt.Errorf("invalid afterID in cursor: %w", err)
		}
		query = query.Where(platformapprole.Or(
			platformapprole.CreateTimeLT(*afterTime),
			platformapprole.And(
				platformapprole.CreateTimeEQ(*afterTime),
				platformapprole.IDGT(*afterID),
			),
		))
	}

	roles, err := query.Limit(limit).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list app roles paginated: %w", err)
	}
	return roles, nil
}

// --- TokenStorage Implementation ---

// ##########################################################################
// # IMPORTANT NOTE: Assumes Ent schema/generation is complete for:         #
// # 1. Renamed 'creator' edge to 'owner' on PlatformToken.                 #
// # 2. Explicit 'owner_id' field added to PlatformToken schema fields.     #
// ##########################################################################

func (s *entStorage) GetTokenByID(ctx context.Context, id int) (*db.PlatformToken, error) {
	if err := validatePositiveID(id); err != nil {
		return nil, err
	}
	token, err := s.client.PlatformToken.Query().
		Where(platformtoken.IDEQ(id)).
		WithOwner(). // Eager load owner edge
		WithRole().  // Eager load role edge
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token by ID %d: %w", id, err)
	}
	return token, nil
}

func (s *entStorage) GetTokenByPublicID(ctx context.Context, publicID string) (*db.PlatformToken, error) {
	if publicID == "" {
		return nil, errors.New("public ID cannot be empty")
	}
	token, err := s.client.PlatformToken.Query().
		Where(platformtoken.PublicIDEQ(publicID)).
		WithOwner().
		WithRole().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token by public ID '%s': %w", publicID, err)
	}
	return token, nil
}

// --- SIGNATURE UPDATED ---
func (s *entStorage) CreateToken(ctx context.Context, data *db.PlatformToken, roleID int) (*db.PlatformToken, error) {
	// Assumes service layer computed SecretHash and generated PublicID.
	// Assumes service layer validated OwnerID corresponds to existing entity.
	// Assumes service layer validated roleID corresponds to existing entity.

	// Corrected Validation: Check explicit OwnerID field.
	if data.OwnerID <= 0 {
		return nil, fmt.Errorf("owner ID (%d) must be positive", data.OwnerID)
	}
	// Add validation for the passed roleID parameter
	if err := validatePositiveID(roleID); err != nil {
		return nil, fmt.Errorf("invalid roleID: %w", err)
	}

	if data.PublicID == "" || len(data.SecretHash) == 0 {
		return nil, errors.New("public ID and secret hash cannot be empty")
	}

	createOp := s.client.PlatformToken.Create().
		SetPublicID(data.PublicID).
		SetSecretHash(data.SecretHash).
		SetOwnerID(data.OwnerID). // Set the explicit FK field
		// --- Use roleID parameter ---
		SetRoleID(roleID) // Set the FK for the required 'role' edge

	if data.ExpiresAt != nil { // Handle optional ExpiresAt
		createOp.SetExpiresAt(*data.ExpiresAt)
	}

	// Rely on schema default for IsActive (true) unless explicitly false in input
	if !data.IsActive {
		createOp.SetIsActive(false)
	}

	token, err := createOp.Save(ctx)
	if err != nil {
		// Constraint errors likely if OwnerID/RoleID FKs invalid, or PublicID duplicate
		return nil, fmt.Errorf("failed to create token for owner %d: %w", data.OwnerID, err)
	}

	// Refetch to include edges consistently
	return s.GetTokenByID(ctx, token.ID)
}

// UpdateTokenRole implements the storage interface method to update ONLY the role of a token.
func (s *entStorage) UpdateTokenRole(ctx context.Context, id int, newRoleID int) (*db.PlatformToken, error) {
	if err := validatePositiveID(id); err != nil {
		return nil, err
	}
	if err := validatePositiveID(newRoleID); err != nil {
		return nil, fmt.Errorf("invalid newRoleID: %w", err)
	}

	// Prepare the update operation to set only the RoleID
	updateOp := s.client.PlatformToken.UpdateOneID(id).
		SetRoleID(newRoleID) // Set FK for the role edge

	// Save changes. Check error first.
	_, err := updateOp.Save(ctx)
	if err != nil {
		// db.NotFoundError, db.ConstraintError (if newRoleID doesn't exist) possible
		return nil, fmt.Errorf("failed to update role for token %d: %w", id, err)
	}

	// Refetch the token to return the updated state with eager-loaded edges.
	return s.GetTokenByID(ctx, id)
}

func (s *entStorage) DeleteTokenByID(ctx context.Context, id int) error {
	if err := validatePositiveID(id); err != nil {
		return err
	}
	err := s.client.PlatformToken.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete token %d: %w", id, err)
	}
	return nil
}

func (s *entStorage) CountTokens(ctx context.Context, filters pstorage.TokenFilters) (int, error) {
	query := s.client.PlatformToken.Query()
	q, err := applyTokenFilters(query, filters) // Filter helper handles owner/role filtering
	if err != nil {
		return 0, err // Error already has context from applyTokenFilters
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count tokens: %w", err)
	}
	return count, nil
}

func (s *entStorage) ListTokensPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters pstorage.TokenFilters) ([]*db.PlatformToken, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}
	query := s.client.PlatformToken.Query()
	q, err := applyTokenFilters(query, filters) // Filter helper handles owner/role filtering
	if err != nil {
		return nil, err // Error already has context from applyTokenFilters
	}

	q = q.Order(
		platformtoken.ByCreateTime(sql.OrderDesc()),
		platformtoken.ByID(sql.OrderAsc()),
	)

	if afterTime != nil && afterID != nil {
		if err := validatePositiveID(*afterID); err != nil {
			return nil, fmt.Errorf("invalid afterID in cursor: %w", err)
		}
		q = q.Where(platformtoken.Or(
			platformtoken.CreateTimeLT(*afterTime),
			platformtoken.And(
				platformtoken.CreateTimeEQ(*afterTime),
				platformtoken.IDGT(*afterID),
			),
		))
	}

	// Eager load owner and role
	tokens, err := q.Limit(limit).WithOwner().WithRole().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens paginated: %w", err)
	}
	return tokens, nil
}

// --- FederatedIdentityStorage Implementation ---

func (s *entStorage) GetFederatedIdentityByID(ctx context.Context, id int) (*db.PlatformFederatedIdentity, error) {
	if err := validatePositiveID(id); err != nil {
		return nil, err
	}
	// Eager load user
	identity, err := s.client.PlatformFederatedIdentity.Query().
		Where(platformfederatedidentity.IDEQ(id)).
		WithUser().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get federated identity by ID %d: %w", id, err)
	}
	return identity, nil
}

func (s *entStorage) DeleteFederatedIdentityByID(ctx context.Context, id int) error {
	if err := validatePositiveID(id); err != nil {
		return err
	}
	err := s.client.PlatformFederatedIdentity.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete federated identity %d: %w", id, err)
	}
	return nil
}

func (s *entStorage) CountFederatedIdentities(ctx context.Context, filters pstorage.FederatedIdentityFilters) (int, error) {
	query := s.client.PlatformFederatedIdentity.Query()
	q, err := applyFederatedIdentityFilters(query, filters)
	if err != nil {
		return 0, err // Error already has context
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count federated identities: %w", err)
	}
	return count, nil
}

func (s *entStorage) ListFederatedIdentitiesPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters pstorage.FederatedIdentityFilters) ([]*db.PlatformFederatedIdentity, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}
	query := s.client.PlatformFederatedIdentity.Query()
	q, err := applyFederatedIdentityFilters(query, filters)
	if err != nil {
		return nil, err // Error already has context
	}

	q = q.Order(
		platformfederatedidentity.ByCreateTime(sql.OrderDesc()),
		platformfederatedidentity.ByID(sql.OrderAsc()),
	)

	if afterTime != nil && afterID != nil {
		if err := validatePositiveID(*afterID); err != nil {
			return nil, fmt.Errorf("invalid afterID in cursor: %w", err)
		}
		q = q.Where(platformfederatedidentity.Or(
			platformfederatedidentity.CreateTimeLT(*afterTime),
			platformfederatedidentity.And(
				platformfederatedidentity.CreateTimeEQ(*afterTime),
				platformfederatedidentity.IDGT(*afterID),
			),
		))
	}

	identities, err := q.Limit(limit).WithUser().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list federated identities paginated: %w", err)
	}
	return identities, nil
}

// --- AssignmentStorage Implementation ---

func (s *entStorage) AssignRoleToUser(ctx context.Context, userID int, roleID int) (*db.PlatformUserRoleAssignment, error) {
	if err := validatePositiveID(userID); err != nil {
		return nil, fmt.Errorf("invalid userID: %w", err)
	}
	if err := validatePositiveID(roleID); err != nil {
		return nil, fmt.Errorf("invalid roleID: %w", err)
	}

	assignment, err := s.client.PlatformUserRoleAssignment.Create().
		SetUserID(userID).
		SetRoleID(roleID).
		Save(ctx)
	if err != nil {
		// --- ADDED Constraint Error Handling ---
		var constraintErr *db.ConstraintError
		var pqErr *pq.Error
		if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && (pqErr.Code == "23505" || pqErr.Code == "23503")) {
			// 23505 = unique violation (already assigned)
			// 23503 = foreign key violation (user or role doesn't exist)
			// Return a wrapped error that service layer can potentially inspect
			return nil, fmt.Errorf("assignment constraint violation (user=%d, role=%d): %w", userID, roleID, err)
		}
		// --- END Added Handling ---
		// Generic fallback error
		return nil, fmt.Errorf("failed to assign role %d to user %d: %w", roleID, userID, err)
	}
	return assignment, nil
}

func (s *entStorage) RemoveRoleFromUser(ctx context.Context, userID int, roleID int) error {
	if err := validatePositiveID(userID); err != nil {
		return fmt.Errorf("invalid userID: %w", err)
	}
	if err := validatePositiveID(roleID); err != nil {
		return fmt.Errorf("invalid roleID: %w", err)
	}

	affected, err := s.client.PlatformUserRoleAssignment.Delete().
		Where(
			// Corrected predicates using Has...With for implicit FKs
			platformuserroleassignment.HasUserWith(platformuser.IDEQ(userID)),
			platformuserroleassignment.HasRoleWith(platformapprole.IDEQ(roleID)),
		).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to remove role %d from user %d: %w", roleID, userID, err)
	}
	if affected == 0 {
		// Return a distinct error for not found
		return fmt.Errorf("assignment for user %d and role %d not found", userID, roleID) // Consider custom error type
	}
	if affected > 1 {
		// Should not happen with unique constraint
		return fmt.Errorf("consistency error: unexpectedly deleted %d assignments for user %d and role %d", affected, userID, roleID)
	}
	return nil // Success
}

func (s *entStorage) ListUserRoles(ctx context.Context, userID int, filters pstorage.AssignmentFilters) ([]*db.PlatformAppRole, error) {
	if err := validatePositiveID(userID); err != nil {
		return nil, fmt.Errorf("invalid userID: %w", err)
	}

	// Define predicates for the PlatformUserRoleAssignment edge
	assignmentPredicates := []predicate.PlatformUserRoleAssignment{
		platformuserroleassignment.HasUserWith(platformuser.IDEQ(userID)),
	}
	if filters.AssignmentIsActive != nil {
		assignmentPredicates = append(assignmentPredicates, platformuserroleassignment.IsActiveEQ(*filters.AssignmentIsActive))
	}

	// Start query from PlatformAppRole
	roleQuery := s.client.PlatformAppRole.Query().
		Where(platformapprole.HasUserAssignmentsWith(assignmentPredicates...)) // Filter roles that have matching assignments

	// Apply filters directly targeting the PlatformAppRole
	if filters.AppID != "" {
		roleQuery = roleQuery.Where(platformapprole.AppIDEQ(filters.AppID))
	}
	if filters.RoleIsActive != nil {
		roleQuery = roleQuery.Where(platformapprole.IsActiveEQ(*filters.RoleIsActive))
	}

	// Apply ordering
	roleQuery = roleQuery.Order(platformapprole.ByWeight(sql.OrderAsc()), platformapprole.ByTitle(sql.OrderAsc()))

	roles, err := roleQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles for user %d: %w", userID, err)
	}
	return roles, nil
}

func (s *entStorage) AssignRoleToIdentity(ctx context.Context, identityID int, roleID int) (*db.PlatformIdentityRoleAssignment, error) {
	if err := validatePositiveID(identityID); err != nil {
		return nil, fmt.Errorf("invalid identityID: %w", err)
	}
	if err := validatePositiveID(roleID); err != nil {
		return nil, fmt.Errorf("invalid roleID: %w", err)
	}

	assignment, err := s.client.PlatformIdentityRoleAssignment.Create().
		SetIdentityID(identityID).
		SetRoleID(roleID).
		Save(ctx)
	if err != nil {
		// --- ADDED Constraint Error Handling ---
		var constraintErr *db.ConstraintError
		var pqErr *pq.Error
		if errors.As(err, &constraintErr) || (errors.As(err, &pqErr) && (pqErr.Code == "23505" || pqErr.Code == "23503")) {
			return nil, fmt.Errorf("assignment constraint violation (identity=%d, role=%d): %w", identityID, roleID, err)
		}
		// --- END Added Handling ---
		return nil, fmt.Errorf("failed to assign role %d to identity %d: %w", roleID, identityID, err)
	}
	return assignment, nil
}

func (s *entStorage) RemoveRoleFromIdentity(ctx context.Context, identityID int, roleID int) error {
	if err := validatePositiveID(identityID); err != nil {
		return fmt.Errorf("invalid identityID: %w", err)
	}
	if err := validatePositiveID(roleID); err != nil {
		return fmt.Errorf("invalid roleID: %w", err)
	}

	affected, err := s.client.PlatformIdentityRoleAssignment.Delete().
		Where(
			// Corrected predicates using Has...With for implicit FKs
			platformidentityroleassignment.HasIdentityWith(platformfederatedidentity.IDEQ(identityID)),
			platformidentityroleassignment.HasRoleWith(platformapprole.IDEQ(roleID)),
		).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to remove role %d from identity %d: %w", roleID, identityID, err)
	}
	if affected == 0 {
		return fmt.Errorf("assignment for identity %d and role %d not found", identityID, roleID) // Consider custom error type
	}
	if affected > 1 {
		return fmt.Errorf("consistency error: unexpectedly deleted %d assignments for identity %d and role %d", affected, identityID, roleID)
	}
	return nil // Success
}

func (s *entStorage) ListIdentityRoles(ctx context.Context, identityID int, filters pstorage.AssignmentFilters) ([]*db.PlatformAppRole, error) {
	if err := validatePositiveID(identityID); err != nil {
		return nil, fmt.Errorf("invalid identityID: %w", err)
	}

	// Define predicates for the PlatformIdentityRoleAssignment edge
	assignmentPredicates := []predicate.PlatformIdentityRoleAssignment{
		platformidentityroleassignment.HasIdentityWith(platformfederatedidentity.IDEQ(identityID)),
	}
	if filters.AssignmentIsActive != nil {
		assignmentPredicates = append(assignmentPredicates, platformidentityroleassignment.IsActiveEQ(*filters.AssignmentIsActive))
	}

	// Start query from PlatformAppRole
	roleQuery := s.client.PlatformAppRole.Query().
		Where(platformapprole.HasIdentityAssignmentsWith(assignmentPredicates...)) // Filter roles that have matching assignments

	// Apply filters directly targeting the PlatformAppRole
	if filters.AppID != "" {
		roleQuery = roleQuery.Where(platformapprole.AppIDEQ(filters.AppID))
	}
	if filters.RoleIsActive != nil {
		roleQuery = roleQuery.Where(platformapprole.IsActiveEQ(*filters.RoleIsActive))
	}

	// Apply ordering
	roleQuery = roleQuery.Order(platformapprole.ByWeight(sql.OrderAsc()), platformapprole.ByTitle(sql.OrderAsc()))

	roles, err := roleQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles for identity %d: %w", identityID, err)
	}
	return roles, nil
}

// --- Filter Helper Implementations ---

// applyUserFilters applies filters to a PlatformUser query.
func applyUserFilters(q *db.PlatformUserQuery, filters pstorage.UserFilters) *db.PlatformUserQuery {
	if filters.IsActive != nil {
		q = q.Where(platformuser.IsActiveEQ(*filters.IsActive))
	}
	if filters.EmailContains != "" {
		q = q.Where(platformuser.EmailContainsFold(filters.EmailContains))
	}
	return q
}

// applyAppRoleFilters applies filters to a PlatformAppRole query.
func applyAppRoleFilters(q *db.PlatformAppRoleQuery, filters pstorage.AppRoleFilters) *db.PlatformAppRoleQuery {
	if filters.AppID != "" {
		q = q.Where(platformapprole.AppIDEQ(filters.AppID))
	}
	if filters.IsActive != nil {
		q = q.Where(platformapprole.IsActiveEQ(*filters.IsActive))
	}
	if filters.TitleContains != "" {
		q = q.Where(platformapprole.TitleContainsFold(filters.TitleContains))
	}
	return q
}

// applyTokenFilters applies filters to a PlatformToken query.
// It needs to handle potential errors converting string IDs to int.
func applyTokenFilters(q *db.PlatformTokenQuery, filters pstorage.TokenFilters) (*db.PlatformTokenQuery, error) {
	if filters.OwnerID != "" {
		ownerIntID, err := stringIDToInt(filters.OwnerID)
		if err != nil {
			return nil, fmt.Errorf("invalid OwnerID filter format: %w", err)
		}
		q = q.Where(platformtoken.HasOwnerWith(platformuser.IDEQ(ownerIntID)))
	}
	if filters.AppRoleID != "" {
		roleIntID, err := stringIDToInt(filters.AppRoleID)
		if err != nil {
			return nil, fmt.Errorf("invalid AppRoleID filter format: %w", err)
		}
		q = q.Where(platformtoken.HasRoleWith(platformapprole.IDEQ(roleIntID)))
	}
	if filters.IsActive != nil {
		q = q.Where(platformtoken.IsActiveEQ(*filters.IsActive))
	}
	if filters.ExcludeExpired {
		now := time.Now()
		q = q.Where(platformtoken.Or(
			platformtoken.ExpiresAtIsNil(),
			platformtoken.ExpiresAtGT(now),
		))
	}

	return q, nil
}

// applyFederatedIdentityFilters applies filters to a PlatformFederatedIdentity query.
// Assumes schema field is named 'connector_subject'.
func applyFederatedIdentityFilters(q *db.PlatformFederatedIdentityQuery, filters pstorage.FederatedIdentityFilters) (*db.PlatformFederatedIdentityQuery, error) {
	if filters.PlatformUserID != "" {
		userIntID, err := stringIDToInt(filters.PlatformUserID)
		if err != nil {
			return nil, fmt.Errorf("invalid PlatformUserID filter format: %w", err)
		}
		q = q.Where(platformfederatedidentity.HasUserWith(platformuser.IDEQ(userIntID)))
	}
	if filters.ConnectorID != "" {
		q = q.Where(platformfederatedidentity.ConnectorIDEQ(filters.ConnectorID))
	}
	if filters.ConnectorSubject != "" {
		q = q.Where(platformfederatedidentity.ConnectorSubjectEQ(filters.ConnectorSubject))
	}

	return q, nil
}

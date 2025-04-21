// server/platform/storage/interfaces.go
package storage

import (
	"context"
	"time"

	// Import the generated Ent client package alias 'db'
	// Needed for entity types like *db.PlatformUser and error types.
	"github.com/dexidp/dex/storage/ent/db"
)

// This file defines the storage interfaces required by the platform gRPC services
// (located in the parent server/platform package). These interfaces decouple
// service logic from the concrete storage implementation (e.g., Ent).

// --- Filter Struct Definitions ---

// UserFilters defines parameters for filtering user lists.
type UserFilters struct {
	IsActive      *bool // Filter by active status
	EmailContains string
}

// AppRoleFilters defines parameters for filtering application role lists.
type AppRoleFilters struct {
	AppID         string // Filter by application ID (often required)
	IsActive      *bool  // Filter by active status
	TitleContains string
}

// TokenFilters defines parameters for filtering platform token lists.
type TokenFilters struct {
	OwnerID        string // Filter by the internal ID string of the owner user
	AppRoleID      string // Filter by the internal ID string of the assigned role
	IsActive       *bool  // Filter by active status
	ExcludeExpired bool   // If true, only return tokens that have not expired
}

// FederatedIdentityFilters defines parameters for filtering federated identity lists.
type FederatedIdentityFilters struct {
	PlatformUserID   string // Filter by the internal ID string of the platform user
	ConnectorID      string // Filter by connector ID
	ConnectorSubject string // Filter by the subject identifier from the connector
}

// AssignmentFilters defines parameters for filtering role assignments when listing roles associated with a user or identity.
type AssignmentFilters struct {
	AppID              string // Filter roles by the application ID they belong to
	AssignmentIsActive *bool  // Filter by the active status of the assignment record itself
	RoleIsActive       *bool  // Filter roles by their own active status
}

// --- Storage Interface Definitions ---

// UserStorage defines database operations specific to PlatformUser entities.
type UserStorage interface {
	// GetUserByID retrieves a single user by their internal integer ID.
	// Returns db.NotFoundError if not found.
	GetUserByID(ctx context.Context, id int) (*db.PlatformUser, error)

	// CreateUser creates a new platform user record.
	// Returns db.ConstraintError if a unique constraint (like email) is violated.
	CreateUser(ctx context.Context, data *db.PlatformUser) (*db.PlatformUser, error)

	// UpdateUser updates specific fields of a user identified by ID using a map.
	// Returns db.NotFoundError if the user ID doesn't exist.
	// Returns db.ConstraintError if the update violates a unique constraint.
	UpdateUser(ctx context.Context, id int, updateData map[string]interface{}) (*db.PlatformUser, error)

	// DeleteUserByID deletes a user by their internal integer ID.
	// Returns db.NotFoundError if the user ID doesn't exist.
	DeleteUserByID(ctx context.Context, id int) error

	// CountUsers returns the total count of users matching the provided filters.
	CountUsers(ctx context.Context, filters UserFilters) (int, error)

	// ListUsersPaginated retrieves a page of users matching the filters, ordered
	// consistently for cursor pagination (e.g., CreateTime DESC, ID ASC).
	ListUsersPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters UserFilters) ([]*db.PlatformUser, error)
}

// AppRoleStorage defines database operations specific to PlatformAppRole entities.
type AppRoleStorage interface {
	// GetAppRoleByID retrieves a single app role by its internal integer ID.
	// Returns db.NotFoundError if not found.
	GetAppRoleByID(ctx context.Context, id int) (*db.PlatformAppRole, error)

	// CreateAppRole creates a new platform app role record.
	// Returns db.ConstraintError if a unique constraint (like app_id+title) is violated.
	CreateAppRole(ctx context.Context, data *db.PlatformAppRole) (*db.PlatformAppRole, error)

	// UpdateAppRole updates specific fields of an app role identified by ID using a map.
	// Returns db.NotFoundError if the role ID doesn't exist.
	// Returns db.ConstraintError if the update violates a unique constraint.
	UpdateAppRole(ctx context.Context, id int, updateData map[string]interface{}) (*db.PlatformAppRole, error)

	// DeleteAppRoleByID deletes an app role by its internal integer ID.
	// Returns db.NotFoundError if the role ID doesn't exist.
	// May return db.ConstraintError if FK constraints prevent deletion (e.g., tokens referencing it).
	DeleteAppRoleByID(ctx context.Context, id int) error

	// CountAppRoles returns the total count of app roles matching the provided filters.
	CountAppRoles(ctx context.Context, filters AppRoleFilters) (int, error)

	// ListAppRolesPaginated retrieves a page of app roles matching the filters, ordered
	// consistently for cursor pagination (e.g., CreateTime DESC, ID ASC).
	ListAppRolesPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters AppRoleFilters) ([]*db.PlatformAppRole, error)
}

// TokenStorage defines database operations specific to PlatformToken entities.
type TokenStorage interface {
	// GetTokenByID retrieves a single token by its internal integer ID.
	// Returns db.NotFoundError if not found.
	GetTokenByID(ctx context.Context, id int) (*db.PlatformToken, error)

	// GetTokenByPublicID retrieves a single token by its public ID string.
	// Returns db.NotFoundError if not found.
	GetTokenByPublicID(ctx context.Context, publicID string) (*db.PlatformToken, error) // Often useful

	// CreateToken creates a new platform token record.
	// Assumes secret hash has been computed by the service layer.
	// Returns db.ConstraintError if a unique constraint (like public_id) is violated.
	// Requires OwnerID in data (corresponding Ent edge must be 'owner').
	CreateToken(ctx context.Context, data *db.PlatformToken, roleID int) (*db.PlatformToken, error)

	// ----- UPDATE START -----
	// UpdateTokenRole updates only the role associated with a token.
	// Returns db.NotFoundError if the token ID doesn't exist.
	// Returns db.ConstraintError if the newRoleID doesn't exist or violates constraints.
	UpdateTokenRole(ctx context.Context, id int, newRoleID int) (*db.PlatformToken, error) // Renamed & Signature Changed from UpdateToken
	// ----- UPDATE END -----

	// DeleteTokenByID deletes a token by its internal integer ID.
	// Returns db.NotFoundError if the token ID doesn't exist.
	DeleteTokenByID(ctx context.Context, id int) error

	// CountTokens returns the total count of tokens matching the provided filters.
	CountTokens(ctx context.Context, filters TokenFilters) (int, error)

	// ListTokensPaginated retrieves a page of tokens matching the filters, ordered
	// consistently for cursor pagination (e.g., CreateTime DESC, ID ASC).
	ListTokensPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters TokenFilters) ([]*db.PlatformToken, error)
}

// FederatedIdentityStorage defines database operations specific to PlatformFederatedIdentity entities.
type FederatedIdentityStorage interface {
	// GetFederatedIdentityByID retrieves a single federated identity by its internal integer ID.
	// Returns db.NotFoundError if not found.
	GetFederatedIdentityByID(ctx context.Context, id int) (*db.PlatformFederatedIdentity, error)

	// DeleteFederatedIdentityByID deletes a federated identity by its internal integer ID.
	// Returns db.NotFoundError if the ID doesn't exist.
	DeleteFederatedIdentityByID(ctx context.Context, id int) error

	// CountFederatedIdentities returns the total count of federated identities matching the provided filters.
	CountFederatedIdentities(ctx context.Context, filters FederatedIdentityFilters) (int, error)

	// ListFederatedIdentitiesPaginated retrieves a page of federated identities matching the filters, ordered
	// consistently for cursor pagination (e.g., CreateTime DESC, ID ASC).
	ListFederatedIdentitiesPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters FederatedIdentityFilters) ([]*db.PlatformFederatedIdentity, error)
}

// AssignmentStorage defines database operations for managing role assignments between
// users/identities and app roles.
type AssignmentStorage interface {
	// AssignRoleToUser creates an entry linking a user to an app role.
	// Returns the created assignment record or db.ConstraintError on duplicate.
	AssignRoleToUser(ctx context.Context, userID int, roleID int) (*db.PlatformUserRoleAssignment, error)

	// RemoveRoleFromUser deletes the link between a user and an app role.
	// Returns error if the specific assignment doesn't exist (e.g., formatted not found error).
	RemoveRoleFromUser(ctx context.Context, userID int, roleID int) error

	// ListUserRoles retrieves the list of PlatformAppRole entities assigned to a specific user.
	// Filters (e.g., by app_id, assignment status, role status) can be applied.
	ListUserRoles(ctx context.Context, userID int, filters AssignmentFilters) ([]*db.PlatformAppRole, error)

	// AssignRoleToIdentity creates an entry linking a federated identity to an app role.
	// Returns the created assignment record or db.ConstraintError on duplicate.
	AssignRoleToIdentity(ctx context.Context, identityID int, roleID int) (*db.PlatformIdentityRoleAssignment, error)

	// RemoveRoleFromIdentity deletes the link between a federated identity and an app role.
	// Returns error if the specific assignment doesn't exist (e.g., formatted not found error).
	RemoveRoleFromIdentity(ctx context.Context, identityID int, roleID int) error

	// ListIdentityRoles retrieves the list of PlatformAppRole entities assigned to a specific federated identity.
	// Filters can be applied.
	ListIdentityRoles(ctx context.Context, identityID int, filters AssignmentFilters) ([]*db.PlatformAppRole, error)
}

// PlatformStorage is a combined interface that embeds all specific storage interfaces.
// This simplifies dependency injection for services that need access to multiple entity types
// and allows the concrete implementation (e.g., entStorage) to satisfy a single interface type.
type PlatformStorage interface {
	UserStorage
	AppRoleStorage
	TokenStorage // Includes the updated UpdateTokenRole method
	FederatedIdentityStorage
	AssignmentStorage
}

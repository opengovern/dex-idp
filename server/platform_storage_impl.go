package server

// This file contains the concrete implementation of storage interfaces
// (like UserStorage) using the Ent client.

import (
	"context"
	"time"

	// For error wrapping

	"entgo.io/ent/dialect/sql"             // For sql.OrderDesc/Asc
	"github.com/dexidp/dex/storage/ent/db" // Generated client package alias 'db'

	// Import specific entity packages for constants and predicates
	"github.com/dexidp/dex/storage/ent/db/platformuser"
	// Import potentially needed for error checking if not returning raw ent errors
	// "github.com/lib/pq"
)

// entStorage implements storage interfaces using an Ent client.
// It will implement UserStorage, RoleStorage, TokenStorage, etc.
type entStorage struct {
	client *db.Client
}

// NewEntStorage creates a new storage implementation backed by Ent.
// It should return all the storage interfaces it implements.
// For now, it returns UserStorage; add others as implemented (e.g., return struct).
func NewEntStorage(client *db.Client) UserStorage { // Update return type later if needed
	if client == nil {
		// Use panic here as this indicates a programming error during setup
		panic("ent client cannot be nil for entStorage implementation")
	}
	return &entStorage{client: client}
}

// --- UserStorage Implementation ---

func (s *entStorage) GetUserByID(ctx context.Context, id int) (*db.PlatformUser, error) {
	return s.client.PlatformUser.Get(ctx, id) // Errors (incl. NotFound) passed through
}

func (s *entStorage) CreateUser(ctx context.Context, data *db.PlatformUser) (*db.PlatformUser, error) {
	createOp := s.client.PlatformUser.Create().
		SetEmail(data.Email) // Assumes Email is validated by service

	if data.DisplayName != "" {
		createOp.SetDisplayName(data.DisplayName)
	}
	// Let IsActive default per schema

	return createOp.Save(ctx) // Errors (incl. Constraint) passed through
}

// UpdateUser implementation using map.
func (s *entStorage) UpdateUser(ctx context.Context, id int, updateData map[string]interface{}) (*db.PlatformUser, error) {
	updateOp := s.client.PlatformUser.UpdateOneID(id)
	setAny := false

	if val, ok := updateData["DisplayName"]; ok {
		if strVal, okStr := val.(string); okStr {
			updateOp.SetDisplayName(strVal)
			setAny = true
		}
		// Optional: return error on type mismatch? updateData["DisplayName"] = nil // Clear field?
	}
	if val, ok := updateData["IsActive"]; ok {
		if boolVal, okBool := val.(bool); okBool {
			updateOp.SetIsActive(boolVal)
			setAny = true
		}
	}
	// Add checks for other fields based on the map keys...

	if !setAny {
		// No valid update fields found in map, maybe return current state or error?
		// Returning current state prevents accidental empty updates.
		return s.client.PlatformUser.Get(ctx, id)
		// return nil, errors.New("no valid fields provided for update") // Alternative
	}

	return updateOp.Save(ctx) // Errors (incl. NotFound, Constraint) passed through
}

func (s *entStorage) DeleteUserByID(ctx context.Context, id int) error {
	return s.client.PlatformUser.DeleteOneID(id).Exec(ctx) // Errors (incl. NotFound) passed through
}

func (s *entStorage) CountUsers(ctx context.Context, filters UserFilters) (int, error) {
	query := s.client.PlatformUser.Query()
	query = applyUserFilters(query, filters) // Apply filters
	return query.Count(ctx)
}

// ListUsersPaginated implementation (updated signature and logic)
func (s *entStorage) ListUsersPaginated(ctx context.Context, limit int, afterTime *time.Time, afterID *int, filters UserFilters) ([]*db.PlatformUser, error) {
	query := s.client.PlatformUser.Query()
	query = applyUserFilters(query, filters) // applyUserFilters helper remains the same

	// Apply standard ordering for cursor pagination consistency
	query = query.Order(
		platformuser.ByCreateTime(sql.OrderDesc()),
		platformuser.ByID(sql.OrderAsc()),
	)

	// Apply WHERE clause for cursor pagination IF values were provided
	if afterTime != nil && afterID != nil {
		// Keyset pagination condition for (CreateTime DESC, ID ASC):
		// (create_time < cursorTime) OR (create_time == cursorTime AND id > cursorID)
		query = query.Where(platformuser.Or(
			platformuser.CreateTimeLT(*afterTime), // Dereference pointers
			platformuser.And(
				platformuser.CreateTimeEQ(*afterTime),
				platformuser.IDGT(*afterID),
			),
		))
	}

	// Apply limit (service requested limit+1)
	return query.Limit(limit).All(ctx)
}

// applyUserFilters is a helper to apply filtering predicates.
func applyUserFilters(q *db.PlatformUserQuery, filters UserFilters) *db.PlatformUserQuery {
	if filters.IsActive != nil {
		q = q.Where(platformuser.IsActiveEQ(*filters.IsActive))
	}
	if filters.EmailContains != "" {
		q = q.Where(platformuser.EmailContainsFold(filters.EmailContains))
	}
	// Add more filters here if defined in UserFilters struct
	return q
}

// --- RoleStorage Implementation (Placeholder) ---
// ...

// --- TokenStorage Implementation (Placeholder) ---
// ...

// --- FederatedIdentityStorage Implementation (Placeholder) ---
// ...

// --- Assignment Storage Implementations (Placeholder) ---
// ...

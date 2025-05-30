// Code generated by ent, DO NOT EDIT.

package platformuserroleassignment

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the platformuserroleassignment type in the database.
	Label = "platform_user_role_assignment"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldUpdateTime holds the string denoting the update_time field in the database.
	FieldUpdateTime = "update_time"
	// FieldIsActive holds the string denoting the is_active field in the database.
	FieldIsActive = "is_active"
	// FieldAssignedAt holds the string denoting the assigned_at field in the database.
	FieldAssignedAt = "assigned_at"
	// EdgeUser holds the string denoting the user edge name in mutations.
	EdgeUser = "user"
	// EdgeRole holds the string denoting the role edge name in mutations.
	EdgeRole = "role"
	// Table holds the table name of the platformuserroleassignment in the database.
	Table = "platform_user_role_assignments"
	// UserTable is the table that holds the user relation/edge.
	UserTable = "platform_user_role_assignments"
	// UserInverseTable is the table name for the PlatformUser entity.
	// It exists in this package in order to avoid circular dependency with the "platformuser" package.
	UserInverseTable = "platform_users"
	// UserColumn is the table column denoting the user relation/edge.
	UserColumn = "platform_user_user_role_assignments"
	// RoleTable is the table that holds the role relation/edge.
	RoleTable = "platform_user_role_assignments"
	// RoleInverseTable is the table name for the PlatformAppRole entity.
	// It exists in this package in order to avoid circular dependency with the "platformapprole" package.
	RoleInverseTable = "platform_app_roles"
	// RoleColumn is the table column denoting the role relation/edge.
	RoleColumn = "platform_app_role_user_assignments"
)

// Columns holds all SQL columns for platformuserroleassignment fields.
var Columns = []string{
	FieldID,
	FieldUpdateTime,
	FieldIsActive,
	FieldAssignedAt,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "platform_user_role_assignments"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"platform_app_role_user_assignments",
	"platform_user_user_role_assignments",
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultUpdateTime holds the default value on creation for the "update_time" field.
	DefaultUpdateTime func() time.Time
	// UpdateDefaultUpdateTime holds the default value on update for the "update_time" field.
	UpdateDefaultUpdateTime func() time.Time
	// DefaultIsActive holds the default value on creation for the "is_active" field.
	DefaultIsActive bool
	// DefaultAssignedAt holds the default value on creation for the "assigned_at" field.
	DefaultAssignedAt func() time.Time
)

// OrderOption defines the ordering options for the PlatformUserRoleAssignment queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByUpdateTime orders the results by the update_time field.
func ByUpdateTime(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldUpdateTime, opts...).ToFunc()
}

// ByIsActive orders the results by the is_active field.
func ByIsActive(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldIsActive, opts...).ToFunc()
}

// ByAssignedAt orders the results by the assigned_at field.
func ByAssignedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldAssignedAt, opts...).ToFunc()
}

// ByUserField orders the results by user field.
func ByUserField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newUserStep(), sql.OrderByField(field, opts...))
	}
}

// ByRoleField orders the results by role field.
func ByRoleField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newRoleStep(), sql.OrderByField(field, opts...))
	}
}
func newUserStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(UserInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, UserTable, UserColumn),
	)
}
func newRoleStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(RoleInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, RoleTable, RoleColumn),
	)
}

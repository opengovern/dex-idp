// Code generated by ent, DO NOT EDIT.

package db

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/dexidp/dex/storage/ent/db/platformapprole"
)

// PlatformAppRole is the model entity for the PlatformAppRole schema.
type PlatformAppRole struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreateTime holds the value of the "create_time" field.
	CreateTime time.Time `json:"create_time,omitempty"`
	// UpdateTime holds the value of the "update_time" field.
	UpdateTime time.Time `json:"update_time,omitempty"`
	// Identifier of the client application (client_id in Dex config) this role belongs to.
	AppID string `json:"app_id,omitempty"`
	// The unique name/title of the role within the scope of the application.
	Title string `json:"title,omitempty"`
	// Optional textual description of the role's purpose.
	Description *string `json:"description,omitempty"`
	// Numeric weight for sorting or prioritizing roles (e.g., lower value means higher priority).
	Weight int `json:"weight,omitempty"`
	// Indicates if this role definition is currently active and usable for assignments.
	IsActive bool `json:"is_active,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the PlatformAppRoleQuery when eager-loading is set.
	Edges        PlatformAppRoleEdges `json:"edges"`
	selectValues sql.SelectValues
}

// PlatformAppRoleEdges holds the relations/edges for other nodes in the graph.
type PlatformAppRoleEdges struct {
	// User assignments associated with this role.
	UserAssignments []*PlatformUserRoleAssignment `json:"user_assignments,omitempty"`
	// Federated identity assignments associated with this role.
	IdentityAssignments []*PlatformIdentityRoleAssignment `json:"identity_assignments,omitempty"`
	// Tokens directly assigned this single role.
	Tokens []*PlatformToken `json:"tokens,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [3]bool
}

// UserAssignmentsOrErr returns the UserAssignments value or an error if the edge
// was not loaded in eager-loading.
func (e PlatformAppRoleEdges) UserAssignmentsOrErr() ([]*PlatformUserRoleAssignment, error) {
	if e.loadedTypes[0] {
		return e.UserAssignments, nil
	}
	return nil, &NotLoadedError{edge: "user_assignments"}
}

// IdentityAssignmentsOrErr returns the IdentityAssignments value or an error if the edge
// was not loaded in eager-loading.
func (e PlatformAppRoleEdges) IdentityAssignmentsOrErr() ([]*PlatformIdentityRoleAssignment, error) {
	if e.loadedTypes[1] {
		return e.IdentityAssignments, nil
	}
	return nil, &NotLoadedError{edge: "identity_assignments"}
}

// TokensOrErr returns the Tokens value or an error if the edge
// was not loaded in eager-loading.
func (e PlatformAppRoleEdges) TokensOrErr() ([]*PlatformToken, error) {
	if e.loadedTypes[2] {
		return e.Tokens, nil
	}
	return nil, &NotLoadedError{edge: "tokens"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*PlatformAppRole) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case platformapprole.FieldIsActive:
			values[i] = new(sql.NullBool)
		case platformapprole.FieldID, platformapprole.FieldWeight:
			values[i] = new(sql.NullInt64)
		case platformapprole.FieldAppID, platformapprole.FieldTitle, platformapprole.FieldDescription:
			values[i] = new(sql.NullString)
		case platformapprole.FieldCreateTime, platformapprole.FieldUpdateTime:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the PlatformAppRole fields.
func (par *PlatformAppRole) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case platformapprole.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			par.ID = int(value.Int64)
		case platformapprole.FieldCreateTime:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field create_time", values[i])
			} else if value.Valid {
				par.CreateTime = value.Time
			}
		case platformapprole.FieldUpdateTime:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field update_time", values[i])
			} else if value.Valid {
				par.UpdateTime = value.Time
			}
		case platformapprole.FieldAppID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field app_id", values[i])
			} else if value.Valid {
				par.AppID = value.String
			}
		case platformapprole.FieldTitle:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field title", values[i])
			} else if value.Valid {
				par.Title = value.String
			}
		case platformapprole.FieldDescription:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field description", values[i])
			} else if value.Valid {
				par.Description = new(string)
				*par.Description = value.String
			}
		case platformapprole.FieldWeight:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field weight", values[i])
			} else if value.Valid {
				par.Weight = int(value.Int64)
			}
		case platformapprole.FieldIsActive:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field is_active", values[i])
			} else if value.Valid {
				par.IsActive = value.Bool
			}
		default:
			par.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the PlatformAppRole.
// This includes values selected through modifiers, order, etc.
func (par *PlatformAppRole) Value(name string) (ent.Value, error) {
	return par.selectValues.Get(name)
}

// QueryUserAssignments queries the "user_assignments" edge of the PlatformAppRole entity.
func (par *PlatformAppRole) QueryUserAssignments() *PlatformUserRoleAssignmentQuery {
	return NewPlatformAppRoleClient(par.config).QueryUserAssignments(par)
}

// QueryIdentityAssignments queries the "identity_assignments" edge of the PlatformAppRole entity.
func (par *PlatformAppRole) QueryIdentityAssignments() *PlatformIdentityRoleAssignmentQuery {
	return NewPlatformAppRoleClient(par.config).QueryIdentityAssignments(par)
}

// QueryTokens queries the "tokens" edge of the PlatformAppRole entity.
func (par *PlatformAppRole) QueryTokens() *PlatformTokenQuery {
	return NewPlatformAppRoleClient(par.config).QueryTokens(par)
}

// Update returns a builder for updating this PlatformAppRole.
// Note that you need to call PlatformAppRole.Unwrap() before calling this method if this PlatformAppRole
// was returned from a transaction, and the transaction was committed or rolled back.
func (par *PlatformAppRole) Update() *PlatformAppRoleUpdateOne {
	return NewPlatformAppRoleClient(par.config).UpdateOne(par)
}

// Unwrap unwraps the PlatformAppRole entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (par *PlatformAppRole) Unwrap() *PlatformAppRole {
	_tx, ok := par.config.driver.(*txDriver)
	if !ok {
		panic("db: PlatformAppRole is not a transactional entity")
	}
	par.config.driver = _tx.drv
	return par
}

// String implements the fmt.Stringer.
func (par *PlatformAppRole) String() string {
	var builder strings.Builder
	builder.WriteString("PlatformAppRole(")
	builder.WriteString(fmt.Sprintf("id=%v, ", par.ID))
	builder.WriteString("create_time=")
	builder.WriteString(par.CreateTime.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("update_time=")
	builder.WriteString(par.UpdateTime.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("app_id=")
	builder.WriteString(par.AppID)
	builder.WriteString(", ")
	builder.WriteString("title=")
	builder.WriteString(par.Title)
	builder.WriteString(", ")
	if v := par.Description; v != nil {
		builder.WriteString("description=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	builder.WriteString("weight=")
	builder.WriteString(fmt.Sprintf("%v", par.Weight))
	builder.WriteString(", ")
	builder.WriteString("is_active=")
	builder.WriteString(fmt.Sprintf("%v", par.IsActive))
	builder.WriteByte(')')
	return builder.String()
}

// PlatformAppRoles is a parsable slice of PlatformAppRole.
type PlatformAppRoles []*PlatformAppRole

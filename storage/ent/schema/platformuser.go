package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
	// time import correctly removed previously
)

// PlatformUser holds the schema definition for the PlatformUser entity.
// This represents a user recognized directly by the platform/RBAC system,
// globally unique by email address. Connector-specific links and origin info
// are stored in the PlatformFederatedIdentity entity.
type PlatformUser struct {
	ent.Schema
}

// Fields of the PlatformUser.
func (PlatformUser) Fields() []ent.Field {
	return []ent.Field{
		// 'id' field is implicitly created by Ent (int64 by default)

		field.String("email").
			NotEmpty().
			Unique().
			Comment("User's unique email address. Used as the primary identifier."),

		field.String("display_name").
			Optional().
			Comment("Optional display name for the user (e.g., Full Name)."),

		field.Bool("is_active").
			Default(true).
			Comment("Indicates whether the user account is active and allowed to log in."),

		// 'first_connector_id' removed - info now derivable from PlatformFederatedIdentity if needed.
		// 'first_federated_user_id' removed - info now derivable from PlatformFederatedIdentity if needed.

		field.Time("last_login").
			Optional().
			Nillable(). // Allows the DB column to be NULL
			Comment("Timestamp of the user's last known login recorded by this system."),
	}
}

// Mixin of the PlatformUser.
func (PlatformUser) Mixin() []ent.Mixin {
	return []ent.Mixin{
		// Adds create_time and update_time fields (using default Ent v0.12+ names)
		mixin.Time{},
	}
}

// Edges of the PlatformUser.
func (PlatformUser) Edges() []ent.Edge {
	return []ent.Edge{
		// O2M edge to the join table linking users to app roles.
		// Assumes PlatformUserRoleAssignment schema exists and defines the inverse edge.
		edge.To("user_role_assignments", PlatformUserRoleAssignment.Type).
			Comment("Holds the individual application role assignments for this user."),

		// O2M edge to the federated identities associated with this user.
		// Assumes PlatformFederatedIdentity schema exists and defines the inverse edge.
		edge.To("federated_identities", PlatformFederatedIdentity.Type).
			Comment("Holds the external identities (e.g., from Google, LDAP) linked to this user."),

		// O2M edge to tokens created by this user.
		// Assumes PlatformToken schema exists and defines the inverse edge ('creator').
		edge.To("created_tokens", PlatformToken.Type).
			Comment("Holds the platform tokens created by this user."),
	}
}

// Indexes of the PlatformUser.
func (PlatformUser) Indexes() []ent.Index {
	return []ent.Index{
		// Index on the email field for efficient lookups and uniqueness enforcement.
		index.Fields("email").
			Unique(), // Explicitly state unique constraint on index as well

		// Optional index if querying by active status often
		index.Fields("is_active"),
	}
}

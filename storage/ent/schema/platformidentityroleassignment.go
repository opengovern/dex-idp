package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// PlatformIdentityRoleAssignment holds the schema definition for the join table
// linking PlatformFederatedIdentities to their assigned PlatformAppRoles.
type PlatformIdentityRoleAssignment struct {
	ent.Schema
}

// Fields of the PlatformIdentityRoleAssignment.
func (PlatformIdentityRoleAssignment) Fields() []ent.Field {
	return []ent.Field{
		// platform_federated_identity_id defined implicitly via the 'identity' edge
		// app_role_id defined implicitly via the 'role' edge

		field.Bool("is_active").
			Default(true).
			Comment("Indicates if this specific role assignment instance is currently active."),

		field.Time("assigned_at").
			Default(time.Now).
			Immutable(). // Assignment time shouldn't change once created
			Comment("Timestamp when the role was initially assigned to the federated identity."),

		// update_time will be handled by the UpdateTime mixin
	}
}

// Mixin of the PlatformIdentityRoleAssignment.
func (PlatformIdentityRoleAssignment) Mixin() []ent.Mixin {
	return []ent.Mixin{
		// Only include UpdateTime mixin, as assigned_at handles creation time.
		mixin.UpdateTime{},
	}
}

// Edges of the PlatformIdentityRoleAssignment.
func (PlatformIdentityRoleAssignment) Edges() []ent.Edge {
	return []ent.Edge{
		// M-to-1 edge back to PlatformFederatedIdentity. Defines 'platform_federated_identity_id'.
		edge.From("identity", PlatformFederatedIdentity.Type).
			Ref("role_assignments"). // Assumes 'role_assignments' edge exists on PlatformFederatedIdentity schema
			// Field("platform_federated_identity_id"). // Ent likely infers this
			Unique().
			Required(),

		// M-to-1 edge back to PlatformAppRole. Defines 'app_role_id'.
		edge.From("role", PlatformAppRole.Type).
			Ref("identity_assignments"). // Assumes 'identity_assignments' edge exists on PlatformAppRole schema
			// Field("app_role_id"). // Ent likely infers this
			Unique().
			Required(),
	}
}

// Indexes of the PlatformIdentityRoleAssignment.
func (PlatformIdentityRoleAssignment) Indexes() []ent.Index {
	return []ent.Index{
		// Enforce uniqueness on the combination of federated identity and role
		index.Edges("identity", "role").
			Unique(),

		index.Fields("is_active"),
	}
}

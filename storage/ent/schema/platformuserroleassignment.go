package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// PlatformUserRoleAssignment holds the schema definition for the join table
// linking PlatformUsers to their assigned PlatformAppRoles.
type PlatformUserRoleAssignment struct {
	ent.Schema
}

// Fields of the PlatformUserRoleAssignment.
func (PlatformUserRoleAssignment) Fields() []ent.Field {
	return []ent.Field{
		// platform_user_id defined implicitly via the 'user' edge
		// app_role_id defined implicitly via the 'role' edge

		field.Bool("is_active").
			Default(true).
			Comment("Indicates if this specific role assignment instance is currently active."),

		field.Time("assigned_at").
			Default(time.Now).
			Immutable(). // Assignment time shouldn't change once created
			Comment("Timestamp when the role was initially assigned to the user."),

		// update_time will be handled by the UpdateTime mixin
	}
}

// Mixin of the PlatformUserRoleAssignment.
func (PlatformUserRoleAssignment) Mixin() []ent.Mixin {
	return []ent.Mixin{
		// Only include UpdateTime mixin, as assigned_at handles creation time.
		mixin.UpdateTime{},
	}
}

// Edges of the PlatformUserRoleAssignment.
func (PlatformUserRoleAssignment) Edges() []ent.Edge {
	return []ent.Edge{
		// M-to-1 edge back to PlatformUser. Defines 'platform_user_id'.
		edge.From("user", PlatformUser.Type).
			Ref("user_role_assignments"). // Matches edge name in PlatformUser schema
			// Field("platform_user_id").
			Unique().
			Required(),

		// M-to-1 edge back to PlatformAppRole. Defines 'app_role_id'.
		edge.From("role", PlatformAppRole.Type).
			Ref("user_assignments"). // Assumes 'user_assignments' edge exists on PlatformAppRole schema
			// Field("app_role_id").
			Unique().
			Required(),
	}
}

// Indexes of the PlatformUserRoleAssignment.
func (PlatformUserRoleAssignment) Indexes() []ent.Index {
	return []ent.Index{
		// Enforce uniqueness on the combination of user and role (prevent duplicate assignments)
		// Uses the edge names defined above.
		index.Edges("user", "role").
			Unique(),

		// Optional indexes on individual FKs (edges) if needed for specific queries
		// index.Edges("user"),
		// index.Edges("role"),
		index.Fields("is_active"),
	}
}

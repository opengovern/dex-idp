package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// PlatformToken holds the schema definition for the PlatformToken entity.
// Stores API tokens or service account tokens, each linked to one creator and one app role.
type PlatformToken struct {
	ent.Schema
}

// Fields of the PlatformToken.
func (PlatformToken) Fields() []ent.Field {
	return []ent.Field{
		// creator_id defined implicitly via the 'creator' edge
		// app_role_id defined implicitly via the 'role' edge

		field.String("public_id").
			NotEmpty().
			Unique().
			Comment("Unique, publicly visible identifier or prefix for the token (safe for logging)."),

		field.String("secret_hash").
			NotEmpty().
			Sensitive(). // Mark as sensitive to exclude from default logging/output
			Comment("Strong cryptographic hash (e.g., Argon2id) of the actual token secret."),

		field.Bool("is_active").
			Default(true).
			Comment("Indicates if the token is currently active and valid for use."),

		field.Time("expires_at").
			Optional().
			Nillable(). // Allows the column to be NULL in the DB (token never expires)
			Comment("Timestamp when the token becomes invalid. NULL indicates the token never expires."),
	}
}

// Mixin of the PlatformToken.
func (PlatformToken) Mixin() []ent.Mixin {
	return []ent.Mixin{
		// Adds create_time and update_time fields
		mixin.Time{},
	}
}

// Edges of the PlatformToken.
func (PlatformToken) Edges() []ent.Edge {
	return []ent.Edge{
		// M-to-1 edge back to the PlatformUser who created the token.
		// Defines the 'creator_id' column.
		edge.From("creator", PlatformUser.Type).
			Ref("created_tokens"). // Matches edge name in PlatformUser schema
			// Field("creator_id"). // Inferred by Ent
			Unique().   // Each token has exactly one creator
			Required(), // creator_id cannot be NULL

		// M-to-1 edge back to the PlatformAppRole defining the token's permissions.
		// Defines the 'app_role_id' column.
		edge.From("role", PlatformAppRole.Type).
			Ref("tokens"). // Matches edge name in PlatformAppRole schema
			// Field("app_role_id"). // Inferred by Ent
			Unique().   // Each token currently has exactly one role
			Required(), // app_role_id cannot be NULL

		// O2M edge to join table removed as token links directly to one role.
		// edge.To("role_assignments", PlatformTokenRoleAssignment.Type),
	}
}

// Indexes of the PlatformToken.
func (PlatformToken) Indexes() []ent.Index {
	return []ent.Index{
		// Index foreign keys for performance (Ent likely creates these from edges)
		index.Fields("creator_id"),
		index.Fields("app_role_id"), // Index for the direct FK to roles

		// Other useful indexes
		index.Fields("is_active"),
		index.Fields("expires_at"),
		// Note: Unique index on public_id is created by the field definition's Unique()
	}
}

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// PlatformToken holds the schema definition for the PlatformToken entity.
// Stores API tokens or service account tokens, each linked to one owner user and one app role.
type PlatformToken struct {
	ent.Schema
}

// Fields of the PlatformToken.
func (PlatformToken) Fields() []ent.Field {
	return []ent.Field{
		// --- FIELD ADDED TO MATCH EDGE DIRECTIVE ---
		field.Int("owner_id"), // Stores the foreign key for the required 'owner' edge
		// --- END FIELD ADDITION ---

		// app_role_id defined implicitly via the 'role' edge unless .Field() is used on that edge too

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
		// M-to-1 edge back to the PlatformUser who owns (created) the token.
		// Defines the 'owner_id' column.
		edge.From("owner", PlatformUser.Type).
			Ref("created_tokens"). // Matches edge name in PlatformUser schema
			Field("owner_id").     // Links to the owner_id field defined above
			Unique().              // Each token has exactly one owner
			Required(),            // owner_id cannot be NULL

		// M-to-1 edge back to the PlatformAppRole defining the token's permissions.
		// Defines the 'app_role_id' column.
		edge.From("role", PlatformAppRole.Type).
			Ref("tokens"). // Matches edge name in PlatformAppRole schema
			// Field("app_role_id"). // Field is implicitly created by Ent as role_id is not defined above
			Unique().   // Each token currently has exactly one role
			Required(), // app_role_id cannot be NULL
	}
}

// Indexes of the PlatformToken.
func (PlatformToken) Indexes() []ent.Index {
	return []ent.Index{
		// Index foreign keys. Use field name if defined via .Field(), otherwise use edge name.
		index.Fields("owner_id"), // Index the explicit FK field
		index.Edges("role"),      // Index the implicit FK field for the 'role' edge

		// Other useful indexes
		index.Fields("is_active"),
		index.Fields("expires_at"),
		// Note: Unique index on public_id is created by the field definition's Unique()
		// Note: Unique index on {owner_id, app_role_id} if needed would be index.Fields("owner_id").Edges("role").Unique()
	}
}

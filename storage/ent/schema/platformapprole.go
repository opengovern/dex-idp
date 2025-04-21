package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// PlatformAppRole holds the schema definition for the PlatformAppRole entity.
// Represents an application-specific role.
type PlatformAppRole struct {
	ent.Schema
}

// Fields of the PlatformAppRole.
func (PlatformAppRole) Fields() []ent.Field {
	return []ent.Field{
		field.String("app_id").
			NotEmpty().
			Comment("Identifier of the client application (client_id in Dex config) this role belongs to."),

		field.String("title").
			NotEmpty().
			Comment("The unique name/title of the role within the scope of the application."),

		field.String("description").
			Optional().
			Nillable().
			Comment("Optional textual description of the role's purpose."),

		field.Int("weight").
			Default(0).
			Comment("Numeric weight for sorting or prioritizing roles (e.g., lower value means higher priority)."),

		field.Bool("is_active").
			Default(true).
			Comment("Indicates if this role definition is currently active and usable for assignments."),
	}
}

// Mixin of the PlatformAppRole.
func (PlatformAppRole) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{}, // Adds create_time and update_time
	}
}

// Edges of the PlatformAppRole.
func (PlatformAppRole) Edges() []ent.Edge {
	return []ent.Edge{
		// O2M edge to the join table linking users to this role.
		edge.To("user_assignments", PlatformUserRoleAssignment.Type).
			Comment("User assignments associated with this role."),

		// O2M edge to the join table linking federated identities to this role.
		edge.To("identity_assignments", PlatformIdentityRoleAssignment.Type).
			Comment("Federated identity assignments associated with this role."),

		// O2M edge linking back to PlatformTokens that use this role directly.
		edge.To("tokens", PlatformToken.Type).
			Comment("Tokens directly assigned this single role."),

		// O2M edge to token assignment join table REMOVED.
		// edge.To("token_assignments", PlatformTokenRoleAssignment.Type),
	}
}

// Indexes of the PlatformAppRole.
func (PlatformAppRole) Indexes() []ent.Index {
	return []ent.Index{
		// Enforce uniqueness on the combination of app_id and title.
		index.Fields("app_id", "title").
			Unique(),

		index.Fields("app_id"), // Index for faster lookup by app
		index.Fields("is_active"),
	}
}

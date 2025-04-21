package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// PlatformFederatedIdentity holds the schema definition for the PlatformFederatedIdentity entity.
// It links a PlatformUser to a specific identity provided by an external connector.
type PlatformFederatedIdentity struct {
	ent.Schema
}

// Fields of the PlatformFederatedIdentity.
func (PlatformFederatedIdentity) Fields() []ent.Field {
	return []ent.Field{
		// platform_user_id defined via the 'user' edge

		field.String("connector_id").
			NotEmpty().
			Comment("Identifier of the Dex connector used for authentication."),

		// --- RENAMED FOR RESILIENCE ---
		field.String("connector_subject"). // *** RENAMED from "federated_user_id" ***
							NotEmpty().
							Comment("The unique subject identifier provided by the external connector (e.g., OIDC 'sub', SAML NameID, LDAP DN/uid)."),
		// --- END RENAME ---
	}
}

// Mixin of the PlatformFederatedIdentity.
func (PlatformFederatedIdentity) Mixin() []ent.Mixin {
	return []ent.Mixin{
		// Adds create_time and update_time fields
		mixin.Time{},
	}
}

// Edges of the PlatformFederatedIdentity.
func (PlatformFederatedIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		// M-to-1 edge back to PlatformUser. Defines 'platform_user_id'.
		edge.From("user", PlatformUser.Type).
			Ref("federated_identities"). // Matches the edge name defined in PlatformUser schema
			Unique().
			Required(),

		// O2M edge to the join table assigning roles to this specific identity.
		edge.To("role_assignments", PlatformIdentityRoleAssignment.Type).
			Comment("Holds the individual application role assignments specific to this federated identity."),
	}
}

// Indexes of the PlatformFederatedIdentity.
func (PlatformFederatedIdentity) Indexes() []ent.Index {
	return []ent.Index{
		// Enforce uniqueness on the combination of connector and the subject from that connector.
		// --- UPDATED FIELD NAME ---
		index.Fields("connector_id", "connector_subject"). // *** UPDATED from "federated_user_id" ***
									Unique(),
		// --- END UPDATE ---

		// Index the foreign key edge for efficient lookups of identities by user.
		index.Edges("user"), // Use index.Edges() for edge-defined FKs
	}
}

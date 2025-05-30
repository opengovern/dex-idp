// Code generated by ent, DO NOT EDIT.

package platformidentityroleassignment

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/dexidp/dex/storage/ent/db/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldLTE(FieldID, id))
}

// UpdateTime applies equality check predicate on the "update_time" field. It's identical to UpdateTimeEQ.
func UpdateTime(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldEQ(FieldUpdateTime, v))
}

// IsActive applies equality check predicate on the "is_active" field. It's identical to IsActiveEQ.
func IsActive(v bool) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldEQ(FieldIsActive, v))
}

// AssignedAt applies equality check predicate on the "assigned_at" field. It's identical to AssignedAtEQ.
func AssignedAt(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldEQ(FieldAssignedAt, v))
}

// UpdateTimeEQ applies the EQ predicate on the "update_time" field.
func UpdateTimeEQ(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldEQ(FieldUpdateTime, v))
}

// UpdateTimeNEQ applies the NEQ predicate on the "update_time" field.
func UpdateTimeNEQ(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldNEQ(FieldUpdateTime, v))
}

// UpdateTimeIn applies the In predicate on the "update_time" field.
func UpdateTimeIn(vs ...time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldIn(FieldUpdateTime, vs...))
}

// UpdateTimeNotIn applies the NotIn predicate on the "update_time" field.
func UpdateTimeNotIn(vs ...time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldNotIn(FieldUpdateTime, vs...))
}

// UpdateTimeGT applies the GT predicate on the "update_time" field.
func UpdateTimeGT(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldGT(FieldUpdateTime, v))
}

// UpdateTimeGTE applies the GTE predicate on the "update_time" field.
func UpdateTimeGTE(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldGTE(FieldUpdateTime, v))
}

// UpdateTimeLT applies the LT predicate on the "update_time" field.
func UpdateTimeLT(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldLT(FieldUpdateTime, v))
}

// UpdateTimeLTE applies the LTE predicate on the "update_time" field.
func UpdateTimeLTE(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldLTE(FieldUpdateTime, v))
}

// IsActiveEQ applies the EQ predicate on the "is_active" field.
func IsActiveEQ(v bool) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldEQ(FieldIsActive, v))
}

// IsActiveNEQ applies the NEQ predicate on the "is_active" field.
func IsActiveNEQ(v bool) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldNEQ(FieldIsActive, v))
}

// AssignedAtEQ applies the EQ predicate on the "assigned_at" field.
func AssignedAtEQ(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldEQ(FieldAssignedAt, v))
}

// AssignedAtNEQ applies the NEQ predicate on the "assigned_at" field.
func AssignedAtNEQ(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldNEQ(FieldAssignedAt, v))
}

// AssignedAtIn applies the In predicate on the "assigned_at" field.
func AssignedAtIn(vs ...time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldIn(FieldAssignedAt, vs...))
}

// AssignedAtNotIn applies the NotIn predicate on the "assigned_at" field.
func AssignedAtNotIn(vs ...time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldNotIn(FieldAssignedAt, vs...))
}

// AssignedAtGT applies the GT predicate on the "assigned_at" field.
func AssignedAtGT(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldGT(FieldAssignedAt, v))
}

// AssignedAtGTE applies the GTE predicate on the "assigned_at" field.
func AssignedAtGTE(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldGTE(FieldAssignedAt, v))
}

// AssignedAtLT applies the LT predicate on the "assigned_at" field.
func AssignedAtLT(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldLT(FieldAssignedAt, v))
}

// AssignedAtLTE applies the LTE predicate on the "assigned_at" field.
func AssignedAtLTE(v time.Time) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.FieldLTE(FieldAssignedAt, v))
}

// HasIdentity applies the HasEdge predicate on the "identity" edge.
func HasIdentity() predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, IdentityTable, IdentityColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasIdentityWith applies the HasEdge predicate on the "identity" edge with a given conditions (other predicates).
func HasIdentityWith(preds ...predicate.PlatformFederatedIdentity) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(func(s *sql.Selector) {
		step := newIdentityStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasRole applies the HasEdge predicate on the "role" edge.
func HasRole() predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, RoleTable, RoleColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasRoleWith applies the HasEdge predicate on the "role" edge with a given conditions (other predicates).
func HasRoleWith(preds ...predicate.PlatformAppRole) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(func(s *sql.Selector) {
		step := newRoleStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.PlatformIdentityRoleAssignment) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.PlatformIdentityRoleAssignment) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.PlatformIdentityRoleAssignment) predicate.PlatformIdentityRoleAssignment {
	return predicate.PlatformIdentityRoleAssignment(sql.NotPredicates(p))
}

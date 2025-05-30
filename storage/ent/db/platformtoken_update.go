// Code generated by ent, DO NOT EDIT.

package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/dexidp/dex/storage/ent/db/platformapprole"
	"github.com/dexidp/dex/storage/ent/db/platformtoken"
	"github.com/dexidp/dex/storage/ent/db/platformuser"
	"github.com/dexidp/dex/storage/ent/db/predicate"
)

// PlatformTokenUpdate is the builder for updating PlatformToken entities.
type PlatformTokenUpdate struct {
	config
	hooks    []Hook
	mutation *PlatformTokenMutation
}

// Where appends a list predicates to the PlatformTokenUpdate builder.
func (ptu *PlatformTokenUpdate) Where(ps ...predicate.PlatformToken) *PlatformTokenUpdate {
	ptu.mutation.Where(ps...)
	return ptu
}

// SetUpdateTime sets the "update_time" field.
func (ptu *PlatformTokenUpdate) SetUpdateTime(t time.Time) *PlatformTokenUpdate {
	ptu.mutation.SetUpdateTime(t)
	return ptu
}

// SetOwnerID sets the "owner_id" field.
func (ptu *PlatformTokenUpdate) SetOwnerID(i int) *PlatformTokenUpdate {
	ptu.mutation.SetOwnerID(i)
	return ptu
}

// SetNillableOwnerID sets the "owner_id" field if the given value is not nil.
func (ptu *PlatformTokenUpdate) SetNillableOwnerID(i *int) *PlatformTokenUpdate {
	if i != nil {
		ptu.SetOwnerID(*i)
	}
	return ptu
}

// SetPublicID sets the "public_id" field.
func (ptu *PlatformTokenUpdate) SetPublicID(s string) *PlatformTokenUpdate {
	ptu.mutation.SetPublicID(s)
	return ptu
}

// SetNillablePublicID sets the "public_id" field if the given value is not nil.
func (ptu *PlatformTokenUpdate) SetNillablePublicID(s *string) *PlatformTokenUpdate {
	if s != nil {
		ptu.SetPublicID(*s)
	}
	return ptu
}

// SetSecretHash sets the "secret_hash" field.
func (ptu *PlatformTokenUpdate) SetSecretHash(s string) *PlatformTokenUpdate {
	ptu.mutation.SetSecretHash(s)
	return ptu
}

// SetNillableSecretHash sets the "secret_hash" field if the given value is not nil.
func (ptu *PlatformTokenUpdate) SetNillableSecretHash(s *string) *PlatformTokenUpdate {
	if s != nil {
		ptu.SetSecretHash(*s)
	}
	return ptu
}

// SetIsActive sets the "is_active" field.
func (ptu *PlatformTokenUpdate) SetIsActive(b bool) *PlatformTokenUpdate {
	ptu.mutation.SetIsActive(b)
	return ptu
}

// SetNillableIsActive sets the "is_active" field if the given value is not nil.
func (ptu *PlatformTokenUpdate) SetNillableIsActive(b *bool) *PlatformTokenUpdate {
	if b != nil {
		ptu.SetIsActive(*b)
	}
	return ptu
}

// SetExpiresAt sets the "expires_at" field.
func (ptu *PlatformTokenUpdate) SetExpiresAt(t time.Time) *PlatformTokenUpdate {
	ptu.mutation.SetExpiresAt(t)
	return ptu
}

// SetNillableExpiresAt sets the "expires_at" field if the given value is not nil.
func (ptu *PlatformTokenUpdate) SetNillableExpiresAt(t *time.Time) *PlatformTokenUpdate {
	if t != nil {
		ptu.SetExpiresAt(*t)
	}
	return ptu
}

// ClearExpiresAt clears the value of the "expires_at" field.
func (ptu *PlatformTokenUpdate) ClearExpiresAt() *PlatformTokenUpdate {
	ptu.mutation.ClearExpiresAt()
	return ptu
}

// SetOwner sets the "owner" edge to the PlatformUser entity.
func (ptu *PlatformTokenUpdate) SetOwner(p *PlatformUser) *PlatformTokenUpdate {
	return ptu.SetOwnerID(p.ID)
}

// SetRoleID sets the "role" edge to the PlatformAppRole entity by ID.
func (ptu *PlatformTokenUpdate) SetRoleID(id int) *PlatformTokenUpdate {
	ptu.mutation.SetRoleID(id)
	return ptu
}

// SetRole sets the "role" edge to the PlatformAppRole entity.
func (ptu *PlatformTokenUpdate) SetRole(p *PlatformAppRole) *PlatformTokenUpdate {
	return ptu.SetRoleID(p.ID)
}

// Mutation returns the PlatformTokenMutation object of the builder.
func (ptu *PlatformTokenUpdate) Mutation() *PlatformTokenMutation {
	return ptu.mutation
}

// ClearOwner clears the "owner" edge to the PlatformUser entity.
func (ptu *PlatformTokenUpdate) ClearOwner() *PlatformTokenUpdate {
	ptu.mutation.ClearOwner()
	return ptu
}

// ClearRole clears the "role" edge to the PlatformAppRole entity.
func (ptu *PlatformTokenUpdate) ClearRole() *PlatformTokenUpdate {
	ptu.mutation.ClearRole()
	return ptu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (ptu *PlatformTokenUpdate) Save(ctx context.Context) (int, error) {
	ptu.defaults()
	return withHooks(ctx, ptu.sqlSave, ptu.mutation, ptu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (ptu *PlatformTokenUpdate) SaveX(ctx context.Context) int {
	affected, err := ptu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (ptu *PlatformTokenUpdate) Exec(ctx context.Context) error {
	_, err := ptu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ptu *PlatformTokenUpdate) ExecX(ctx context.Context) {
	if err := ptu.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ptu *PlatformTokenUpdate) defaults() {
	if _, ok := ptu.mutation.UpdateTime(); !ok {
		v := platformtoken.UpdateDefaultUpdateTime()
		ptu.mutation.SetUpdateTime(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ptu *PlatformTokenUpdate) check() error {
	if v, ok := ptu.mutation.PublicID(); ok {
		if err := platformtoken.PublicIDValidator(v); err != nil {
			return &ValidationError{Name: "public_id", err: fmt.Errorf(`db: validator failed for field "PlatformToken.public_id": %w`, err)}
		}
	}
	if v, ok := ptu.mutation.SecretHash(); ok {
		if err := platformtoken.SecretHashValidator(v); err != nil {
			return &ValidationError{Name: "secret_hash", err: fmt.Errorf(`db: validator failed for field "PlatformToken.secret_hash": %w`, err)}
		}
	}
	if ptu.mutation.OwnerCleared() && len(ptu.mutation.OwnerIDs()) > 0 {
		return errors.New(`db: clearing a required unique edge "PlatformToken.owner"`)
	}
	if ptu.mutation.RoleCleared() && len(ptu.mutation.RoleIDs()) > 0 {
		return errors.New(`db: clearing a required unique edge "PlatformToken.role"`)
	}
	return nil
}

func (ptu *PlatformTokenUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := ptu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(platformtoken.Table, platformtoken.Columns, sqlgraph.NewFieldSpec(platformtoken.FieldID, field.TypeInt))
	if ps := ptu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ptu.mutation.UpdateTime(); ok {
		_spec.SetField(platformtoken.FieldUpdateTime, field.TypeTime, value)
	}
	if value, ok := ptu.mutation.PublicID(); ok {
		_spec.SetField(platformtoken.FieldPublicID, field.TypeString, value)
	}
	if value, ok := ptu.mutation.SecretHash(); ok {
		_spec.SetField(platformtoken.FieldSecretHash, field.TypeString, value)
	}
	if value, ok := ptu.mutation.IsActive(); ok {
		_spec.SetField(platformtoken.FieldIsActive, field.TypeBool, value)
	}
	if value, ok := ptu.mutation.ExpiresAt(); ok {
		_spec.SetField(platformtoken.FieldExpiresAt, field.TypeTime, value)
	}
	if ptu.mutation.ExpiresAtCleared() {
		_spec.ClearField(platformtoken.FieldExpiresAt, field.TypeTime)
	}
	if ptu.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   platformtoken.OwnerTable,
			Columns: []string{platformtoken.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(platformuser.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ptu.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   platformtoken.OwnerTable,
			Columns: []string{platformtoken.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(platformuser.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if ptu.mutation.RoleCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   platformtoken.RoleTable,
			Columns: []string{platformtoken.RoleColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(platformapprole.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ptu.mutation.RoleIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   platformtoken.RoleTable,
			Columns: []string{platformtoken.RoleColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(platformapprole.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, ptu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{platformtoken.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	ptu.mutation.done = true
	return n, nil
}

// PlatformTokenUpdateOne is the builder for updating a single PlatformToken entity.
type PlatformTokenUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *PlatformTokenMutation
}

// SetUpdateTime sets the "update_time" field.
func (ptuo *PlatformTokenUpdateOne) SetUpdateTime(t time.Time) *PlatformTokenUpdateOne {
	ptuo.mutation.SetUpdateTime(t)
	return ptuo
}

// SetOwnerID sets the "owner_id" field.
func (ptuo *PlatformTokenUpdateOne) SetOwnerID(i int) *PlatformTokenUpdateOne {
	ptuo.mutation.SetOwnerID(i)
	return ptuo
}

// SetNillableOwnerID sets the "owner_id" field if the given value is not nil.
func (ptuo *PlatformTokenUpdateOne) SetNillableOwnerID(i *int) *PlatformTokenUpdateOne {
	if i != nil {
		ptuo.SetOwnerID(*i)
	}
	return ptuo
}

// SetPublicID sets the "public_id" field.
func (ptuo *PlatformTokenUpdateOne) SetPublicID(s string) *PlatformTokenUpdateOne {
	ptuo.mutation.SetPublicID(s)
	return ptuo
}

// SetNillablePublicID sets the "public_id" field if the given value is not nil.
func (ptuo *PlatformTokenUpdateOne) SetNillablePublicID(s *string) *PlatformTokenUpdateOne {
	if s != nil {
		ptuo.SetPublicID(*s)
	}
	return ptuo
}

// SetSecretHash sets the "secret_hash" field.
func (ptuo *PlatformTokenUpdateOne) SetSecretHash(s string) *PlatformTokenUpdateOne {
	ptuo.mutation.SetSecretHash(s)
	return ptuo
}

// SetNillableSecretHash sets the "secret_hash" field if the given value is not nil.
func (ptuo *PlatformTokenUpdateOne) SetNillableSecretHash(s *string) *PlatformTokenUpdateOne {
	if s != nil {
		ptuo.SetSecretHash(*s)
	}
	return ptuo
}

// SetIsActive sets the "is_active" field.
func (ptuo *PlatformTokenUpdateOne) SetIsActive(b bool) *PlatformTokenUpdateOne {
	ptuo.mutation.SetIsActive(b)
	return ptuo
}

// SetNillableIsActive sets the "is_active" field if the given value is not nil.
func (ptuo *PlatformTokenUpdateOne) SetNillableIsActive(b *bool) *PlatformTokenUpdateOne {
	if b != nil {
		ptuo.SetIsActive(*b)
	}
	return ptuo
}

// SetExpiresAt sets the "expires_at" field.
func (ptuo *PlatformTokenUpdateOne) SetExpiresAt(t time.Time) *PlatformTokenUpdateOne {
	ptuo.mutation.SetExpiresAt(t)
	return ptuo
}

// SetNillableExpiresAt sets the "expires_at" field if the given value is not nil.
func (ptuo *PlatformTokenUpdateOne) SetNillableExpiresAt(t *time.Time) *PlatformTokenUpdateOne {
	if t != nil {
		ptuo.SetExpiresAt(*t)
	}
	return ptuo
}

// ClearExpiresAt clears the value of the "expires_at" field.
func (ptuo *PlatformTokenUpdateOne) ClearExpiresAt() *PlatformTokenUpdateOne {
	ptuo.mutation.ClearExpiresAt()
	return ptuo
}

// SetOwner sets the "owner" edge to the PlatformUser entity.
func (ptuo *PlatformTokenUpdateOne) SetOwner(p *PlatformUser) *PlatformTokenUpdateOne {
	return ptuo.SetOwnerID(p.ID)
}

// SetRoleID sets the "role" edge to the PlatformAppRole entity by ID.
func (ptuo *PlatformTokenUpdateOne) SetRoleID(id int) *PlatformTokenUpdateOne {
	ptuo.mutation.SetRoleID(id)
	return ptuo
}

// SetRole sets the "role" edge to the PlatformAppRole entity.
func (ptuo *PlatformTokenUpdateOne) SetRole(p *PlatformAppRole) *PlatformTokenUpdateOne {
	return ptuo.SetRoleID(p.ID)
}

// Mutation returns the PlatformTokenMutation object of the builder.
func (ptuo *PlatformTokenUpdateOne) Mutation() *PlatformTokenMutation {
	return ptuo.mutation
}

// ClearOwner clears the "owner" edge to the PlatformUser entity.
func (ptuo *PlatformTokenUpdateOne) ClearOwner() *PlatformTokenUpdateOne {
	ptuo.mutation.ClearOwner()
	return ptuo
}

// ClearRole clears the "role" edge to the PlatformAppRole entity.
func (ptuo *PlatformTokenUpdateOne) ClearRole() *PlatformTokenUpdateOne {
	ptuo.mutation.ClearRole()
	return ptuo
}

// Where appends a list predicates to the PlatformTokenUpdate builder.
func (ptuo *PlatformTokenUpdateOne) Where(ps ...predicate.PlatformToken) *PlatformTokenUpdateOne {
	ptuo.mutation.Where(ps...)
	return ptuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (ptuo *PlatformTokenUpdateOne) Select(field string, fields ...string) *PlatformTokenUpdateOne {
	ptuo.fields = append([]string{field}, fields...)
	return ptuo
}

// Save executes the query and returns the updated PlatformToken entity.
func (ptuo *PlatformTokenUpdateOne) Save(ctx context.Context) (*PlatformToken, error) {
	ptuo.defaults()
	return withHooks(ctx, ptuo.sqlSave, ptuo.mutation, ptuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (ptuo *PlatformTokenUpdateOne) SaveX(ctx context.Context) *PlatformToken {
	node, err := ptuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (ptuo *PlatformTokenUpdateOne) Exec(ctx context.Context) error {
	_, err := ptuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ptuo *PlatformTokenUpdateOne) ExecX(ctx context.Context) {
	if err := ptuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ptuo *PlatformTokenUpdateOne) defaults() {
	if _, ok := ptuo.mutation.UpdateTime(); !ok {
		v := platformtoken.UpdateDefaultUpdateTime()
		ptuo.mutation.SetUpdateTime(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ptuo *PlatformTokenUpdateOne) check() error {
	if v, ok := ptuo.mutation.PublicID(); ok {
		if err := platformtoken.PublicIDValidator(v); err != nil {
			return &ValidationError{Name: "public_id", err: fmt.Errorf(`db: validator failed for field "PlatformToken.public_id": %w`, err)}
		}
	}
	if v, ok := ptuo.mutation.SecretHash(); ok {
		if err := platformtoken.SecretHashValidator(v); err != nil {
			return &ValidationError{Name: "secret_hash", err: fmt.Errorf(`db: validator failed for field "PlatformToken.secret_hash": %w`, err)}
		}
	}
	if ptuo.mutation.OwnerCleared() && len(ptuo.mutation.OwnerIDs()) > 0 {
		return errors.New(`db: clearing a required unique edge "PlatformToken.owner"`)
	}
	if ptuo.mutation.RoleCleared() && len(ptuo.mutation.RoleIDs()) > 0 {
		return errors.New(`db: clearing a required unique edge "PlatformToken.role"`)
	}
	return nil
}

func (ptuo *PlatformTokenUpdateOne) sqlSave(ctx context.Context) (_node *PlatformToken, err error) {
	if err := ptuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(platformtoken.Table, platformtoken.Columns, sqlgraph.NewFieldSpec(platformtoken.FieldID, field.TypeInt))
	id, ok := ptuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`db: missing "PlatformToken.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := ptuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, platformtoken.FieldID)
		for _, f := range fields {
			if !platformtoken.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("db: invalid field %q for query", f)}
			}
			if f != platformtoken.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := ptuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ptuo.mutation.UpdateTime(); ok {
		_spec.SetField(platformtoken.FieldUpdateTime, field.TypeTime, value)
	}
	if value, ok := ptuo.mutation.PublicID(); ok {
		_spec.SetField(platformtoken.FieldPublicID, field.TypeString, value)
	}
	if value, ok := ptuo.mutation.SecretHash(); ok {
		_spec.SetField(platformtoken.FieldSecretHash, field.TypeString, value)
	}
	if value, ok := ptuo.mutation.IsActive(); ok {
		_spec.SetField(platformtoken.FieldIsActive, field.TypeBool, value)
	}
	if value, ok := ptuo.mutation.ExpiresAt(); ok {
		_spec.SetField(platformtoken.FieldExpiresAt, field.TypeTime, value)
	}
	if ptuo.mutation.ExpiresAtCleared() {
		_spec.ClearField(platformtoken.FieldExpiresAt, field.TypeTime)
	}
	if ptuo.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   platformtoken.OwnerTable,
			Columns: []string{platformtoken.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(platformuser.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ptuo.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   platformtoken.OwnerTable,
			Columns: []string{platformtoken.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(platformuser.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if ptuo.mutation.RoleCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   platformtoken.RoleTable,
			Columns: []string{platformtoken.RoleColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(platformapprole.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ptuo.mutation.RoleIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   platformtoken.RoleTable,
			Columns: []string{platformtoken.RoleColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(platformapprole.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &PlatformToken{config: ptuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, ptuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{platformtoken.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	ptuo.mutation.done = true
	return _node, nil
}

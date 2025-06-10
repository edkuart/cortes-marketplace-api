package auth

import (
	"context"
	"errors"

	"github.com/rs/zerolog"
	"github.com/uptrace/bun"
)

var (
	ErrReturningUser = errors.New("failed to get user id")
)

type Repository interface {
	Insert(User) (int64, error)

	ByUsername(string) (User, error)
	ByEmail(string) (User, error)
	ByID(string) (User, error)
}

type repository struct {
	ctx context.Context
	db  *bun.DB
	log *zerolog.Logger
}

func NewRepository(ctx context.Context, db *bun.DB, logger *zerolog.Logger) Repository {
	return &repository{
		ctx,
		db,
		logger,
	}
}

func (r *repository) Insert(user User) (int64, error) {
	m := make(map[string]interface{})
	_, err := r.db.
		NewInsert().
		Model(&user).
		Returning("id").
		Exec(r.ctx, &m)
	if err != nil {
		return 0, err
	}

	userId, ok := m["id"].(int64)
	if !ok {
		return 0, ErrReturningUser
	}

	return userId, nil
}

func (r *repository) ByUsername(username string) (user User, err error) {
	err = r.db.
		NewSelect().
		Model(&user).
		Where("username = ?", username).
		Scan(r.ctx)
	if err != nil {
		return User{}, err
	}

	return user, err
}

func (r *repository) ByEmail(email string) (User, error) {
	var user User

	err := r.db.
		NewSelect().
		Model(&user).
		Where("email = ?", email).
		Scan(r.ctx)
	if err != nil {
		return User{}, err
	}

	return User{}, nil
}

func (r *repository) ByID(id string) (User, error) {
	var user User

	err := r.db.
		NewSelect().
		Model(&user).
		Where("id = ?", id).
		Scan(r.ctx)
	if err != nil {
		return User{}, err
	}

	return User{}, nil
}

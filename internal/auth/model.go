package auth

import (
	"time"

	"github.com/uptrace/bun"
)

const (
	AdminRole Role = "admin"
	UserRole  Role = "user"
)

type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`
	ID            int64     `bun:"id,pk,autoincrement"`
	Username      string    `bun:"username,unique,notnull"`
	Email         string    `bun:"email,unique,notnull"`
	PasswordHash  string    `bun:"password_hash,notnull"`
	IsActive      bool      `bun:"is_active,notnull"`
	CreatedAt     time.Time `bun:"created_at,default:current_timestamp"`
	UpdatedAt     time.Time `bun:"updated_at,default:current_timestamp"`
}

type (
	Role string

	// TokenResponse represents a response containing a JWT.
	TokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	// NewUser represents a new user in the database.
	NewUser struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Credentials holds the username and password received in requests
	Credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// RegisteredUser represents a response containing a user ID
	RegisteredUser struct {
		Message string `json:"message"`
		UserID  int64  `json:"user_id"`
	}
)

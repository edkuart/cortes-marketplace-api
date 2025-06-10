package auth

import (
	"errors"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

var (
	UsernameNotFound    = errors.New("username not found")
	CredentialsRequired = errors.New("username and password are required")
	InvalidUsername     = errors.New("invalid username")
	WrongPassword       = errors.New("wrong password")

	UserDataRequired   = errors.New("username, email, and password is required")
	FailedToHash       = errors.New("failed to hash password")
	FailedToCreateUser = errors.New("failed to create user")
)

type Service interface {
	CheckUsername(string) error
	CheckEmail(string) error
	Login(Credentials) error
	Register(NewUser) (int64, error)
	ResetPassword() error
}

type service struct {
	repo Repository
	log  *zerolog.Logger
}

func NewService(repo Repository, log *zerolog.Logger) Service {
	return &service{repo, log}
}

func (s *service) CheckUsername(username string) error {
	_, err := s.repo.ByUsername(username)
	if err != nil {
		return UsernameNotFound
	}
	return nil
}

func (s *service) CheckEmail(email string) error {
	_, err := s.repo.ByEmail(email)
	if err != nil {
		return UsernameNotFound
	}
	return nil
}

func (s *service) Login(creds Credentials) error {
	if creds.Username == "" || creds.Password == "" {
		return CredentialsRequired
	}

	user, err := s.repo.ByUsername(creds.Username)
	if err != nil {
		return InvalidUsername
	}

	// Compare the stored hashed password with the provided password.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password)); err != nil {
		return WrongPassword
	}

	return nil
}

func (s *service) Register(newUser NewUser) (userId int64, err error) {
	if newUser.Username == "" || newUser.Email == "" || newUser.Password == "" {
		return 0, UserDataRequired
	}

	// Hash the password before storing.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		return 0, FailedToHash
	}

	user := User{
		Username:     newUser.Username,
		Email:        newUser.Email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	userId, err = s.repo.Insert(user)
	if err != nil {
		return 0, FailedToCreateUser
	}

	return userId, nil
}

func (s *service) ResetPassword() error {
	return nil
}

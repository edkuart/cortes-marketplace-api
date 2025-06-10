package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog"
	"github.com/uptrace/bun"

	"github.com/edkuart/cortes-marketplace-api/config"
	"github.com/edkuart/cortes-marketplace-api/internal/response"
)

var (
	InvalidPayload    = "invalid request payload"
	FailedToken       = "failed to generate token"
	UserAlreadyExists = "user already exists"
	UserRegistered    = "user registered successfully"
)

type Handler interface {
	Login() http.HandlerFunc
	Register() http.HandlerFunc
}

type handler struct {
	svc  Service
	log  *zerolog.Logger
	conf config.Config
}

func NewHandler(ctx context.Context, db *bun.DB, log *zerolog.Logger, conf config.Config) Handler {
	authRepo := NewRepository(ctx, db, log)
	svc := NewService(authRepo, log)

	return &handler{svc, log, conf}
}

type CustomClaims struct {
	Roles []Role `json:"roles"`
	jwt.RegisteredClaims
}

func (h *handler) Login() http.HandlerFunc {
	var myClaims CustomClaims

	// ... to other stuff

	myClaims = CustomClaims{}
	h.log.Info().Interface("my_claims", myClaims).Send()

	customClaims := CustomClaims{
		// ... assignment
	}

	h.log.Info().Interface("my_claims", customClaims).Send()

	newClaims := new(CustomClaims)

	// ... to other stuff

	newClaims = &CustomClaims{}

	h.log.Info().Interface("my_claims", newClaims).Send()

	return func(w http.ResponseWriter, r *http.Request) {
		var creds Credentials

		// Decode the JSON request body.
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			response.Error(w, http.StatusBadRequest, InvalidPayload)
			return
		}

		err := h.svc.Login(creds)
		if err != nil {
			response.Error(w, http.StatusUnauthorized, err.Error())
			return
		}

		expDuration := h.conf.JwtExpDiration
		tokenResponse, err := h.getToken(creds.Username, expDuration)
		if err != nil {
			h.log.Error().Err(err).Msg(FailedToken)
			response.Error(w, http.StatusInternalServerError, FailedToken)
			return
		}

		// Return the token in the response.
		response.Success(w, http.StatusOK, tokenResponse)
	}
}

// Register creates a new user in the database.
func (h *handler) Register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var newUser NewUser

		// Decode the JSON request body.
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			response.Error(w, http.StatusBadRequest, InvalidPayload)
			return
		}

		// Check if the user already exists.
		err := h.svc.CheckUsername(newUser.Username)
		if err == nil {
			response.Error(w, http.StatusBadRequest, UserAlreadyExists)
			return
		}

		err = h.svc.CheckEmail(newUser.Email)
		if err == nil {
			response.Error(w, http.StatusBadRequest, UserAlreadyExists)
			return
		}

		userId, err := h.svc.Register(newUser)
		if err != nil {
			response.Error(w, http.StatusInternalServerError, err.Error())
			return
		}

		response.Success(w, http.StatusCreated, RegisteredUser{
			Message: UserRegistered,
			UserID:  userId,
		})
	}
}

func (h *handler) getToken(username string, expDuration time.Duration) (TokenResponse, error) {
	// Create a new JWT token with a 24-hour expiration.
	claims := CustomClaims{
		[]Role{AdminRole, UserRole},
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expDuration * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Audience:  jwt.ClaimStrings{"cm-web"},
			Issuer:    h.conf.JwtIssuer,
			Subject:   username,
		},
	}

	jwtKey := h.conf.JwtSecret
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		h.log.Error().Err(err).Str("token_string", tokenString).Msg(FailedToken)
		return TokenResponse{}, err
	}

	tokenResponse := TokenResponse{
		AccessToken:  tokenString,
		RefreshToken: tokenString,
	}

	return tokenResponse, nil
}

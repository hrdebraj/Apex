package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"apex/teamserver/internal/config"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrOperatorNotFound   = errors.New("operator not found")
	ErrUnauthorized       = errors.New("unauthorized")
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleReadOnly Role = "readonly"
)

type Operator struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	LastLogin time.Time `json:"last_login"`
}

type Claims struct {
	OperatorID string `json:"operator_id"`
	Username   string `json:"username"`
	Role       Role   `json:"role"`
	jwt.RegisteredClaims
}

type Service struct {
	db        *pgxpool.Pool
	jwtSecret []byte
	expiry    time.Duration
}

func NewService(db *pgxpool.Pool, cfg config.AuthConfig) *Service {
	return &Service{
		db:        db,
		jwtSecret: []byte(cfg.JWTSecret),
		expiry:    cfg.TokenExpiry,
	}
}

func (s *Service) Login(ctx context.Context, username, password string) (string, *Operator, error) {
	var (
		op         Operator
		hashedPass string
	)

	err := s.db.QueryRow(ctx,
		`SELECT id, username, role, password_hash, created_at FROM operators WHERE username = $1`,
		username,
	).Scan(&op.ID, &op.Username, &op.Role, &hashedPass, &op.CreatedAt)

	if err != nil {
		return "", nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(password)); err != nil {
		return "", nil, ErrInvalidCredentials
	}

	_, err = s.db.Exec(ctx, `UPDATE operators SET last_login = NOW() WHERE id = $1`, op.ID)
	if err != nil {
		log.Warn().Err(err).Str("operator", op.Username).Msg("Failed to update last_login")
	}

	token, err := s.generateToken(&op)
	if err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}

	log.Info().Str("operator", op.Username).Str("role", string(op.Role)).Msg("Operator logged in")
	return token, &op, nil
}

func (s *Service) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, ErrUnauthorized
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrUnauthorized
	}
	return claims, nil
}

func (s *Service) CreateOperator(ctx context.Context, username, password string, role Role) (*Operator, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	op := &Operator{}
	err = s.db.QueryRow(ctx,
		`INSERT INTO operators (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role, created_at`,
		username, string(hash), string(role),
	).Scan(&op.ID, &op.Username, &op.Role, &op.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create operator: %w", err)
	}

	log.Info().Str("username", username).Str("role", string(role)).Msg("Operator created")
	return op, nil
}

func (s *Service) generateToken(op *Operator) (string, error) {
	claims := Claims{
		OperatorID: op.ID,
		Username:   op.Username,
		Role:       op.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "apex-teamserver",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

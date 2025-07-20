package database

import "errors"

var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrTenantExists   = errors.New("tenant already exists")
	ErrUserNotFound   = errors.New("user not found")
	ErrUserExists     = errors.New("user already exists")
)

package service

import "errors"

var (
	// ErrInvalidURI возникает когда URI некорректен
	ErrInvalidURI = errors.New("invalid URI")
	// ErrInvalidShortUUID возникает когда shortUUID слишком короткий
	ErrInvalidShortUUID = errors.New("short UUID is too short")
	// ErrNoOriginalURI возникает когда отсутствует заголовок X-Original-URI
	ErrNoOriginalURI = errors.New("no X-Original-URI header provided")
)

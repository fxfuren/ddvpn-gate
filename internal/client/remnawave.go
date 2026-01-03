package client

import (
	"context"
	"fmt"

	remapi "github.com/Jolymmiles/remnawave-api-go/v2/api"
)

// RemnawaveClient оборачивает SDK клиент Remnawave
type RemnawaveClient struct {
	client *remapi.ClientExt
}

// UserData содержит данные пользователя, необходимые для авторизации
type UserData struct {
	Username             string
	Tag                  string
	ExternalSquadUUID    string
	ActiveInternalSquads []InternalSquad
}

// InternalSquad представляет внутренний сквод пользователя
type InternalSquad struct {
	UUID string
	Name string
}

// NewRemnawaveClient создает новый клиент Remnawave
func NewRemnawaveClient(baseURL, token string) (*RemnawaveClient, error) {
	baseClient, err := remapi.NewClient(baseURL, remapi.StaticToken{Token: token})
	if err != nil {
		return nil, fmt.Errorf("failed to create remnawave client: %w", err)
	}

	client := remapi.NewClientExt(baseClient)

	return &RemnawaveClient{
		client: client,
	}, nil
}

// GetUserByShortUUID получает пользователя по короткому UUID
func (r *RemnawaveClient) GetUserByShortUUID(ctx context.Context, shortUUID string) (*UserData, error) {
	resp, err := r.client.Users().GetUserByShortUuid(ctx, shortUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by short uuid: %w", err)
	}

	// Обрабатываем тип ответа
	switch user := resp.(type) {
	case *remapi.UserResponse:
		return r.extractUserData(user), nil
	default:
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}
}

// extractUserData извлекает данные пользователя из ответа API
func (r *RemnawaveClient) extractUserData(resp *remapi.UserResponse) *UserData {
	userData := &UserData{
		Username: resp.Response.Username,
	}

	// Извлекаем тег (NilString тип)
	if !resp.Response.Tag.IsNull() {
		userData.Tag = resp.Response.Tag.Value
	}

	// Извлекаем external squad UUID (NilUUID тип - это uuid.UUID массив)
	if !resp.Response.ExternalSquadUuid.IsNull() {
		userData.ExternalSquadUUID = resp.Response.ExternalSquadUuid.Value.String()
	}

	// Извлекаем active internal squads
	for _, squad := range resp.Response.ActiveInternalSquads {
		internalSquad := InternalSquad{
			UUID: squad.UUID.String(),
			Name: squad.Name,
		}
		userData.ActiveInternalSquads = append(userData.ActiveInternalSquads, internalSquad)
	}

	return userData
}

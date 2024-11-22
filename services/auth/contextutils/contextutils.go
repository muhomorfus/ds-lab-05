package contextutils

import "context"

const (
	tokenCtxKey = "token"
	userCtxKey  = "user"
)

func GetToken(ctx context.Context) string {
	value, _ := ctx.Value(tokenCtxKey).(string)
	return value
}

func SetToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenCtxKey, token)
}

func GetUser(ctx context.Context) string {
	value, _ := ctx.Value(userCtxKey).(string)
	return value
}

func SetUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userCtxKey, user)
}

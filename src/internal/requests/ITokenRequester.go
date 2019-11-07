package requests

import "github.com/markzuber/msalgo/internal/msalbase"

type ITokenRequester interface {
	Execute() (*msalbase.TokenResponse, error)
}

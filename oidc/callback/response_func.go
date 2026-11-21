// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package callback

import (
	"net/http"

	"github.com/hashicorp/cap/oidc"
)

// SuccessResponseFunc is used by Callbacks to create a http response when the
// callback is successful.
//
// The function state parameter will contain the state that was returned as
// part of a successful oidc authentication response. The oidc.Token is the
// result of a successful token exchange with the provider.  The function
// should use the http.ResponseWriter to send back whatever content (headers,
// html, JSON, etc) it wishes to the client that originated the oidc flow.
//
// The oidc.Request associated with state has already been consumed when this
// function is called, so it must not be used to start or complete another
// authentication flow.
type SuccessResponseFunc func(state string, t oidc.Token, w http.ResponseWriter, req *http.Request)

// ErrorResponseFunc is used by Callbacks to create a http response when the
// callback fails.
//
// The function receives the state returned as part of the oidc authentication
// response.  It also gets parameters for the oidc authentication error response
// and/or the callback error raised while processing the request.  The function
// should use the http.ResponseWriter to send back whatever content (headers,
// html, JSON, etc) it wishes to the client that originated the oidc flow.
//
// The oidc.Request associated with state has already been consumed when this
// function is called, even when the error was returned by the provider rather
// than by the token exchange.  The request must not be used to start or
// complete another authentication flow.
type ErrorResponseFunc func(state string, respErr *AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request)

// AuthenErrorResponse represents Oauth2 error responses.  See:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthError
type AuthenErrorResponse struct {
	Error       string
	Description string
	Uri         string
}

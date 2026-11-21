// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/cap/oidc"
)

type extendedRequest struct {
	oidc.Request
	t oidc.Token
}

type requestCache struct {
	m sync.Mutex
	c map[string]extendedRequest
}

func newRequestCache() *requestCache {
	return &requestCache{
		c: map[string]extendedRequest{},
	}
}

// Read implements the callback.RequestReader interface.
func (rc *requestCache) Read(ctx context.Context, state string) (oidc.Request, error) {
	const op = "requestCache.Read"
	rc.m.Lock()
	defer rc.m.Unlock()
	if oidcRequest, ok := rc.c[state]; ok {
		if oidcRequest.Request != nil && oidcRequest.IsExpired() {
			delete(rc.c, state)
			return nil, fmt.Errorf("%s: state %s not found", op, state)
		}
		return oidcRequest, nil
	}
	return nil, fmt.Errorf("%s: state %s not found", op, state)
}

// Consume implements the callback.RequestConsumer interface.  It atomically
// removes the pending request so the state can only be used by one callback.
func (rc *requestCache) Consume(ctx context.Context, state string) (oidc.Request, error) {
	const op = "requestCache.Consume"
	rc.m.Lock()
	defer rc.m.Unlock()
	oidcRequest, ok := rc.c[state]
	if !ok || oidcRequest.Request == nil {
		return nil, fmt.Errorf("%s: state %s not found", op, state)
	}
	if oidcRequest.IsExpired() {
		delete(rc.c, state)
		return nil, fmt.Errorf("%s: state %s not found", op, state)
	}
	if consumer, ok := oidcRequest.Request.(oidc.RequestConsumer); ok {
		if err := consumer.Consume(); err != nil {
			delete(rc.c, state)
			return nil, fmt.Errorf("%s: state %s not found", op, state)
		}
	}
	delete(rc.c, state)
	return oidcRequest.Request, nil
}

func (rc *requestCache) Add(s oidc.Request) {
	rc.m.Lock()
	defer rc.m.Unlock()
	rc.c[s.State()] = extendedRequest{Request: s}
}

func (rc *requestCache) SetToken(id string, t oidc.Token) error {
	const op = "stateCache.SetToken"
	rc.m.Lock()
	defer rc.m.Unlock()
	if oidcRequest, ok := rc.c[id]; ok {
		if oidcRequest.Request != nil && oidcRequest.IsExpired() {
			delete(rc.c, id)
			return fmt.Errorf("%s: state %s not found (expired)", op, id)
		}
		rc.c[id] = extendedRequest{Request: oidcRequest.Request, t: t}
		return nil
	}
	// The callback handler consumes the pending request before invoking the
	// success function, so store the token under the consumed state.
	rc.c[id] = extendedRequest{t: t}
	return nil
}

func (rc *requestCache) Delete(id string) {
	rc.m.Lock()
	defer rc.m.Unlock()
	delete(rc.c, id)
}

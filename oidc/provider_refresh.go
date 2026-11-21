// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"
)

// ExchangeRefreshToken exchanges one refresh token at the provider's token
// endpoint. It does not persist a session generation; use RefreshRotator when
// the exchange must be generation-safe across retries, concurrent requests, or
// process restarts.
func (p *Provider) ExchangeRefreshToken(ctx context.Context, refreshToken RefreshToken) (*oauth2.Token, error) {
	const op = "Provider.ExchangeRefreshToken"
	if p == nil || p.config == nil {
		return nil, fmt.Errorf("%s: provider config is nil: %w", op, ErrNilParameter)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%s: context is nil: %w", op, ErrNilParameter)
	}
	if refreshToken == "" {
		return nil, fmt.Errorf("%s: %w", op, ErrMissingRefreshToken)
	}

	oidcCtx, err := p.HTTPClientContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create http client: %w", op, err)
	}
	oauth2Config := oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: string(p.config.ClientSecret),
		Endpoint:     p.provider.Endpoint(),
		Scopes:       p.config.Scopes,
	}

	// oauth2.ReuseTokenSource only refreshes an expired token. A refresh token
	// loaded from durable storage has no access-token deadline, so seed the
	// source with an explicitly expired access token.
	current := &oauth2.Token{
		RefreshToken: string(refreshToken),
		Expiry:       time.Now().Add(-time.Second),
	}
	token, err := oauth2Config.TokenSource(oidcCtx, current).Token()
	if err != nil {
		converted := p.convertError(err)
		if converted.Error() != err.Error() {
			// Keep the original oauth2 error available to the rotation state
			// machine so it can distinguish a provider rejection (no new
			// generation) from an ambiguous transport failure.
			err = errors.Join(converted, err)
		}
		return nil, fmt.Errorf("%s: unable to exchange refresh token with provider: %w", op, err)
	}
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("%s: %w", op, ErrMissingAccessToken)
	}
	return token, nil
}

// RefreshToken is an alias for ExchangeRefreshToken.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken RefreshToken) (*oauth2.Token, error) {
	return p.ExchangeRefreshToken(ctx, refreshToken)
}

// RotateToken exchanges current's refresh token through rotator and returns a
// new Tk only after the new generation is durably committed. The receiver is
// never modified, so a failed or uncertain commit cannot publish a token into
// the old session.
func (p *Provider) RotateToken(ctx context.Context, current *Tk, rotator *RefreshRotator, sessionID string) (*Tk, error) {
	const op = "Provider.RotateToken"
	if p == nil || p.config == nil {
		return nil, fmt.Errorf("%s: provider config is nil: %w", op, ErrNilParameter)
	}
	if current == nil {
		return nil, fmt.Errorf("%s: current token is nil: %w", op, ErrNilParameter)
	}
	if current.underlying == nil || current.RefreshToken() == "" {
		return nil, fmt.Errorf("%s: %w", op, ErrMissingRefreshToken)
	}
	if rotator == nil {
		return nil, fmt.Errorf("%s: refresh rotator is nil: %w", op, ErrNilParameter)
	}

	result, err := rotator.Rotate(ctx, sessionID, current.RefreshToken())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	idToken := current.IDToken()
	if raw, ok := result.Token.Extra("id_token").(string); ok && raw != "" {
		idToken = IDToken(raw)
	}
	nowFunc := current.nowFunc
	if nowFunc == nil {
		nowFunc = p.config.NowFunc
	}
	next, err := NewToken(idToken, result.Token, WithNow(nowFunc), WithTokenGeneration(result.Generation()))
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create refreshed token: %w", op, err)
	}
	for key, value := range current.additionalClaims {
		next.additionalClaims[key] = value
	}
	return next, nil
}

// RotateRefreshToken is an alias for RotateToken.
func (p *Provider) RotateRefreshToken(ctx context.Context, current *Tk, rotator *RefreshRotator, sessionID string) (*Tk, error) {
	return p.RotateToken(ctx, current, rotator, sessionID)
}

// ensure Provider can be used as the exchange implementation for a
// RefreshRotator without an adapter.
var _ RefreshTokenExchanger = (*Provider)(nil)

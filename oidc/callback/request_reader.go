// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package callback

import (
	"context"
	"errors"
	"sync"

	"github.com/hashicorp/cap/oidc"
)

// RequestReader defines an interface for finding and reading an oidc.Request
//
// Implementations must be concurrently safe, since the reader will likely be
// used within a concurrent http.Handler
type RequestReader interface {
	// Read an existing Request entry.  The returned request's State()
	// must match the state used to look it up. Implementations must be
	// concurrently safe, which likely means returning a deep copy.
	//
	// Single-use readers should implement RequestConsumer so handlers can
	// atomically look up and consume the request.  Read must not be relied on
	// to consume the request unless the implementation also implements
	// RequestConsumer.
	Read(ctx context.Context, state string) (oidc.Request, error)
}

// RequestConsumer is an optional interface for RequestReader implementations
// that can atomically look up and consume a request.  Consume must remove the
// request (or otherwise record it as consumed) before returning, so a
// concurrent or subsequent callback cannot consume it again.  Implementations
// which persist requests must also persist the consumed record so a process
// restart cannot make the request usable again.
type RequestConsumer interface {
	Consume(ctx context.Context, state string) (oidc.Request, error)
}

// RequestTaker is an optional alias style interface for readers which use
// Take rather than Consume to atomically remove a request.  Callback handlers
// support either name.
type RequestTaker interface {
	Take(ctx context.Context, state string) (oidc.Request, error)
}

// RequestReadDeleter is an optional alias style interface for readers which
// expose an atomic read-and-delete operation.
type RequestReadDeleter interface {
	ReadAndDelete(ctx context.Context, state string) (oidc.Request, error)
}

// RequestDeleter is an optional interface for RequestReader implementations
// which support deleting a request by state.  It is used as a fallback for
// readers which do not implement RequestConsumer.
type RequestDeleter interface {
	Delete(ctx context.Context, state string) error
}

// SingleRequestReader implements the RequestReader interface for a single request.
// It is concurrently safe.
type SingleRequestReader struct {
	Request oidc.Request
}

// Read returns its single request if the state matches Request.State() and
// consumes the request when it implements oidc.RequestConsumer.  Otherwise it
// returns an error of oidc.ErrNotFound.  It satisfies the RequestReader
// interface.  Read is concurrently safe.
func (sr *SingleRequestReader) Read(ctx context.Context, state string) (oidc.Request, error) {
	if sr.Request == nil {
		return nil, oidc.ErrNotFound
	}
	if sr.Request.State() != state {
		return nil, oidc.ErrNotFound
	}
	if consumer, ok := sr.Request.(oidc.RequestConsumer); ok {
		if err := consumer.Consume(); err != nil {
			if errors.Is(err, oidc.ErrRequestConsumed) {
				return nil, oidc.ErrRequestConsumed
			}
			return nil, err
		}
	}
	return sr.Request, nil
}

// Consume implements RequestConsumer.  It returns the single request at most
// once for a matching state.  When the request implements oidc.RequestConsumer
// the request itself records the consumption, which prevents the same request
// from being used by a newly constructed SingleRequestReader (for example
// after a callback handler is rebuilt).
func (sr *SingleRequestReader) Consume(ctx context.Context, state string) (oidc.Request, error) {
	return sr.Read(ctx, state)
}

var (
	_ RequestReader   = (*SingleRequestReader)(nil)
	_ RequestConsumer = (*SingleRequestReader)(nil)
)

// consumingReader is the per-handler one-time gate.  It protects readers which
// do not implement RequestConsumer as well as concurrent callbacks which both
// look up a request before either marks it consumed.  Durable storage remains
// the responsibility of RequestConsumer implementations.
type consumingReader struct {
	rw RequestReader

	mu       sync.Mutex
	consumed map[string]struct{}
	inflight map[string]struct{}
}

func newConsumingReader(rw RequestReader) *consumingReader {
	return &consumingReader{
		rw:       rw,
		consumed: make(map[string]struct{}),
		inflight: make(map[string]struct{}),
	}
}

func consumeFailedFlow(oidcRequest oidc.Request) {
	switch consumer := oidcRequest.(type) {
	case oidc.RequestFlowConsumer:
		consumer.ConsumeAll()
	case interface{ ConsumeAll() error }:
		_ = consumer.ConsumeAll()
	}
}

func requestAlreadyConsumed(err error) bool {
	return errors.Is(err, oidc.ErrRequestConsumed)
}

// consume atomically reserves the state for this callback and then delegates
// to the underlying reader.  The state is marked in-flight before the lookup so
// concurrent callbacks cannot both win, even when the underlying reader is not
// a RequestConsumer.  Only a successfully returned request is recorded as
// consumed.
func (c *consumingReader) consume(ctx context.Context, state string) (oidc.Request, error) {
	c.mu.Lock()
	if _, ok := c.consumed[state]; ok {
		c.mu.Unlock()
		return nil, oidc.ErrRequestConsumed
	}
	if _, ok := c.inflight[state]; ok {
		c.mu.Unlock()
		return nil, oidc.ErrRequestConsumed
	}
	c.inflight[state] = struct{}{}
	c.mu.Unlock()

	oidcRequest, err := c.consumeFromReader(ctx, state)

	c.mu.Lock()
	delete(c.inflight, state)
	if err == nil && oidcRequest != nil {
		c.consumed[state] = struct{}{}
	}
	c.mu.Unlock()
	return oidcRequest, err
}

func (c *consumingReader) consumeFromReader(ctx context.Context, state string) (oidc.Request, error) {
	if consumer, ok := c.rw.(RequestConsumer); ok {
		return consumer.Consume(ctx, state)
	}
	if taker, ok := c.rw.(RequestTaker); ok {
		return taker.Take(ctx, state)
	}
	if readDeleter, ok := c.rw.(RequestReadDeleter); ok {
		return readDeleter.ReadAndDelete(ctx, state)
	}

	oidcRequest, err := c.rw.Read(ctx, state)
	if err != nil {
		return nil, err
	}
	if oidcRequest == nil {
		return nil, nil
	}
	if consumer, ok := oidcRequest.(oidc.RequestConsumer); ok {
		if err := consumer.Consume(); err != nil {
			if errors.Is(err, oidc.ErrRequestConsumed) {
				return nil, oidc.ErrRequestConsumed
			}
			return nil, err
		}
	}
	switch deleter := c.rw.(type) {
	case RequestDeleter:
		if err := deleter.Delete(ctx, state); err != nil {
			return nil, err
		}
	case interface{ Delete(string) error }:
		if err := deleter.Delete(state); err != nil {
			return nil, err
		}
	}
	return oidcRequest, nil
}

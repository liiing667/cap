// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package handler

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/saml"
)

// ACSHandlerFunc creates a handler function that handles a SAML
// ACS request
func ACSHandlerFunc(sp *saml.ServiceProvider) (http.HandlerFunc, error) {
	const op = "handler.ACSHandler"
	switch {
	case sp == nil:
		return nil, fmt.Errorf("%s: missing service provider", op)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		samlResp := r.PostForm.Get("SAMLResponse")
		if samlResp == "" {
			samlResp = r.Form.Get("SAMLResponse")
		}
		relayState := r.PostForm.Get("RelayState")
		if relayState == "" {
			relayState = r.Form.Get("RelayState")
		}

		requestID, requestIDErr := saml.ResponseRequestID(samlResp)
		state, hasState := sp.RequestState(requestID)
		if hasState {
			res, err := sp.ParseACSResponse(
				samlResp,
				requestID,
				relayState,
				saml.RequireRequestState(),
				saml.WithContext(r.Context()),
			)
			if err != nil {
				state, _ = sp.RequestState(requestID)
				stage := state.FailureStage
				if stage == "" {
					switch {
					case state.Consumed():
						stage = "consumed"
					case state.Cancelled():
						stage = "cancelled"
					default:
						stage = "acs-admission"
					}
				}
				writeACSHeaders(w, requestID, saml.RelayStateDigest(relayState), stage, state)
				fmt.Printf(
					"failed to handle SAML response: %s: %s\n",
					state.Report(),
					err.Error(),
				)
				http.Error(w, "failed to handle SAML response", http.StatusUnauthorized)
				return
			}
			writeACSHeaders(w, res.RequestID, res.RelayStateDigest, "", state)
			fmt.Fprintf(w, "Authenticated! %+v", res)
			return
		}

		if sp.HasPendingRequestState() {
			// A response may not detach itself from another tab's pending
			// request generation.
			stage := "unknown-request"
			reason := "response has no pending request state"
			if requestIDErr != nil {
				stage = "request-id"
				reason = requestIDErr.Error()
			}
			writeACSHeaders(w, requestID, saml.RelayStateDigest(relayState), stage, saml.RequestState{})
			fmt.Printf(
				"failed to handle SAML response: request_id=%q relay_state_digest=%q stage=%q: %s\n",
				requestID,
				saml.RelayStateDigest(relayState),
				stage,
				reason,
			)
			http.Error(w, "failed to handle SAML response", http.StatusUnauthorized)
			return
		}

		// Preserve the historical stateless fallback for callers that manage
		// AuthnRequests outside this package and never registered request
		// state. When the response carries InResponseTo, validate against that
		// value rather than a process-global placeholder. Once this provider
		// has a pending request, the strict path above takes precedence.
		fallbackID := requestID
		fallbackOpts := []saml.Option{saml.WithContext(r.Context())}
		if requestIDErr != nil {
			fallbackID = "responseID"
			fallbackOpts = append(fallbackOpts, saml.InsecureSkipRequestIDValidation())
		}
		res, err := sp.ParseResponse(samlResp, fallbackID, fallbackOpts...)
		if err != nil {
			fmt.Println("failed to handle SAML response:", err.Error())
			http.Error(w, "failed to handle SAML response", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "Authenticated! %+v", res)
	}, nil
}

func writeACSHeaders(
	w http.ResponseWriter,
	requestID string,
	relayStateDigest string,
	stage string,
	state saml.RequestState,
) {
	if requestID != "" {
		w.Header().Set("X-SAML-Request-ID", requestID)
	}
	if relayStateDigest != "" {
		w.Header().Set("X-SAML-RelayState-Digest", relayStateDigest)
	}
	if stage != "" {
		w.Header().Set("X-SAML-Rejection-Stage", stage)
	}
	if state.Generation != 0 {
		w.Header().Set("X-SAML-Request-Generation", fmt.Sprintf("%d", state.Generation))
	}
	if state.MetadataGeneration != 0 {
		w.Header().Set("X-SAML-Metadata-Generation", fmt.Sprintf("%d", state.MetadataGeneration))
	}
}

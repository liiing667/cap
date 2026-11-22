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
		relayState := r.PostForm.Get("RelayState")

		if !sp.HasRequestState() {
			// Preserve the historical handler behavior for callers that
			// manage AuthnRequests outside this package and therefore never
			// register recoverable request state.
			res, err := sp.ParseResponse(
				samlResp,
				"responseID",
				saml.InsecureSkipRequestIDValidation(),
			)
			if err != nil {
				fmt.Println("failed to handle SAML response:", err.Error())
				http.Error(w, "failed to handle SAML response", http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, "Authenticated! %+v", res)
			return
		}

		requestID, err := saml.ResponseRequestID(samlResp)
		if err != nil {
			fmt.Printf(
				"failed to handle SAML response: relay_state=%q: %s\n",
				relayState,
				err.Error(),
			)
			http.Error(w, "failed to handle SAML response", http.StatusUnauthorized)
			return
		}

		// Once this ServiceProvider has issued an AuthnRequest, every ACS
		// response must correlate to a recoverable request state.
		res, err := sp.ParseACSResponse(
			samlResp,
			requestID,
			relayState,
			saml.RequireRequestState(),
		)
		if err != nil {
			state, _ := sp.RequestState(requestID)
			fmt.Printf(
				"failed to handle SAML response: request_id=%q relay_state=%q issuer=%q generation=%d certificate_fingerprints=%v: %s\n",
				requestID,
				relayState,
				state.Issuer,
				state.MetadataGeneration,
				state.CertificateFingerprints,
				err.Error(),
			)
			http.Error(
				w, "failed to handle SAML response",
				http.StatusUnauthorized,
			)
			return
		}

		fmt.Fprintf(w, "Authenticated! %+v", res)
	}, nil
}

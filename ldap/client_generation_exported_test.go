// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package ldap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/cap/ldap"
	"github.com/jimlambrt/gldap"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Authenticate_GenerationIsScopedToUser(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()

	td := testdirectory.Start(t,
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"})
	td.SetUsers(users...)
	groups := []*gldap.Entry{
		testdirectory.NewGroup(t, "admin", []string{"alice"}),
	}
	td.SetGroups(groups...)

	url := fmt.Sprintf("ldaps://127.0.0.1:%d", td.Port())
	client, err := ldap.NewClient(testCtx, &ldap.ClientConfig{
		URLs:         []string{url},
		Certificates: []string{td.Cert()},
		DiscoverDN:   true,
		UserDN:       testdirectory.DefaultUserDN,
		GroupDN:      testdirectory.DefaultGroupDN,
	})
	require.NoError(t, err)
	defer client.Close(testCtx)

	aliceResult, err := client.Authenticate(testCtx, "alice", "password", ldap.WithGroups())
	require.NoError(t, err)
	require.NotNil(t, aliceResult)
	require.Len(t, aliceResult.Groups, 1)
	assert.Equal(t, groups[0].DN, aliceResult.Groups[0])
	assert.Equal(t, fmt.Sprintf("127.0.0.1:%d", td.Port()), aliceResult.Host)
	assert.Equal(t, url, aliceResult.URL)
	assert.Equal(t, "cn=alice,ou=people,dc=example,dc=org", aliceResult.BindDN)
	assert.Equal(t, aliceResult.BindDN, aliceResult.GroupBindDN)
	require.NotZero(t, aliceResult.Generation)

	bobResult, err := client.Authenticate(testCtx, "bob", "password", ldap.WithGroups())
	require.NoError(t, err)
	require.NotNil(t, bobResult)
	require.NotNil(t, bobResult.Groups)
	assert.Empty(t, bobResult.Groups)
	assert.NotContains(t, bobResult.Groups, groups[0].DN)
	assert.Equal(t, "cn=bob,ou=people,dc=example,dc=org", bobResult.BindDN)
	assert.Equal(t, bobResult.BindDN, bobResult.GroupBindDN)
	assert.Greater(t, bobResult.Generation, aliceResult.Generation)
}

func TestClient_Authenticate_StartTLSMultiURLReportsSelectedHost(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()

	td := testdirectory.Start(t,
		testdirectory.WithNoTLS(t),
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	users := testdirectory.NewUsers(t, []string{"alice"})
	td.SetUsers(users...)
	groups := []*gldap.Entry{
		testdirectory.NewGroup(t, "admin", []string{"alice"}),
	}
	td.SetGroups(groups...)

	selectedURL := fmt.Sprintf("ldap://localhost:%d", td.Port())
	client, err := ldap.NewClient(testCtx, &ldap.ClientConfig{
		// The first URL is deliberately unreachable so this authentication has
		// to fail over to the second URL and establish its own StartTLS channel.
		URLs:         []string{"ldap://127.0.0.1:1", selectedURL},
		Certificates: []string{td.Cert()},
		StartTLS:     true,
		DiscoverDN:   true,
		UserDN:       testdirectory.DefaultUserDN,
		GroupDN:      testdirectory.DefaultGroupDN,
	})
	require.NoError(t, err)
	defer client.Close(testCtx)

	result, err := client.Authenticate(testCtx, "alice", "password", ldap.WithGroups())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, fmt.Sprintf("localhost:%d", td.Port()), result.Host)
	assert.Equal(t, selectedURL, result.URL)
	assert.Equal(t, "cn=alice,ou=people,dc=example,dc=org", result.BindDN)
	assert.Equal(t, []string{groups[0].DN}, result.Groups)
}

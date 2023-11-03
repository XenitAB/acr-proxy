package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/optest"
	"golang.org/x/sync/errgroup"
)

func TestDefault(t *testing.T) {
	azureOp, cognitoOps, closeFn := testCreateProviders(t)
	defer closeFn(t)

	cognitoIssuers := []string{}
	for _, cognitoOp := range cognitoOps {
		cognitoIssuers = append(cognitoIssuers, cognitoOp.GetURL(t))
	}

	port := testAvailableTCPPort(t)
	cfg := config{
		azureIssuer:    azureOp.GetURL(t),
		azureAudience:  "ze-audience",
		azureTokenType: "JWT",
		azureValidationFn: func(c *azureClaims) error {
			return nil
		},
		cognitoRequiredScope:           "registry-credentials/regcred",
		AzureContainerRegistryUser:     "ze-user",
		AzureContainerRegistryPassword: "ze-pass",
		AllowedAzureTenantIDs:          []string{"ze-tenant-id"},
		AllowedCognitoIssuers:          cognitoIssuers,
		Address:                        fmt.Sprintf(":%d", port),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "ze-user" || password != "ze-pass" {
			w.WriteHeader(500)
			return
		}
		//nolint:errcheck // ignore
		w.Write([]byte("working!"))
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg.registryURL = srv.URL

	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return run(ctx, cfg)
	})

	testWaitForTCPPort(t, port)

	t.Run("GET /healthz", func(t *testing.T) {
		res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("POST /oauth2/exchange", func(t *testing.T) {
		res, err := http.PostForm(fmt.Sprintf("http://127.0.0.1:%d/oauth2/exchange", port), url.Values{
			"access_token": {"ze-token"},
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		defer res.Body.Close()

		require.JSONEq(t, `{"access_token": "ze-token", "refresh_token": "ze-token"}`, string(body))
	})

	t.Run("POST /oauth2/exchange without access_token", func(t *testing.T) {
		res, err := http.PostForm(fmt.Sprintf("http://127.0.0.1:%d/oauth2/exchange", port), url.Values{})
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, res.StatusCode)
	})

	t.Run("POST /oauth2/token", func(t *testing.T) {
		res, err := http.PostForm(fmt.Sprintf("http://127.0.0.1:%d/oauth2/token", port), url.Values{
			"refresh_token": {"ze-token"},
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		defer res.Body.Close()

		require.JSONEq(t, `{"access_token": "ze-token", "refresh_token": "ze-token"}`, string(body))
	})

	t.Run("POST /oauth2/token without refresh_token", func(t *testing.T) {
		res, err := http.PostForm(fmt.Sprintf("http://127.0.0.1:%d/oauth2/token", port), url.Values{})
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, res.StatusCode)
	})

	t.Run("HEAD /v2", func(t *testing.T) {
		res, err := http.Head(fmt.Sprintf("http://127.0.0.1:%d/v2", port))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("HEAD /v2/foobar/baz", func(t *testing.T) {
		res, err := http.Head(fmt.Sprintf("http://127.0.0.1:%d/v2/foobar/baz", port))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("GET /v2", func(t *testing.T) {
		res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/v2", port))
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
		require.Equal(t, "registry/2.0", res.Header.Get("Docker-Distribution-Api-Version"))
		expectedHost := fmt.Sprintf("127.0.0.1:%d", port)
		expectedWwwAuthenticateHeaderValue := fmt.Sprintf(`Basic realm="https://%s", service="%s"`, expectedHost, expectedHost)
		require.Equal(t, expectedWwwAuthenticateHeaderValue, res.Header.Get("Www-Authenticate"))
	})

	t.Run("GET /v2/foobar/noauth", func(t *testing.T) {
		res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/v2/foobar/noauth", port))
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
		require.Equal(t, "registry/2.0", res.Header.Get("Docker-Distribution-Api-Version"))
		expectedHost := fmt.Sprintf("127.0.0.1:%d", port)
		expectedWwwAuthenticateHeaderValue := fmt.Sprintf(`Basic realm="https://%s", service="%s"`, expectedHost, expectedHost)
		require.Equal(t, expectedWwwAuthenticateHeaderValue, res.Header.Get("Www-Authenticate"))
	})

	t.Run("GET /v2/foobar/auth invalid token", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v2/foobar/auth", port), http.NoBody)
		require.NoError(t, err)
		req.SetBasicAuth("will-be-ignored", "ze-fake")

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, res.StatusCode)
	})

	t.Run("GET /v2/foobar azure token", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v2/foobar", port), http.NoBody)
		require.NoError(t, err)
		req.SetBasicAuth("will-be-ignored", azureOp.GetToken(t).AccessToken)

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("GET /v2/foobar cognito token", func(t *testing.T) {
		for _, cognitoOp := range cognitoOps {
			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v2/foobar", port), http.NoBody)
			require.NoError(t, err)
			req.SetBasicAuth("will-be-ignored", cognitoOp.GetToken(t).AccessToken)

			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, res.StatusCode)
		}
	})

	cancel()
	err := g.Wait()
	require.NoError(t, err)
}

func TestAzureClaimsValidationFn(t *testing.T) {
	fn := newAzureClaimsValidationFn([]string{"ze-tenant-1", "ze-tenant-2", "ze-tenant-3"})
	t.Run("first tenant", func(t *testing.T) {
		err := fn(&azureClaims{
			Issuer:   "https://sts.windows.net/ze-tenant-1/",
			TenantId: "ze-tenant-1",
		})
		require.NoError(t, err)
	})

	t.Run("second tenant", func(t *testing.T) {
		err := fn(&azureClaims{
			Issuer:   "https://sts.windows.net/ze-tenant-2/",
			TenantId: "ze-tenant-2",
		})
		require.NoError(t, err)
	})

	t.Run("third tenant", func(t *testing.T) {
		err := fn(&azureClaims{
			Issuer:   "https://sts.windows.net/ze-tenant-3/",
			TenantId: "ze-tenant-3",
		})
		require.NoError(t, err)
	})

	t.Run("issuer needs to start with https://sts.windows.net/", func(t *testing.T) {
		err := fn(&azureClaims{
			Issuer: "ze-invalid-issuer",
		})
		require.ErrorContains(t, err, "issuer needs to start with https://sts.windows.net/, but received: ze-invalid-issuer")
	})

	t.Run("tenant from issuer and tid not matching", func(t *testing.T) {
		err := fn(&azureClaims{
			Issuer:   "https://sts.windows.net/ze-invalid-tenant-1/",
			TenantId: "ze-invalid-tenant-2",
		})
		require.ErrorContains(t, err, "expected to receive tenant id (ze-invalid-tenant-2) in the issuer (https://sts.windows.net/ze-invalid-tenant-1/) but received: ze-invalid-tenant-")
	})

	t.Run("tenant not trusted", func(t *testing.T) {
		err := fn(&azureClaims{
			Issuer:   "https://sts.windows.net/ze-invalid-tenant/",
			TenantId: "ze-invalid-tenant",
		})
		require.ErrorContains(t, err, "received tenant id isn't allowed")
	})
}

func TestCognitoClaimsValidationFn(t *testing.T) {
	fn := newCognitoClaimsValidationFn("ze-scope")
	t.Run("working", func(t *testing.T) {
		err := fn(&cognitoClaims{
			TokenUse: "access",
			Scope:    "ze-scope",
		})
		require.NoError(t, err)
	})

	t.Run("wrong token_use", func(t *testing.T) {
		err := fn(&cognitoClaims{
			TokenUse: "foo",
			Scope:    "ze-scope",
		})
		require.EqualError(t, err, "expected token_use to be access but received: foo")
	})

	t.Run("wrong scope", func(t *testing.T) {
		err := fn(&cognitoClaims{
			TokenUse: "access",
			Scope:    "ze-wrong-scope",
		})
		require.EqualError(t, err, "expected scope to be ze-scope but received: ze-wrong-scope")
	})
}

func TestNewConfig(t *testing.T) {
	envVarsToClear := []string{
		"ADDRESS",
		"AZURE_CONTAINER_REGISTRY_NAME",
		"AZURE_CONTAINER_REGISTRY_USER",
		"AZURE_CONTAINER_REGISTRY_PASSWORD",
		"ALLOWED_AZURE_TENANT_IDS",
		"ALLOWED_COGNITO_ISSUERS",
	}

	for _, envVar := range envVarsToClear {
		restore := testTempUnsetEnv(t, envVar)
		defer restore()
	}

	args := []string{
		"/foo/bar/bin",
		"--allowed-azure-tenant-ids",
		"ze-tenant-id-1",
		"ze-tenant-id-2",
		"--azure-container-registry-name",
		"ze-registry-name",
		"--azure-container-registry-user",
		"ze-user",
		"--azure-container-registry-password",
		"ze-password",
	}
	cfg, err := newConfig(args[1:])
	require.NoError(t, err)

	cfg.azureValidationFn = nil
	require.Equal(t, config{
		Address:                        ":8080",
		AzureContainerRegistryName:     "ze-registry-name",
		AzureContainerRegistryUser:     "ze-user",
		AzureContainerRegistryPassword: "ze-password",
		AllowedAzureTenantIDs:          []string{"ze-tenant-id-1", "ze-tenant-id-2"},

		azureIssuer:          "https://sts.windows.net/common",
		azureAudience:        "https://management.azure.com",
		azureTokenType:       "JWT",
		azureValidationFn:    nil,
		cognitoRequiredScope: "registry-credentials/regcred",
		registryURL:          "https://ze-registry-name.azurecr.io",
	}, cfg)
}

func testAvailableTCPPort(t *testing.T) int {
	t.Helper()

	var a *net.TCPAddr
	a, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(t, err)

	l, err := net.ListenTCP("tcp", a)
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	err = l.Close()
	require.NoError(t, err)

	return port
}

func testWaitForTCPPort(t *testing.T, port int) {
	t.Helper()

	for i := 0; i < 10; i++ {
		_, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 10*time.Millisecond)
		if err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	require.FailNow(t, "timed out waiting for tcp port")
}

func testTempUnsetEnv(t *testing.T, key string) func() {
	t.Helper()

	oldEnv := os.Getenv(key)
	os.Unsetenv(key)
	return func() { os.Setenv(key, oldEnv) }
}

func testCreateProviders(t *testing.T) (*optest.OPTesting, []*optest.OPTesting, func(t *testing.T)) {
	t.Helper()

	azureTestUser := map[string]optest.TestUser{
		"test": {
			Audience:           "ze-audience",
			Subject:            "test",
			Name:               "Test Testersson",
			GivenName:          "Test",
			FamilyName:         "Testersson",
			Locale:             "en-US",
			Email:              "test@testersson.com",
			AccessTokenKeyType: "JWT",
			IdTokenKeyType:     "JWT",
			ExtraAccessTokenClaims: map[string]interface{}{
				"tid": "ze-tenant-id",
			},
		},
	}

	azureOp := optest.NewTesting(t, optest.WithTestUsers(azureTestUser), optest.WithDefaultTestUser("test"))

	cognitoTestUser := map[string]optest.TestUser{
		"test": {
			Audience:           "ze-audience",
			Subject:            "test",
			Name:               "Test Testersson",
			GivenName:          "Test",
			FamilyName:         "Testersson",
			Locale:             "en-US",
			Email:              "test@testersson.com",
			AccessTokenKeyType: "JWT",
			IdTokenKeyType:     "JWT",
			ExtraAccessTokenClaims: map[string]interface{}{
				"token_use": "access",
				"scope":     "registry-credentials/regcred",
			},
		},
	}

	cognitoOps := []*optest.OPTesting{}
	for i := 0; i < 3; i++ {
		cognitoOp := optest.NewTesting(t, optest.WithTestUsers(cognitoTestUser), optest.WithDefaultTestUser("test"))
		cognitoOps = append(cognitoOps, cognitoOp)
	}

	closeFn := func(t *testing.T) {
		azureOp.Close(t)
		for _, cognitoOp := range cognitoOps {
			cognitoOp.Close(t)
		}
	}

	return azureOp, cognitoOps, closeFn
}

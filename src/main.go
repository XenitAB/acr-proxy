package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
	"github.com/xenitab/go-oidc-middleware/oidctoken"
	"github.com/xenitab/go-oidc-middleware/options"
	"golang.org/x/sync/errgroup"
)

func main() {
	cfg, err := newConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to parse config: %v\n", err)
		os.Exit(1)
	}

	err = run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "application returned an error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config) error {
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	tokenValidatorFn, err := newTokenValidator(cfg)
	if err != nil {
		return err
	}

	gin.SetMode(gin.ReleaseMode)
	gin.Default()
	r := gin.New()
	r.Use(gin.Recovery())

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r.Use(
		sloggin.NewWithFilters(
			logger,
			sloggin.IgnorePath("/healthz"),
		),
	)

	r.GET("/healthz", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	r.POST("/oauth2/exchange", func(c *gin.Context) {
		token := c.PostForm("access_token")
		if token == "" {
			//nolint:errcheck // ignore
			c.AbortWithError(http.StatusForbidden, fmt.Errorf("access_token empty"))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  token,
			"refresh_token": token,
		})
	})

	r.POST("/oauth2/token", func(c *gin.Context) {
		token := c.PostForm("refresh_token")
		if token == "" {
			//nolint:errcheck // ignore
			c.AbortWithError(http.StatusForbidden, fmt.Errorf("refresh_token empty"))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  token,
			"refresh_token": token,
		})
	})

	registryURL, err := url.Parse(cfg.registryURL)
	if err != nil {
		return err
	}

	rp := httputil.NewSingleHostReverseProxy(registryURL)
	rp.Director = func(r *http.Request) {
		r.Header.Del("Authorization")
		r.SetBasicAuth(cfg.AzureContainerRegistryUser, cfg.AzureContainerRegistryPassword)
		r.Host = registryURL.Host
		r.URL.Host = registryURL.Host
		r.URL.Scheme = registryURL.Scheme
	}

	v2 := r.Group("/v2")
	v2.HEAD("*path", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	v2.GET("*path", func(c *gin.Context) {
		if c.Request.URL.Path == "/v2" || c.Request.URL.Path == "/v2/" {
			c.Writer.Header().Set("Www-Authenticate", fmt.Sprintf(`Basic realm="https://%s", service="%s"`, c.Request.Host, c.Request.Host))
			c.Writer.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
			c.Status(http.StatusUnauthorized)
			return
		}

		_, token, ok := c.Request.BasicAuth()
		if !ok || token == "" {
			c.Writer.Header().Set("Www-Authenticate", fmt.Sprintf(`Basic realm="https://%s", service="%s"`, c.Request.Host, c.Request.Host))
			c.Writer.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
			//nolint:errcheck // ignore
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("unable to extract token from basic auth"))
			return
		}

		err = tokenValidatorFn(c.Request.Context(), token)
		if err != nil {
			//nolint:errcheck // ignore
			c.AbortWithError(http.StatusForbidden, fmt.Errorf("unable to validate the token: %v", err))
			return
		}

		rp.ServeHTTP(c.Writer, c.Request)
	})

	srv := &http.Server{
		Addr:    cfg.Address,
		Handler: r,
	}

	g.Go(func() error {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	})

	g.Go(func() error {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		return srv.Shutdown(shutdownCtx)
	})

	return g.Wait()
}

type config struct {
	Address                        string   `json:"address" arg:"--address,env:ADDRESS" default:":8080" help:"The address to listen on."`
	AzureContainerRegistryName     string   `json:"azure_container_registry_name" arg:"--azure-container-registry-name,env:AZURE_CONTAINER_REGISTRY_NAME,required" help:"The name of the Azure Container Registry that should be proxied."`
	AzureContainerRegistryUser     string   `json:"azure_container_registry_user" arg:"--azure-container-registry-user,env:AZURE_CONTAINER_REGISTRY_USER,required" help:"The user for the Azure Container Registry that should be proxied."`
	AzureContainerRegistryPassword string   `json:"azure_container_registry_password" arg:"--azure-container-registry-password,env:AZURE_CONTAINER_REGISTRY_PASSWORD,required" help:"The password for the Azure Container Registry that should be proxied."`
	AllowedAzureTenantIDs          []string `json:"allowed_azure_tenant_ids" arg:"--allowed-azure-tenant-ids,env:ALLOWED_AZURE_TENANT_IDS,required" help:"A list of the allowed Azure tenant ids that can use the proxy."`
	AllowedCognitoIssuers          []string `json:"allowed_cognito_issuers" arg:"--allowed-cognito-issuers,env:ALLOWED_COGNITO_ISSUERS" help:"A list of the allowed AWS Cognito issuers that can use the proxy."`

	azureIssuer          string
	azureAudience        string
	azureTokenType       string
	azureValidationFn    options.ClaimsValidationFn[azureClaims]
	cognitoRequiredScope string
	registryURL          string
}

func newConfig(args []string) (config, error) {
	cfg := config{
		azureTokenType:       "JWT",
		azureIssuer:          "https://sts.windows.net/common",
		azureAudience:        "https://management.azure.com",
		cognitoRequiredScope: "registry-credentials/regcred",
	}

	parser, err := arg.NewParser(arg.Config{
		Program:   "acr-proxy",
		IgnoreEnv: false,
	}, &cfg)
	if err != nil {
		return config{}, err
	}

	err = parser.Parse(args)
	if err != nil {
		return config{}, err
	}

	cfg.registryURL = fmt.Sprintf("https://%s.azurecr.io", cfg.AzureContainerRegistryName)
	cfg.azureValidationFn = newAzureClaimsValidationFn(cfg.AllowedAzureTenantIDs)

	return cfg, nil
}

type azureClaims struct {
	Aio                                 string    `json:"aio"`
	ApplicationID                       string    `json:"appid"`
	ApplicationIDACR                    string    `json:"appidacr"`
	Audience                            []string  `json:"aud"`
	ExpiresAt                           time.Time `json:"exp"`
	Idp                                 string    `json:"idp"`
	IdpTyp                              string    `json:"idtyp"`
	IssuedAt                            time.Time `json:"iat"`
	Issuer                              string    `json:"iss"`
	ManagedIdentityResourceIDidentifier string    `json:"xms_mirid"`
	NotBefore                           time.Time `json:"nbf"`
	Oid                                 string    `json:"oid"`
	Rh                                  string    `json:"rh"`
	Subject                             string    `json:"sub"`
	TenantId                            string    `json:"tid"`
	TokenVersion                        string    `json:"ver"`
	Uti                                 string    `json:"uti"`
}

func newAzureClaimsValidationFn(allowedTenantIDs []string) options.ClaimsValidationFn[azureClaims] {
	return func(c *azureClaims) error {
		if !strings.HasPrefix(c.Issuer, "https://sts.windows.net/") {
			return fmt.Errorf("issuer needs to start with https://sts.windows.net/, but received: %s", c.Issuer)
		}
		tenantIDFromIssuer := strings.TrimPrefix(c.Issuer, "https://sts.windows.net/")
		tenantIDFromIssuer = strings.TrimSuffix(tenantIDFromIssuer, "/")

		if tenantIDFromIssuer != c.TenantId {
			return fmt.Errorf("expected to receive tenant id (%s) in the issuer (%s) but received: %s", c.TenantId, c.Issuer, tenantIDFromIssuer)
		}

		if !slices.Contains(allowedTenantIDs, tenantIDFromIssuer) {
			return fmt.Errorf("received tenant id isn't allowed")
		}

		return nil
	}
}

type cognitoClaims struct {
	Subject   string    `json:"sub"`
	TokenUse  string    `json:"token_use"`
	Scope     string    `json:"scope"`
	AuthTime  time.Time `json:"auth_time"`
	Issuer    string    `json:"iss"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	Version   int       `json:"version"`
	Jti       string    `json:"jti"`
	ClientID  string    `json:"client_id"`
}

func newCognitoClaimsValidationFn(requiredScope string) options.ClaimsValidationFn[cognitoClaims] {
	return func(c *cognitoClaims) error {
		if c.TokenUse != "access" {
			return fmt.Errorf("expected token_use to be access but received: %s", c.TokenUse)
		}

		if c.Scope != requiredScope {
			return fmt.Errorf("expected scope to be %s but received: %s", requiredScope, c.Scope)
		}

		return nil
	}
}

type tokenValidator func(ctx context.Context, tokenString string) error

func newTokenValidator(cfg config) (tokenValidator, error) {
	azureTenantValidator, err := oidctoken.New(
		cfg.azureValidationFn,
		options.WithRequiredTokenType(cfg.azureTokenType),
		options.WithIssuer(cfg.azureIssuer),
		options.WithRequiredAudience(cfg.azureAudience),
		options.WithDisableIssuerValidation(),
	)
	if err != nil {
		return nil, err
	}

	cognitoValidators := []*oidctoken.TokenHandler[cognitoClaims]{}
	for _, issuer := range cfg.AllowedCognitoIssuers {
		cognitoValidator, err := oidctoken.New(
			newCognitoClaimsValidationFn(cfg.cognitoRequiredScope),
			options.WithIssuer(issuer),
		)
		if err != nil {
			return nil, err
		}
		cognitoValidators = append(cognitoValidators, cognitoValidator)
	}

	validatorFn := func(ctx context.Context, tokenString string) error {
		_, err := azureTenantValidator.ParseToken(ctx, tokenString)
		if err == nil {
			return nil
		}

		for _, validator := range cognitoValidators {
			_, err := validator.ParseToken(ctx, tokenString)
			if err == nil {
				return nil
			}
		}

		return fmt.Errorf("unable to validate the token: %v", err)
	}

	return validatorFn, nil
}

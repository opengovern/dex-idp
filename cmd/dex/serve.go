package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"time"

	// External Dependencies (ensure versions match your go.mod)
	gosundheit "github.com/AppsFlyer/go-sundheit"
	"github.com/AppsFlyer/go-sundheit/checks"
	gosundheithttp "github.com/AppsFlyer/go-sundheit/http"
	"github.com/ghodss/yaml"
	grpcprometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	// Dex Internal Imports
	api "github.com/dexidp/dex/api/v2" // Use 'api' alias matching go_package
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/ent/db" // Import generated Ent client
	"github.com/dexidp/dex/storage/sql"    // Import sql storage types for config access
)

type serveOptions struct {
	// Config file path
	config string

	// Flags
	webHTTPAddr   string
	webHTTPSAddr  string
	telemetryAddr string
	grpcAddr      string
}

var buildInfo = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name:      "build_info",
		Namespace: "dex",
		Help:      "A metric with a constant '1' value labeled by version from which Dex was built.",
	},
	[]string{"version", "go_version", "platform"},
)

func commandServe() *cobra.Command {
	options := serveOptions{}

	cmd := &cobra.Command{
		Use:     "serve [flags] [config file]",
		Short:   "Launch Dex",
		Example: "dex serve config.yaml",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true

			options.config = args[0]

			return runServe(options)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&options.webHTTPAddr, "web-http-addr", "", "Web HTTP address")
	flags.StringVar(&options.webHTTPSAddr, "web-https-addr", "", "Web HTTPS address")
	flags.StringVar(&options.telemetryAddr, "telemetry-addr", "", "Telemetry address")
	flags.StringVar(&options.grpcAddr, "grpc-addr", "", "gRPC API address")

	return cmd
}

func runServe(options serveOptions) error {
	configFile := options.config
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %v", configFile, err)
	}

	// Assume 'Config' struct definition exists in config.go or similar within package main
	var c Config
	if err := yaml.Unmarshal(configData, &c); err != nil {
		return fmt.Errorf("error parse config file %s: %v", configFile, err)
	}

	applyConfigOverrides(options, &c)

	// Assume 'newLogger' function definition exists in logger.go or similar within package main
	logger, err := newLogger(c.Logger.Level, c.Logger.Format)
	if err != nil {
		return fmt.Errorf("invalid config: %v", err)
	}

	logger.Info(
		"Version info",
		"dex_version", version,
		slog.Group("go",
			"version", runtime.Version(),
			"os", runtime.GOOS,
			"arch", runtime.GOARCH,
		),
	)

	if c.Logger.Level != slog.LevelInfo {
		logger.Info("config using log level", "level", c.Logger.Level)
	}
	// Assume c.Validate() method exists on Config struct
	if err := c.Validate(); err != nil {
		return err
	}

	logger.Info("config issuer", "issuer", c.Issuer)

	prometheusRegistry := prometheus.NewRegistry()

	prometheusRegistry.MustRegister(buildInfo)
	recordBuildInfo() // Assume defined elsewhere

	err = prometheusRegistry.Register(collectors.NewGoCollector())
	if err != nil {
		return fmt.Errorf("failed to register Go runtime metrics: %v", err)
	}

	err = prometheusRegistry.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if err != nil {
		return fmt.Errorf("failed to register process metrics: %v", err)
	}

	grpcMetrics := grpcprometheus.NewServerMetrics()
	err = prometheusRegistry.Register(grpcMetrics)
	if err != nil {
		return fmt.Errorf("failed to register gRPC server metrics: %v", err)
	}

	// --- Standard Dex Storage Initialization ---
	// 's' implements storage.Storage (e.g., *sql.conn)
	s, err := c.Storage.Config.Open(logger)
	if err != nil {
		return fmt.Errorf("failed to initialize standard storage: %v", err)
	}
	defer s.Close()
	logger.Info("config storage", "storage_type", c.Storage.Type)

	// --- Apply Static Configs to Standard Storage 's' ---
	// Assume 'password' type and 'ToStorageConnector' func defined elsewhere in package main
	if len(c.StaticClients) > 0 {
		for i, client := range c.StaticClients {
			if client.Name == "" {
				return fmt.Errorf("invalid config: Name field is required for a client")
			}
			if client.ID == "" && client.IDEnv == "" {
				return fmt.Errorf("invalid config: ID or IDEnv field is required for a client")
			}
			if client.IDEnv != "" {
				if client.ID != "" {
					return fmt.Errorf("invalid config: ID and IDEnv fields are exclusive for client %q", client.ID)
				}
				c.StaticClients[i].ID = os.Getenv(client.IDEnv)
			}
			if client.Secret == "" && client.SecretEnv == "" && !client.Public {
				return fmt.Errorf("invalid config: Secret or SecretEnv field is required for client %q", client.ID)
			}
			if client.SecretEnv != "" {
				if client.Secret != "" {
					return fmt.Errorf("invalid config: Secret and SecretEnv fields are exclusive for client %q", client.ID)
				}
				c.StaticClients[i].Secret = os.Getenv(client.SecretEnv)
			}
			logger.Info("config static client", "client_name", client.Name)
		}
		s = storage.WithStaticClients(s, c.StaticClients)
	}
	if len(c.StaticPasswords) > 0 {
		passwords := make([]storage.Password, len(c.StaticPasswords))
		for i, p := range c.StaticPasswords {
			passwords[i] = storage.Password(p)
		} // Requires 'password' type definition
		s = storage.WithStaticPasswords(s, passwords, logger)
	}
	var storageConnectors []storage.Connector
	for _, staticConn := range c.StaticConnectors {
		if staticConn.ID == "" || staticConn.Name == "" || staticConn.Type == "" {
			return fmt.Errorf("invalid config: ID, Type and Name fields are required for a connector")
		}
		if staticConn.Config == nil {
			return fmt.Errorf("invalid config: no config field for connector %q", staticConn.ID)
		}
		logger.Info("config connector", "connector_id", staticConn.ID)
		conn, err := ToStorageConnector(staticConn) // Requires 'ToStorageConnector' func definition
		if err != nil {
			return fmt.Errorf("failed to initialize static connector %s: %v", staticConn.ID, err)
		}
		storageConnectors = append(storageConnectors, conn)
	}
	if c.EnablePasswordDB {
		storageConnectors = append(storageConnectors, storage.Connector{ID: server.LocalConnector, Name: "Email", Type: server.LocalConnector})
		logger.Info("config connector: local passwords enabled")
	}
	if len(storageConnectors) > 0 {
		s = storage.WithStaticConnectors(s, storageConnectors)
	}

	// --- BEGIN Initialize Separate Ent Client for Custom Platform Tables ---
	var entClient *db.Client // Declare entClient variable

	if c.Storage.Type == "postgres" {
		pgConfig, ok := c.Storage.Config.(*sql.Postgres)
		if !ok {
			return fmt.Errorf("storage type is postgres, but config is not *sql.Postgres type")
		}
		// Construct DSN - ensure fields on pgConfig match your actual struct
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			pgConfig.Host, pgConfig.Port, pgConfig.User, pgConfig.Password, pgConfig.Database, pgConfig.SSL.Mode)
		if pgConfig.ConnectionTimeout > 0 {
			dsn = fmt.Sprintf("%s connect_timeout=%d", dsn, pgConfig.ConnectionTimeout)
		}
		// Add other SSL params if needed: pgConfig.SSL.CAFile, pgConfig.SSL.CertFile, pgConfig.SSL.KeyFile

		logger.Info("connecting to postgres for custom platform tables via Ent", "host", pgConfig.Host, "database", pgConfig.Database)
		entClient, err = db.Open("postgres", dsn)
		if err != nil {
			return fmt.Errorf("failed to connect to postgres via ent for custom tables: %w", err)
		}
		defer func() {
			logger.Info("closing ent client connection pool for custom tables...")
			if err := entClient.Close(); err != nil {
				logger.Error("failed to close custom ent client", "err", err)
			}
		}()

		// Optional: Run Ent auto-migration on startup
		// logger.Info("running ent auto-migration for custom tables...")
		// migrateCtx, migrateCancel := context.WithTimeout(context.Background(), 1*time.Minute)
		// defer migrateCancel()
		// if err := entClient.Schema.Create(migrateCtx); err != nil {
		//     logger.Error("failed to run ent auto-migration for custom tables", "err", err)
		//     // Decide if fatal
		// }
		// logger.Info("custom table ent auto-migration complete.")

	} else {
		logger.Warn("storage type is not postgres, custom platform gRPC services will not be available")
	}
	// --- END Initialize Separate Ent Client ---

	// --- Main Server Config and Initialization ---
	// ... logging other config values ...
	if len(c.OAuth2.ResponseTypes) > 0 {
		logger.Info("config response types accepted", "response_types", c.OAuth2.ResponseTypes)
	}
	if c.OAuth2.SkipApprovalScreen {
		logger.Info("config skipping approval screen")
	}
	if c.OAuth2.PasswordConnector != "" {
		logger.Info("config using password grant connector", "password_connector", c.OAuth2.PasswordConnector)
	}
	if len(c.Web.AllowedOrigins) > 0 {
		logger.Info("config allowed origins", "origins", c.Web.AllowedOrigins)
	}

	now := func() time.Time { return time.Now().UTC() }
	healthChecker := gosundheit.New()

	serverConfig := server.Config{
		Storage:                s, // Use standard storage 's' for main server config
		Issuer:                 c.Issuer,
		AllowedGrantTypes:      c.OAuth2.GrantTypes,
		SupportedResponseTypes: c.OAuth2.ResponseTypes,
		SkipApprovalScreen:     c.OAuth2.SkipApprovalScreen,
		AlwaysShowLoginScreen:  c.OAuth2.AlwaysShowLoginScreen,
		PasswordConnector:      c.OAuth2.PasswordConnector,
		Headers:                c.Web.Headers.ToHTTPHeader(),
		AllowedOrigins:         c.Web.AllowedOrigins,
		AllowedHeaders:         c.Web.AllowedHeaders,
		Web:                    c.Frontend,
		Logger:                 logger,
		Now:                    now,
		PrometheusRegistry:     prometheusRegistry,
		HealthChecker:          healthChecker,
	}
	// ... setting expiry durations on serverConfig ...
	if d, err := time.ParseDuration(c.Expiry.SigningKeys); err == nil {
		serverConfig.RotateKeysAfter = d
	} else if c.Expiry.SigningKeys != "" {
		return fmt.Errorf("invalid signing keys expiry: %v", err)
	}
	if d, err := time.ParseDuration(c.Expiry.IDTokens); err == nil {
		serverConfig.IDTokensValidFor = d
	} else if c.Expiry.IDTokens != "" {
		return fmt.Errorf("invalid id token expiry: %v", err)
	}
	if d, err := time.ParseDuration(c.Expiry.AuthRequests); err == nil {
		serverConfig.AuthRequestsValidFor = d
	} else if c.Expiry.AuthRequests != "" {
		return fmt.Errorf("invalid auth request expiry: %v", err)
	}
	if d, err := time.ParseDuration(c.Expiry.DeviceRequests); err == nil {
		serverConfig.DeviceRequestsValidFor = d
	} else if c.Expiry.DeviceRequests != "" {
		return fmt.Errorf("invalid device request expiry: %v", err)
	}

	refreshTokenPolicy, err := server.NewRefreshTokenPolicy(logger, c.Expiry.RefreshTokens.DisableRotation, c.Expiry.RefreshTokens.ValidIfNotUsedFor, c.Expiry.RefreshTokens.AbsoluteLifetime, c.Expiry.RefreshTokens.ReuseInterval)
	if err != nil {
		return fmt.Errorf("invalid refresh token policy config: %v", err)
	}
	serverConfig.RefreshTokenPolicy = refreshTokenPolicy
	serverConfig.RealIPHeader = c.Web.ClientRemoteIP.Header
	serverConfig.TrustedRealIPCIDRs, err = c.Web.ClientRemoteIP.ParseTrustedProxies()
	if err != nil {
		return fmt.Errorf("failed to parse client remote IP settings: %v", err)
	}

	// Initialize main Dex server (which uses standard storage 's' via serverConfig)
	serv, err := server.NewServer(context.Background(), serverConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize main dex server: %v", err)
	}

	// --- Health Checker & Telemetry Setup --- (Same as before)
	telemetryRouter := http.NewServeMux()
	telemetryRouter.Handle("/metrics", promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}))
	{
		handler := gosundheithttp.HandleHealthJSON(healthChecker)
		telemetryRouter.Handle("/healthz", handler)
		telemetryRouter.HandleFunc("/healthz/live", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		telemetryRouter.Handle("/healthz/ready", handler)
	}
	healthChecker.RegisterCheck(&checks.CustomCheck{CheckName: "storage", CheckFunc: storage.NewCustomHealthCheckFunc(s, now)}, gosundheit.ExecutionPeriod(15*time.Second), gosundheit.InitiallyPassing(true))

	// --- oklog/run Group Setup ---
	var group run.Group

	// --- Telemetry Server ---
	if c.Telemetry.HTTP != "" {
		const name = "telemetry"
		logger.Info("listening on", "server", name, "address", c.Telemetry.HTTP)
		l, err := net.Listen("tcp", c.Telemetry.HTTP)
		if err != nil {
			return fmt.Errorf("listening (%s) on %s: %v", name, c.Telemetry.HTTP, err)
		}
		if c.Telemetry.EnableProfiling {
			pprofHandler(telemetryRouter)
		}
		httpSrv := &http.Server{Handler: telemetryRouter}
		// Use different var name than https server
		group.Add(func() error { return httpSrv.Serve(l) }, func(error) { _ = httpSrv.Shutdown(context.Background()) })
	}

	// --- Web HTTP Server ---
	if c.Web.HTTP != "" {
		const name = "http"
		logger.Info("listening on", "server", name, "address", c.Web.HTTP)
		l, err := net.Listen("tcp", c.Web.HTTP)
		if err != nil {
			return fmt.Errorf("listening (%s) on %s: %v", name, c.Web.HTTP, err)
		}
		httpSrv := &http.Server{Handler: serv}
		group.Add(func() error { return httpSrv.Serve(l) }, func(error) { _ = httpSrv.Shutdown(context.Background()) })
	}

	// --- Web HTTPS Server ---
	if c.Web.HTTPS != "" {
		const name = "https"
		logger.Info("listening on", "server", name, "address", c.Web.HTTPS)
		l, err := net.Listen("tcp", c.Web.HTTPS)
		if err != nil {
			return fmt.Errorf("listening (%s) on %s: %v", name, c.Web.HTTPS, err)
		}
		allowedTLSVersions := map[string]int{"1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}
		tlsMinVersion := tls.VersionTLS12
		if v, ok := allowedTLSVersions[c.Web.TLSMinVersion]; ok {
			tlsMinVersion = v
		}
		tlsMaxVersion := 0
		if v, ok := allowedTLSVersions[c.Web.TLSMaxVersion]; ok {
			tlsMaxVersion = v
		}
		allowedTLSCiphers := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384}
		baseTLSConfig := &tls.Config{MinVersion: uint16(tlsMinVersion), MaxVersion: uint16(tlsMaxVersion), CipherSuites: allowedTLSCiphers, PreferServerCipherSuites: true}
		tlsConfig, err := newTLSReloader(logger, c.Web.TLSCert, c.Web.TLSKey, "", baseTLSConfig) // Assume defined elsewhere
		if err != nil {
			return fmt.Errorf("invalid config: get HTTP TLS: %v", err)
		}
		httpsSrv := &http.Server{Handler: serv, TLSConfig: tlsConfig}
		group.Add(func() error { return httpsSrv.ServeTLS(l, "", "") }, func(error) { _ = httpsSrv.Shutdown(context.Background()) })
	}

	// --- gRPC Server Setup ---
	if c.GRPC.Addr != "" {
		logger.Info("listening on", "server", "grpc", "address", c.GRPC.Addr)

		grpcListener, err := net.Listen("tcp", c.GRPC.Addr)
		if err != nil {
			return fmt.Errorf("listening (grpc) on %s: %w", c.GRPC.Addr, err)
		}

		// --- gRPC TLS Options ---
		var grpcOptions []grpc.ServerOption
		if c.GRPC.TLSCert != "" {
			// ... logic for TLS config from baseConfig ... (same as before)
			allowedTLSVersions := map[string]int{"1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}
			tlsMinVersion := tls.VersionTLS12
			if v, ok := allowedTLSVersions[c.GRPC.TLSMinVersion]; ok {
				tlsMinVersion = v
			}
			tlsMaxVersion := 0
			if v, ok := allowedTLSVersions[c.GRPC.TLSMaxVersion]; ok {
				tlsMaxVersion = v
			}
			allowedTLSCiphers := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384}
			baseTLSConfig := &tls.Config{MinVersion: uint16(tlsMinVersion), MaxVersion: uint16(tlsMaxVersion), CipherSuites: allowedTLSCiphers, PreferServerCipherSuites: true}
			tlsConfig, err := newTLSReloader(logger, c.GRPC.TLSCert, c.GRPC.TLSKey, c.GRPC.TLSClientCA, baseTLSConfig) // Assume defined elsewhere
			if err != nil {
				return fmt.Errorf("invalid config: get gRPC TLS: %v", err)
			}
			if c.GRPC.TLSClientCA != "" {
				grpcOptions = append(grpcOptions, grpc.StreamInterceptor(grpcMetrics.StreamServerInterceptor()), grpc.UnaryInterceptor(grpcMetrics.UnaryServerInterceptor()))
			}
			grpcOptions = append(grpcOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
		}

		// --- Create gRPC Server & Register Services ---
		grpcSrv := grpc.NewServer(grpcOptions...)

		// Register CUSTOM Platform User Service (uses separate entClient)
		if entClient != nil { // Only register if Ent client was successfully initialized
			platformStorage := server.NewEntStorage(entClient)                // Use the constructor from platform_storage_impl.go
			platformUserSvc := server.NewPlatformUserService(platformStorage) // Pass the implementation

			api.RegisterPlatformUserServiceServer(grpcSrv, platformUserSvc)

			logger.Info("registered Platform User gRPC service")
			// TODO: Add registration for other custom services (Roles, Tokens, etc.) here if needed
		} else {
			logger.Info("skipping registration of Platform User gRPC service (requires postgres storage)")
		}

		// Register STANDARD Dex Service (uses standard storage interface 's')
		// serverConfig.Storage == s
		api.RegisterDexServer(grpcSrv, server.NewAPI(serverConfig.Storage, logger, version, serv))
		logger.Info("registered standard Dex gRPC service")

		// --- gRPC Metrics & Reflection ---
		grpcMetrics.InitializeMetrics(grpcSrv)
		if c.GRPC.Reflection {
			logger.Info("enabling reflection in grpc service")
			reflection.Register(grpcSrv)
		}

		// --- Add gRPC server to run group ---
		group.Add(func() error {
			return grpcSrv.Serve(grpcListener)
		}, func(err error) {
			logger.Debug("starting graceful shutdown", "server", "grpc")
			grpcSrv.GracefulStop()
		})
	} // end if c.GRPC.Addr != ""

	// --- Signal Handling ---
	group.Add(run.SignalHandler(context.Background(), os.Interrupt, syscall.SIGTERM))

	// --- Run Everything ---
	logger.Info("starting run group")
	if err := group.Run(); err != nil {
		// run.SignalError is expected on ctrl-c, don't return as error
		if _, ok := err.(run.SignalError); !ok {
			return fmt.Errorf("run group failed: %w", err)
		}
		logger.Info("shutdown initiated by signal", "err", err)
	} else {
		logger.Info("run group finished normally")
	}

	logger.Info("server shutting down")
	return nil // Normal exit
}

// --- Helper Functions (Assume these exist in other files in package main or are included below) ---

// NOTE: Provide actual implementations or ensure they exist in your project
func applyConfigOverrides(options serveOptions, config *Config) {}
func pprofHandler(router *http.ServeMux)                        {}
func newTLSReloader(logger *slog.Logger, certFile, keyFile, caFile string, baseConfig *tls.Config) (*tls.Config, error) {
	return baseConfig, nil /* Dummy */
}
func loadTLSConfig(certFile, keyFile, caFile string, baseConfig *tls.Config) (*tls.Config, error) {
	return baseConfig, nil /* Dummy */
}
func recordBuildInfo() {}

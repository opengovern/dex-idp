// cmd/dex/serve.go
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"time"

	// External Dependencies
	gosundheit "github.com/AppsFlyer/go-sundheit"
	"github.com/AppsFlyer/go-sundheit/checks"
	gosundheithttp "github.com/AppsFlyer/go-sundheit/http"

	// Import generated Ent client
	entstorage "github.com/dexidp/dex/storage/sql" // *** ADD THIS IMPORT ***
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
	platformsvc "github.com/dexidp/dex/server/platform/service" // *** ADDED: Import platform service package ***
	pstorage "github.com/dexidp/dex/server/platform/storage"    // Import platform storage INTERFACE package
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/ent/db" // Import generated Ent client

	// Import sql storage package for config access
	// *** ADDED: Import sql storage IMPLEMENTATION package ***
	// DB Drivers (Import for side effects)
	_ "github.com/lib/pq"
	// _ "github.com/go-sql-driver/mysql"
	// _ "github.com/mattn/go-sqlite3"
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

	// Add flags from config structure (if using pflag binding)
	// Example: AddConfigFlags(flags, &c)

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

	applyConfigOverrides(options, &c) // Assume defined elsewhere

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
			// ... (validation logic as before) ...
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
		}
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
	var entClient *db.Client                     // Declare entClient variable
	var platformStorage pstorage.PlatformStorage // Declare variable for the platform storage implementation

	if c.Storage.Type == "postgres" {
		// Need to re-parse the postgres config specifically for Ent DSN construction
		var pgConfig entstorage.Postgres                                // Use the consistent alias
		jsonData, err := json.MarshalIndent(c.Storage.Config, "", "  ") // Use MarshalIndent for pretty print
		if err != nil {
			// handle marshal error
		} else {
			// Use jsonData (which is []byte) - e.g., log it
			log.Printf("Storage Config JSON: %s", string(jsonData))
		}

		// Construct DSN (Ensure sensitive info isn't logged excessively)
		// Example DSN, adjust based on Ent's postgres driver requirements
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			pgConfig.Host, pgConfig.Port, pgConfig.User, pgConfig.Password, pgConfig.Database, pgConfig.SSL.Mode)
		// Add other parameters like connect_timeout, sslrootcert etc. as needed from pgConfig
		if pgConfig.ConnectionTimeout > 0 {
			dsn = fmt.Sprintf("%s connect_timeout=%d", dsn, pgConfig.ConnectionTimeout)
		}
		// Potential Fix (assuming the field is now 'CAFile')
		if pgConfig.SSL.CAFile != "" {
			dsn = fmt.Sprintf("%s sslrootcert=%s", dsn, pgConfig.SSL.CAFile)
		}
		if pgConfig.SSL.CertFile != "" {
			dsn = fmt.Sprintf("%s sslcert=%s", dsn, pgConfig.SSL.CertFile)
		}
		if pgConfig.SSL.KeyFile != "" {
			dsn = fmt.Sprintf("%s sslkey=%s", dsn, pgConfig.SSL.KeyFile)
		}

		logger.Info("connecting to postgres for custom platform tables via Ent",
			"host", pgConfig.Host,
			"port", pgConfig.Port,
			"user", pgConfig.User, // Be careful logging user in prod
			"database", pgConfig.Database,
			"ssl_mode", pgConfig.SSL.Mode,
		)
		entClient, err = db.Open("postgres", dsn)
		if err != nil {
			// Log the error but allow Dex to potentially continue without platform services
			logger.Error("failed to connect to postgres via ent for custom tables, platform services will be unavailable", "err", err)
			// Do not return here, let the server start without platform services
		} else {
			// Ent client connected successfully
			defer func() {
				logger.Info("closing ent client connection pool for custom tables...")
				if err := entClient.Close(); err != nil {
					logger.Error("failed to close custom ent client", "err", err)
				}
			}()

			// Instantiate Platform Storage Implementation
			// Use entstorage alias which points to github.com/dexidp/dex/storage/sql
			platformStorage = entstorage.NewEntStorage(entClient)
			logger.Info("platform storage initialized using Ent client")

			// Optional: Run Ent auto-migration on startup (Use with caution in production)
			logger.Info("running ent auto-migration for platform tables...")
			if err := entClient.Schema.Create(context.Background()); err != nil {
				logger.Error("failed to run ent auto-migration", "err", err)
				//  // Decide if this should be fatal or just a warning
				return fmt.Errorf("failed running auto migration: %w", err)
			}
			logger.Info("ent auto-migration complete.")
		}

	} else {
		logger.Warn("storage type is not postgres, custom platform gRPC services will not be available", "storage_type", c.Storage.Type)
		// platformStorage remains nil
	}
	// --- END Initialize Separate Ent Client & Platform Storage ---
	// --- END Initialize Separate Ent Client & Platform Storage ---

	// --- Main Server Config and Initialization ---
	// ... (logging other config values) ...
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
		Storage: s, // Use standard storage 's' for main server config
		Issuer:  c.Issuer,
		// ... (rest of serverConfig fields as before) ...
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
	// ... (setting expiry durations on serverConfig as before) ...
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

	// --- Health Checker & Telemetry Setup ---
	telemetryRouter := http.NewServeMux()
	telemetryRouter.Handle("/metrics", promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}))
	{
		handler := gosundheithttp.HandleHealthJSON(healthChecker)
		telemetryRouter.Handle("/healthz", handler)
		telemetryRouter.HandleFunc("/healthz/live", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		telemetryRouter.Handle("/healthz/ready", handler)
	}
	// Assuming storage.NewCustomHealthCheckFunc exists and works with storage.Storage
	healthChecker.RegisterCheck(&checks.CustomCheck{CheckName: "storage", CheckFunc: storage.NewCustomHealthCheckFunc(s, now)}, gosundheit.ExecutionPeriod(15*time.Second), gosundheit.InitiallyPassing(true))
	// TODO: Add health check for platformStorage / entClient if needed

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
		// ... (HTTPS setup logic as before, using c.Web.TLSCert, c.Web.TLSKey) ...
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
		tlsConfig, err := newTLSReloader(logger, c.Web.TLSCert, c.Web.TLSKey, "", baseTLSConfig)
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
			// ... (gRPC TLS config logic as before, using c.GRPC.TLSCert, c.GRPC.TLSKey, c.GRPC.TLSClientCA) ...
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
			tlsConfig, err := newTLSReloader(logger, c.GRPC.TLSCert, c.GRPC.TLSKey, c.GRPC.TLSClientCA, baseTLSConfig)
			if err != nil {
				return fmt.Errorf("invalid config: get gRPC TLS: %v", err)
			}
			creds := credentials.NewTLS(tlsConfig)
			grpcOptions = append(grpcOptions, grpc.Creds(creds))
		} else {
			logger.Warn("serving gRPC without TLS") // Add warning if running without TLS
		}
		// Add Prometheus interceptors AFTER credential options
		grpcOptions = append(grpcOptions, grpc.StreamInterceptor(grpcMetrics.StreamServerInterceptor()), grpc.UnaryInterceptor(grpcMetrics.UnaryServerInterceptor()))

		// --- Create gRPC Server & Register Services ---
		grpcSrv := grpc.NewServer(grpcOptions...)

		// Register CUSTOM Platform Services (using separate platformStorage)
		// Register CUSTOM Platform Services (using separate platformStorage)
		if platformStorage != nil { // Check if platform storage was successfully initialized
			// Platform User Service
			platformUserSvc := platformsvc.NewPlatformUserService(platformStorage) // Assumes constructor exists
			api.RegisterPlatformUserServiceServer(grpcSrv, platformUserSvc)
			logger.Info("registered Platform User gRPC service")

			// *** ADDED: Platform AppRole Service ***
			platformAppRoleSvc := platformsvc.NewPlatformAppRoleService(platformStorage) // Assumes constructor exists
			api.RegisterPlatformAppRoleServiceServer(grpcSrv, platformAppRoleSvc)
			logger.Info("registered Platform AppRole gRPC service")

			// *** ADDED: Platform Token Service ***
			platformTokenSvc := platformsvc.NewPlatformTokenService(platformStorage) // Assumes constructor exists
			api.RegisterPlatformTokenServiceServer(grpcSrv, platformTokenSvc)
			logger.Info("registered Platform Token gRPC service")

			// *** ADDED: Platform Federated Identity Service ***
			platformFedIdSvc := platformsvc.NewPlatformFederatedIdentityService(platformStorage) // Assumes constructor exists
			api.RegisterPlatformFederatedIdentityServiceServer(grpcSrv, platformFedIdSvc)
			logger.Info("registered Platform Federated Identity gRPC service")

		} else {
			logger.Warn("skipping registration of Platform gRPC services (requires postgres storage or platformStorage initialization failed)")
		}

		// Register STANDARD Dex Service (uses standard storage interface 's')
		api.RegisterDexServer(grpcSrv, server.NewAPI(s, logger, version, serv)) // server.NewAPI is standard Dex
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
			// Log the actual error causing the run group to fail
			logger.Error("run group failed", "err", err)
			return fmt.Errorf("run group failed: %w", err)
		}
		logger.Info("shutdown initiated by signal", "signal", err)
	} else {
		logger.Info("run group finished normally")
	}

	logger.Info("server shutting down")
	return nil // Normal exit
}

// --- Helper Functions (Assume these exist in other files in package main or are included/defined below) ---

// NOTE: Provide actual implementations or ensure they exist in your project
// Config struct definition is assumed to exist
// type Config struct { ... }
// func (c *Config) Validate() error { return nil } // Dummy validation

func applyConfigOverrides(options serveOptions, config *Config) {
	// Override config values with flags if flags were provided
	if options.webHTTPAddr != "" {
		config.Web.HTTP = options.webHTTPAddr
	}
	if options.webHTTPSAddr != "" {
		config.Web.HTTPS = options.webHTTPSAddr
	}
	if options.telemetryAddr != "" {
		config.Telemetry.HTTP = options.telemetryAddr
	}
	if options.grpcAddr != "" {
		config.GRPC.Addr = options.grpcAddr
	}
}
func pprofHandler(router *http.ServeMux) { /* Add net/http/pprof handlers */ }

// newTLSReloader needs a proper implementation that handles cert reloading
func newTLSReloader(logger *slog.Logger, certFile, keyFile, caFile string, baseConfig *tls.Config) (*tls.Config, error) {
	// Placeholder - requires actual implementation using libraries like github.com/fsnotify/fsnotify
	// For now, just load once
	if certFile == "" || keyFile == "" {
		logger.Info("TLS cert/key not provided for reloader, returning base config")
		return baseConfig, nil // Or error if TLS is required
	}
	logger.Info("loading TLS cert/key", "cert", certFile, "key", keyFile)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %v", err)
	}
	// Base config might be nil, create if needed
	if baseConfig == nil {
		baseConfig = &tls.Config{}
	}
	// Create a new config copying base and adding GetCertificate
	tlsConfig := baseConfig.Clone()
	tlsConfig.Certificates = []tls.Certificate{cert}
	// TODO: Add CA loading if caFile is provided
	// TODO: Implement actual reloading mechanism
	return tlsConfig, nil
}

func recordBuildInfo() {
	buildInfo.WithLabelValues(version, runtime.Version(), fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)).Set(1)
}

type RefreshTokenPolicyConfig struct {
	DisableRotation   bool   `json:"disableRotation"`
	ValidIfNotUsedFor string `json:"validIfNotUsedFor"`
	AbsoluteLifetime  string `json:"absoluteLifetime"`
	ReuseInterval     string `json:"reuseInterval"`
}
type PasswordConfig storage.Password // Example alias
type StaticConnector struct {        // Example struct
	ID     string          `json:"id"`
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

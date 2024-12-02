package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	exporter "github.com/greenpau/gobgp_exporter/pkg/gobgp_exporter"
	tlsutil "github.com/greenpau/gobgp_exporter/pkg/tlsutil"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func main() {
	var listenAddress string
	var webServerTLS bool
	var webServerTLSCAPath string
	var webServerTLSServerCertPath string
	var webServerTLSServerKeyPath string
	var metricsPath string

	var serverAddress string
	var serverTLS bool
	var serverTLSCAPath string
	var serverTLSServerName string
	var serverTLSClientCertPath string
	var serverTLSClientKeyPath string

	var pollTimeout int
	var pollInterval int
	var isShowMetrics bool
	var isShowVersion bool
	var logLevel string
	var authToken string

	flag.StringVar(&listenAddress, "web.listen-address", ":9474", "Address to listen on for web interface and telemetry.")
	flag.BoolVar(&webServerTLS, "web.mtls", false, "Whether to enable mTLS for the prometheus endpoint.")
	flag.StringVar(&webServerTLSCAPath, "web.mtls-ca", "/a/golinject/etc/ssl/gecko-gobgpexporter-prometheus-chain.pem", "Optional path to PEM file with CA certificates to be trusted for mTLS '/metrics' access.")
	flag.StringVar(&webServerTLSServerCertPath, "web.mtls-server-cert", "/a/golinject/etc/ssl/gecko-gobgpexporter-prometheus-cert.pem", "Optional path to PEM file with server certificate to be used for server authentication.")
	flag.StringVar(&webServerTLSServerKeyPath, "web.mtls-server-key", "/a/golinject/etc/ssl/gecko-gobgpexporter-prometheus-key.pem", "Optional path to PEM file with server key to be used for server authentication.")
	flag.StringVar(&metricsPath, "web.telemetry-path", "/metrics", "Path under which to expose metrics.")

	flag.StringVar(&serverAddress, "gobgp.address", "127.0.0.1:50051", "gRPC API address of GoBGP server.")
	flag.BoolVar(&serverTLS, "gobgp.tls", false, "Whether to enable TLS for gRPC API access.")
	flag.StringVar(&serverTLSCAPath, "gobgp.tls-ca", "", "Optional path to PEM file with CA certificates to be trusted for gRPC API access.")
	flag.StringVar(&serverTLSServerName, "gobgp.tls-server-name", "", "Optional hostname to verify API server as.")
	flag.StringVar(&serverTLSClientCertPath, "gobgp.tls-client-cert", "", "Optional path to PEM file with client certificate to be used for client authentication.")
	flag.StringVar(&serverTLSClientKeyPath, "gobgp.tls-client-key", "", "Optional path to PEM file with client key to be used for client authentication.")

	flag.IntVar(&pollTimeout, "gobgp.timeout", 2, "Timeout on gRPC requests to a GoBGP server.")
	flag.IntVar(&pollInterval, "gobgp.poll-interval", 15, "The minimum interval (in seconds) between collections from a GoBGP server.")
	flag.StringVar(&authToken, "auth.token", "anonymous", "The X-Token for accessing the exporter itself")
	flag.BoolVar(&isShowMetrics, "metrics", false, "Display available metrics")
	flag.BoolVar(&isShowVersion, "version", false, "version information")
	flag.StringVar(&logLevel, "log.level", "info", "logging severity level")

	usageHelp := func() {
		fmt.Fprintf(os.Stderr, "\n%s - Prometheus Exporter for GoBGP\n\n", exporter.GetExporterName())
		fmt.Fprintf(os.Stderr, "Usage: %s [arguments]\n\n", exporter.GetExporterName())
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDocumentation: https://github.com/greenpau/gobgp_exporter/\n\n")
	}
	flag.Usage = usageHelp
	flag.Parse()

	opts := exporter.Options{
		Address: serverAddress,
		Timeout: pollTimeout,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	rootPath, _ := tlsutil.GetPackageRootPath()
	if !strings.HasSuffix(rootPath, "/") {
		rootPath += "/"
	}

	logger.SetReportCaller(true)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			source := fmt.Sprintf(" source: %s:%d", filepath.Base(f.File), f.Line)
			return "//", source
		},
	})

	switch logLevel {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	opts.Logger = logger

	if serverTLS {
		opts.TLS = new(tls.Config)
		if len(serverTLSCAPath) > 0 {
			// assuming PEM file here
			pemCerts, err := os.ReadFile(filepath.Clean(serverTLSCAPath))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not read TLS CA PEM file %q: %s\n", serverTLSCAPath, err)
				os.Exit(1)
			}

			opts.TLS.RootCAs = x509.NewCertPool()
			ok := opts.TLS.RootCAs.AppendCertsFromPEM(pemCerts)
			if !ok {
				fmt.Fprintf(os.Stderr, "Could not parse any TLS CA certificate from PEM file %q: %s\n", serverTLSCAPath, err)
				os.Exit(1)
			}
		}
		if len(serverTLSServerName) > 0 {
			opts.TLS.ServerName = serverTLSServerName
		}
		if len(serverTLSClientCertPath) > 0 && len(serverTLSClientKeyPath) > 0 {
			// again assuming PEM file
			cert, err := tlsutil.LoadCertificatePEM(serverTLSClientCertPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load client certificate: %s\n", err)
			}
			key, err := tlsutil.LoadKeyPEM(serverTLSClientKeyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load client key: %s\n", err)
			}
			opts.TLS.Certificates = []tls.Certificate{
				{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  key,
				},
			}
		} else if len(serverTLSClientCertPath) > 0 || len(serverTLSClientKeyPath) > 0 {
			fmt.Fprintln(os.Stderr, "Only one of client certificate and key was set, must set both.")
			os.Exit(1)
		}
	}

	if isShowVersion {
		fmt.Fprintf(os.Stdout, "%s %s", exporter.GetExporterName(), exporter.GetVersion())
		if exporter.GetRevision() != "" {
			fmt.Fprintf(os.Stdout, ", commit: %s\n", exporter.GetRevision())
		} else {
			fmt.Fprint(os.Stdout, "\n")
		}
		os.Exit(0)
	}

	if isShowMetrics {
		e := &exporter.RouterNode{}
		fmt.Fprintf(os.Stdout, "%s\n", e.GetMetricsTable())
		os.Exit(0)
	}

	logger.Infof("Starting %s %s", exporter.GetExporterName(), exporter.GetVersionInfo())

	e, err := exporter.NewExporter(opts)
	if err != nil {
		logger.Errorf("msg: %s. error: %s", "failed to init properly", err.Error())
		os.Exit(1)
	}

	e.SetPollInterval(int64(pollInterval))
	if err := e.AddAuthenticationToken(authToken); err != nil {
		logger.Errorf("msg: %s. error: %s", "failed to add authentication token", err.Error())
		os.Exit(1)
	}

	logger.Infof("msg %s. min_scrape_interval: %d", "exporter configuration", e.GetPollInterval())

	http.HandleFunc(metricsPath, func(w http.ResponseWriter, r *http.Request) {
		e.Scrape(w, r)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		e.Summary(metricsPath, w, r)
	})

	var server *http.Server

	if webServerTLS {
		// http server with mtls
		tlsReloader := tlsutil.NewTLSReloader(webServerTLSServerCertPath, webServerTLSServerKeyPath, webServerTLSCAPath, logger)
		// initial load of the TLS certs
		err := tlsReloader.Reload()
		if err != nil {
			logger.Fatalf("Failed to do an initial load of TLS certificates: %v", err)
		}

		tlsConfig := &tls.Config{
			GetCertificate:     tlsReloader.GetCertificate,
			GetConfigForClient: tlsReloader.GetConfigForClient,
		}

		server = &http.Server{
			Addr:      listenAddress,
			TLSConfig: tlsConfig,
			Handler:   nil,
		}

		// go routine with https server start
		go func() {
			logger.Infof("mTLS is set - Starting HTTPS server on %s", listenAddress)
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logger.Fatalf("Server failed: %v", err)
			}
		}()

		logger.Info("mTLS is set - preparing to handle SIGHUP, SIGINT or SIGTERM")
		// handle SIGHUP for certificate reloading
		go func() {
			for {
				sig := <-sigCh
				if sig == syscall.SIGHUP {
					// reload certs for SIGHUP
					logger.Info("Received SIGHUP, reloading certificates")
					if err := tlsReloader.Reload(); err != nil {
						logger.Infof("Failed to reload certificates: %v", err)
					} else {
						logger.Info("Certificates reloaded")
					}
				} else if sig == syscall.SIGINT || sig == syscall.SIGTERM {
					// graceful shutdown for SIGINT or SIGTERM
					logger.Info("Received shutdown signal, shutting down http server with mtls...")

					// setting maximum time that the server waits for a connection to close for 10s
					if serverShutdownWithTimeout(server, context.Background(), time.Second*10); err != nil {
						os.Exit(1)
					} else {
						os.Exit(0)
					}
				}
			}
		}()
	} else {
		// non-tls server
		server = &http.Server{
			Addr:    listenAddress,
			Handler: nil,
		}

		go func() {
			logger.Infof("mTLS is not set - Starting HTTP server on %s", listenAddress)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatalf("Server failed: %v", err)
			}
		}()

		logger.Info("mTLS is not set - preparing to handle SIGINT or SIGTERM")
		// Handle signals
		go func() {
			for {
				sig := <-sigCh
				if sig == syscall.SIGINT || sig == syscall.SIGTERM {
					logger.Info("Received shutdown signal, shutting down http server with no mtls...")

					// setting maximum time that the server waits for a connection to close for 10s
					if serverShutdownWithTimeout(server, context.Background(), time.Second*10); err != nil {
						os.Exit(1)
					} else {
						os.Exit(0)
					}
				}
			}
		}()
	}

	select {}
}

func serverShutdownWithTimeout(server *http.Server, ctx context.Context, duration time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server shutdown with timeout failed to have a clean exit: %v", err)
		return err
	} else {
		logger.Info("Server shutdown with timeout exited properly")
		return err
	}
}

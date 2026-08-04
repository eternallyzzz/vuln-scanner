package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/cve"
	"vuln-scanner/internal/llm"
	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/server"
	"vuln-scanner/internal/store"

	pb "vuln-scanner/api/gen/vulnscan/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfgPath := "server.yaml"
	if p := os.Getenv("VULNSCAN_CONFIG"); p != "" {
		cfgPath = p
	}

	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	if cfg.Patch == nil {
		cfg.Patch = &patch.Config{}
	}
	if err := cfg.Patch.Validate(); err != nil {
		slog.Error("patch config invalid", "error", err)
		os.Exit(1)
	}
	if cfg.ContainerScan != nil {
		if err := cfg.ContainerScan.Validate(); err != nil {
			slog.Error("container_scan config invalid", "error", err)
			os.Exit(1)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	db, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("database connected")

	if err := db.RunMigrations(ctx); err != nil {
		slog.Error("migration failed", "error", err)
		os.Exit(1)
	}

	auth := server.NewAgentAuth(cfg.JWTSecret)
	mw := server.NewAuthInterceptor(auth)

	feed := cve.NewFeedManager(db)
	msrcClient := cve.NewMSRCClient()
	nvdClient := cve.NewNVDClient(cfg.CVE.NVDAPIKey)
	osvClient := cve.NewOSVClient()
	feedCfg := cfg.CVE.FeedConfig()
	loader := cve.NewLoader(feed, db, msrcClient, nvdClient, osvClient, feedCfg)
	matcher := cve.NewMatcher(db, loader, feed, nvdClient)

	alertSvc, err := alert.NewService(db, cfg.Alerting)
	if err != nil {
		slog.Error("alert service init failed", "error", err)
		os.Exit(1)
	}
	if alertSvc.Enabled() {
		slog.Info("alerting enabled", "channels", alertSvc.ChannelNames())
	} else {
		slog.Info("alerting disabled, not configured")
	}

	worker := server.NewWorker(db, loader, matcher, alertSvc, cfg.Patch, feedCfg)
	worker.ConfigureContainerScanning(cfg.ContainerScan)
	worker.Start(ctx)

	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(mw.Unary()),
	)
	reflection.Register(grpcSrv)

	agentGRPC := server.NewAgentGRPCServer(auth, db, worker, cfg.Patch)
	pb.RegisterAgentServiceServer(grpcSrv, agentGRPC)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		slog.Error("grpc listen failed", "addr", cfg.GRPCAddr, "error", err)
		os.Exit(1)
	}

	go func() {
		slog.Info("gRPC server listening", "addr", cfg.GRPCAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			slog.Error("grpc serve failed", "error", err)
		}
	}()

	if cfg.LLMEnabled() {
		analyzer := llm.NewAnalyzer(db, cfg.LLM)
		if analyzer.Enabled() {
			slog.Info("LLM analyzer enabled",
				"provider", cfg.LLM.Provider,
				"auto_analyze", cfg.LLM.AutoAnalyze)
		}
	} else {
		slog.Info("LLM disabled, not configured")
	}

	rest := server.NewRESTServer(db, auth, cfg, worker, alertSvc)
	httpSrv := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: rest.Handler(),
	}

	go func() {
		slog.Info("HTTP server listening", "addr", cfg.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http serve failed", "error", err)
		}
	}()

	slog.Info("vuln-scanner server started",
		"http", cfg.HTTPAddr,
		"grpc", cfg.GRPCAddr,
		"version", "1.0.0")

	<-ctx.Done()
	slog.Info("shutting down")

	worker.Stop()
	httpSrv.Shutdown(context.Background())
	grpcSrv.GracefulStop()

	fmt.Fprintln(os.Stdout, "bye")
}

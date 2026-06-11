// controld is the OpenNGFW control-plane daemon.
//
// It owns the policy store (candidate/commit/rollback), compiles policy
// to the IR, renders per-engine configs, and supervises the engines.
// The gRPC API is canonical; REST is served via grpc-gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	gwruntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/apiserver"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/renderers"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	grpcListen := flag.String("listen", "127.0.0.1:9443", "gRPC listen address")
	httpListen := flag.String("http-listen", "127.0.0.1:8080", "REST gateway listen address (empty disables)")
	dataDir := flag.String("data-dir", "/var/lib/openngfw", "state directory (store, rendered configs)")
	dryRun := flag.Bool("dry-run", false, "render and validate but never touch engines (dev/demo)")
	flag.Parse()

	if *showVersion {
		fmt.Println("controld " + version.String())
		return
	}

	if err := run(*grpcListen, *httpListen, *dataDir, *dryRun); err != nil {
		slog.Error("controld exited", "error", err)
		os.Exit(1)
	}
}

func run(grpcListen, httpListen, dataDir string, dryRun bool) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(filepath.Join(dataDir, "store.db"))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	var sup *engines.Supervisor
	if dryRun {
		slog.Warn("running in dry-run mode: engine changes are NOT applied")
		sup = engines.NewSupervisor(
			&engines.DryRun{EngineName: engines.NftablesName},
			&engines.DryRun{EngineName: engines.RoutesName},
		)
	} else {
		sup = engines.NewSupervisor(
			&engines.Nftables{StateDir: dataDir},
			&engines.Routes{StateDir: dataDir},
		)
	}

	lis, err := net.Listen("tcp", grpcListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", grpcListen, err)
	}

	srv := grpc.NewServer()
	openngfwv1.RegisterSystemServiceServer(srv, &apiserver.SystemService{})
	openngfwv1.RegisterPolicyServiceServer(srv, apiserver.NewPolicyServer(st, sup, renderers.RenderAll))

	errCh := make(chan error, 2)
	go func() { errCh <- srv.Serve(lis) }()
	slog.Info("controld started", "version", version.Version, "grpc", grpcListen, "dry_run", dryRun)

	var httpSrv *http.Server
	if httpListen != "" {
		mux := gwruntime.NewServeMux()
		dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
		ctx := context.Background()
		if err := openngfwv1.RegisterSystemServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register system gateway: %w", err)
		}
		if err := openngfwv1.RegisterPolicyServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register policy gateway: %w", err)
		}
		httpSrv = &http.Server{Addr: httpListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("http gateway: %w", err)
			}
		}()
		slog.Info("REST gateway started", "http", httpListen)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("shutting down", "signal", sig.String())
		if httpSrv != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = httpSrv.Shutdown(shutCtx)
		}
		srv.GracefulStop()
		return nil
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	}
}

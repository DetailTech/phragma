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
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/intel"
	"github.com/detailtech/oss-ngfw/internal/renderers"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/version"
	"github.com/detailtech/oss-ngfw/internal/webui"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	grpcListen := flag.String("listen", "127.0.0.1:9443", "gRPC listen address")
	httpListen := flag.String("http-listen", "127.0.0.1:8080", "REST gateway listen address (empty disables)")
	dataDir := flag.String("data-dir", "/var/lib/openngfw", "state directory (store, rendered configs)")
	logDir := flag.String("log-dir", "/var/log/openngfw", "engine log directory (eve.json)")
	dryRun := flag.Bool("dry-run", false, "render and validate but never touch engines (dev/demo)")
	usersFile := flag.String("users-file", "", "local API users file enabling token auth + RBAC (YAML; chmod 600)")
	flag.Parse()

	if *showVersion {
		fmt.Println("controld " + version.String())
		return
	}

	if err := run(*grpcListen, *httpListen, *dataDir, *logDir, *usersFile, *dryRun); err != nil {
		slog.Error("controld exited", "error", err)
		os.Exit(1)
	}
}

func run(grpcListen, httpListen, dataDir, logDir, usersFile string, dryRun bool) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(filepath.Join(dataDir, "store.db"))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	opts := renderers.DefaultOptions(dataDir, logDir)

	var sup *engines.Supervisor
	if dryRun {
		slog.Warn("running in dry-run mode: engine changes are NOT applied")
		sup = engines.NewSupervisor(
			&engines.DryRun{EngineName: engines.NftablesName},
			&engines.DryRun{EngineName: engines.RoutesName},
			&engines.DryRun{EngineName: engines.SuricataName},
			&engines.DryRun{EngineName: engines.VectorName},
			&engines.DryRun{EngineName: engines.FRRName},
			&engines.DryRun{EngineName: engines.StrongswanName},
			&engines.DryRun{EngineName: engines.WireguardName},
			&engines.DryRun{EngineName: engines.NetdevName},
		)
	} else {
		suricata := &engines.Suricata{StateDir: filepath.Join(dataDir, "suricata"), LogDir: logDir}
		vector := &engines.Vector{StateDir: filepath.Join(dataDir, "vector")}
		defer suricata.Stop()
		defer vector.Stop()
		sup = engines.NewSupervisor(
			&engines.Nftables{StateDir: dataDir},
			&engines.Routes{StateDir: dataDir},
			suricata,
			vector,
			&engines.FRR{StateDir: dataDir},
			&engines.Strongswan{},
			&engines.Wireguard{StateDir: dataDir},
			&engines.Netdev{},
		)
	}

	lis, err := net.Listen("tcp", grpcListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", grpcListen, err)
	}

	updater := &intel.Updater{RunningPolicy: func() (*openngfwv1.Policy, error) {
		p, _, err := st.GetRunning()
		return p, err
	}}
	intelTrigger := make(chan struct{}, 1)
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	go updater.Run(rootCtx, time.Hour, intelTrigger)

	// Re-apply the running policy at startup: kernel rulesets and child
	// engines do not survive reboots/daemon restarts, the store does.
	if p, ver, err := st.GetRunning(); err != nil {
		return fmt.Errorf("read running policy: %w", err)
	} else if ver > 0 && !dryRun {
		artifacts, err := renderers.RenderAll(p, opts)
		if err != nil {
			return fmt.Errorf("render running policy v%d: %w", ver, err)
		}
		if err := sup.Apply(rootCtx, artifacts, nil); err != nil {
			return fmt.Errorf("re-apply running policy v%d: %w", ver, err)
		}
		slog.Info("running policy re-applied at startup", "version", ver)
		select {
		case intelTrigger <- struct{}{}:
		default:
		}
	}

	policyServer := apiserver.NewPolicyServer(st, sup, renderers.Pipeline(opts))
	policyServer.OnCommit = func() {
		select {
		case intelTrigger <- struct{}{}:
		default:
		}
	}

	var serverOpts []grpc.ServerOption
	if usersFile != "" {
		auth, err := authz.Load(usersFile)
		if err != nil {
			return fmt.Errorf("load users file: %w", err)
		}
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(auth.UnaryInterceptor()))
		slog.Info("API authentication enabled", "users_file", usersFile)
	} else {
		slog.Warn("API authentication is DISABLED (no --users-file); every caller is 'local' admin — do not expose the API off-host")
	}

	srv := grpc.NewServer(serverOpts...)
	openngfwv1.RegisterSystemServiceServer(srv, &apiserver.SystemService{})
	openngfwv1.RegisterPolicyServiceServer(srv, policyServer)
	openngfwv1.RegisterAlertServiceServer(srv, &apiserver.AlertServer{EvePath: opts.EvePath()})
	openngfwv1.RegisterIntelServiceServer(srv, &apiserver.IntelServer{Store: st, Updater: updater})
	openngfwv1.RegisterFlowServiceServer(srv, &apiserver.FlowServer{EvePath: opts.EvePath()})

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
		if err := openngfwv1.RegisterAlertServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register alert gateway: %w", err)
		}
		if err := openngfwv1.RegisterIntelServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register intel gateway: %w", err)
		}
		if err := openngfwv1.RegisterFlowServiceHandlerFromEndpoint(ctx, mux, grpcListen, dialOpts); err != nil {
			return fmt.Errorf("register flow gateway: %w", err)
		}
		root := http.NewServeMux()
		root.Handle("/ui/", webui.Handler())
		root.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/ui/", http.StatusFound)
				return
			}
			mux.ServeHTTP(w, r)
		}))
		httpSrv = &http.Server{Addr: httpListen, Handler: root, ReadHeaderTimeout: 10 * time.Second}
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

// Command operator runs the kube-token-exchanger operator, which exchanges
// Kubernetes ServiceAccount identity tokens for authentik identity tokens
// via RFC 8693 token exchange.
package main

import (
	"flag"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	tokenexchangev1alpha1 "github.com/lukaspj/kube-token-exchanger/api/v1alpha1"
	"github.com/lukaspj/kube-token-exchanger/internal/authentik"
	"github.com/lukaspj/kube-token-exchanger/internal/controller"
	internalKubernetes "github.com/lukaspj/kube-token-exchanger/internal/kubernetes"
	_ "github.com/lukaspj/kube-token-exchanger/internal/metrics"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(tokenexchangev1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var probeAddr string
	var enableLeaderElection bool
	var authentikURL string
	var authentikScopes string
	var authentikTokenPath string
	var authentikTimeout time.Duration
	var authentikInsecureTLS bool
	var authentikCACertFile string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. Enabling this ensures only one active controller manager.")
	flag.StringVar(&authentikURL, "authentik-url", "", "Base URL of the authentik instance performing the RFC 8693 token exchange. Required.")
	flag.StringVar(&authentikScopes, "authentik-scopes", "openid",
		"Comma-separated OAuth2 scopes requested on exchanged tokens.")
	flag.StringVar(&authentikTokenPath, "authentik-token-path", "",
		"Path of the authentik token endpoint. Defaults to /application/o/token/.")
	flag.DurationVar(&authentikTimeout, "authentik-timeout", 15*time.Second,
		"Timeout for HTTP requests against authentik.")
	flag.BoolVar(&authentikInsecureTLS, "authentik-insecure-tls", false,
		"Disable TLS certificate verification against authentik. Do not use in production.")
	flag.StringVar(&authentikCACertFile, "authentik-ca-cert", "",
		"Path to a PEM file with the certificate authority used to verify the authentik TLS certificate.")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if authentikURL == "" {
		setupLog.Error(nil, "--authentik-url is required")
		os.Exit(1)
	}

	authentikScopesList := []string{}
	for _, s := range strings.Split(authentikScopes, ",") {
		if s = strings.TrimSpace(s); s != "" {
			authentikScopesList = append(authentikScopesList, s)
		}
	}

	authentikConfig := authentik.Config{
		URL:         authentikURL,
		TokenPath:   authentikTokenPath,
		Scopes:      authentikScopesList,
		Timeout:     authentikTimeout,
		InsecureTLS: authentikInsecureTLS,
	}
	if authentikCACertFile != "" {
		ca, err := os.ReadFile(authentikCACertFile)
		if err != nil {
			setupLog.Error(err, "unable to read --authentik-ca-cert", "path", authentikCACertFile)
			os.Exit(1)
		}
		authentikConfig.CACert = ca
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "tokenexchange.aldershaab-it.dk",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to build kubernetes clientset")
		os.Exit(1)
	}

	reconciler := &controller.TokenExchangeRequestReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Recorder:        mgr.GetEventRecorderFor("token-exchange-controller"),
		Minter:          internalKubernetes.NewMinter(clientset),
		AuthentikConfig: authentikConfig,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TokenExchangeRequest")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

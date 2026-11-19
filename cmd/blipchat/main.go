// Command blipchat is the project coordinator: it sequences turns, turns blip
// reports into turns, runs coordinator steps against an OpenAI-compatible
// model, and serves the engineer chat.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/blipchat"
)

// +kubebuilder:rbac:groups=blip.dev,resources=blipturns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=blip.dev,resources=blipturns/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=blip.dev,resources=blipthreads,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=blip.dev,resources=blipthreads/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=blip.dev,resources=blips,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=blip.dev,resources=blipstates,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=blip.dev,resources=blippools,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create;get
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

func main() {
	var cfg blipchat.Config
	var leaderElect bool
	var agentCommand string
	var heartbeat, debounce string
	flag.StringVar(&cfg.Listen, "listen", ":8080", "chat HTTP listen address")
	flag.BoolVar(&leaderElect, "leader-elect", false, "enable leader election")
	flag.StringVar(&cfg.BaseURL, "llm-base-url", "", "OpenAI-compatible API root, for example https://llm.example/v1")
	flag.StringVar(&cfg.APIKey, "llm-api-key", os.Getenv("BLIP_LLM_API_KEY"), "optional API key for the LLM endpoint")
	flag.StringVar(&cfg.Model, "model", "", "default model when a thread does not set spec.model")
	flag.StringVar(&agentCommand, "agent-command", "blip-pi", "command that runs one task; the prompt is appended")
	flag.StringVar(&debounce, "debounce", "5s", "how long Batch turns wait before a step")
	flag.StringVar(&heartbeat, "heartbeat", "30m", "default heartbeat while tasks are open")
	flag.Int64Var(&cfg.StepTokenLimit, "step-token-limit", 60000, "tokens one step may spend")
	flag.IntVar(&cfg.MaxToolCalls, "max-tool-calls", 20, "tool calls one step may make")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	var err error
	if cfg.Debounce, err = time.ParseDuration(debounce); err != nil {
		fail("--debounce: " + err.Error())
	}
	if cfg.Heartbeat, err = time.ParseDuration(heartbeat); err != nil {
		fail("--heartbeat: " + err.Error())
	}
	cfg.AgentCommand = strings.Fields(agentCommand)
	if cfg.BaseURL == "" {
		fail("--llm-base-url is required")
	}
	if err := run(cfg, leaderElect); err != nil {
		fail(err.Error())
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "blipchat:", message)
	os.Exit(1)
}

func run(cfg blipchat.Config, leaderElect bool) error {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := v1.AddToScheme(scheme); err != nil {
		return err
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		LeaderElection:                leaderElect,
		LeaderElectionID:              "blipchat.blip.dev",
		LeaderElectionReleaseOnCancel: true,
		HealthProbeBindAddress:        "0",
		Metrics:                       metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		return err
	}
	ctx := ctrl.SetupSignalHandler()
	if err := blipchat.Setup(ctx, mgr, cfg); err != nil {
		return err
	}
	return mgr.Start(ctx)
}

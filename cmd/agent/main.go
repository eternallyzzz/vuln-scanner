package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"vuln-scanner/internal/agent"
	"vuln-scanner/internal/collector"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vuln-agent",
	Short: "VulnScanner Agent - lightweight asset collector",
}

var installCmd = &cobra.Command{
	Use:   "install [code]",
	Short: "Register with server and install as system service",
	Args:  cobra.ExactArgs(1),
	RunE:  runInstall,
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove agent from system service",
	RunE:  runUninstall,
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run agent in foreground",
	RunE:  runAgent,
}

func init() {
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(runCmd)

	installCmd.Flags().String("server", "", "Server HTTP URL (http://host:port)")
	runCmd.Flags().Bool("once", false, "Run a single collection cycle then exit")
	runCmd.Flags().String("dump-assets", "", "Export collected assets to JSON file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newCollector() collector.Collector {
	return platformCollector()
}

func dumpAssets(assets []collector.Asset, sys collector.SystemInfo, path string) error {
	output := struct {
		SystemInfo collector.SystemInfo `json:"system_info"`
		Total      int                  `json:"total"`
		Assets     []collector.Asset    `json:"assets"`
	}{
		SystemInfo: sys,
		Total:      len(assets),
		Assets:     assets,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	fmt.Printf("dumped %d assets to %s\n", len(assets), path)
	return nil
}

func runInstall(cmd *cobra.Command, args []string) error {
	code := args[0]
	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return fmt.Errorf("--server flag is required")
	}

	cfg, err := registerAgent(context.Background(), serverURL, code)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	if err := agent.SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	if err := installService(); err != nil {
		return fmt.Errorf("install service: %w", err)
	}

	fmt.Println("Agent installed successfully. Service is running.")
	return nil
}

func runUninstall(cmd *cobra.Command, args []string) error {
	if err := uninstallService(); err != nil {
		return fmt.Errorf("uninstall service: %w", err)
	}
	fmt.Println("Agent uninstalled successfully.")
	return nil
}

func runAgent(cmd *cobra.Command, args []string) error {
	cfg, err := agent.LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx := context.Background()

	dumpPath, _ := cmd.Flags().GetString("dump-assets")
	if dumpPath != "" {
		col := newCollector()
		assets, sys, err := collector.All(ctx, col)
		if err != nil {
			return fmt.Errorf("collection: %w", err)
		}
		return dumpAssets(assets, sys, dumpPath)
	}

	client, err := agent.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if err := client.Auth(ctx); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	col := newCollector()
	sched := agent.NewScheduler(cfg, client, col)

	once, _ := cmd.Flags().GetBool("once")
	if once {
		sched.RunOnce(ctx)
		return nil
	}

	sched.Start(ctx)
	select {}
}

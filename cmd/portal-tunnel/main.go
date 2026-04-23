package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func main() {
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := utils.RunCommands(os.Args[1:], os.Stdout, os.Stderr, printRootUsage, map[string]utils.CommandFunc{
		"expose": runExposeCommand,
		"list":   runListCommand,
		"update": runUpdateCommand,
		"version": func(args []string) error {
			fmt.Fprintln(os.Stdout, types.ReleaseVersion)
			return nil
		},
		"help": utils.MakeHelpCommand(printRootUsage, []utils.HelpTopic{
			{Name: "expose", Usage: printExposeUsage},
			{Name: "list", Usage: printListUsage},
		}),
	}); err != nil {
		log.Error().Err(err).Msg("portal tunnel exited with error")
		os.Exit(1)
	}
}

type exposeFlags struct {
	relayCSV        string
	multiHopCSV     string
	discovery       bool
	banMITM         bool
	identityPath    string
	identityJSON    string
	name            string
	desc            string
	tags            string
	owner           string
	thumbnail       string
	hide            bool
	targetAddr      string
	httpRoutes      []string
	udp             bool
	udpAddr         string
	tcp             bool
	maxActiveRelays int
	multiHopDepth   int
}

func runExposeCommand(args []string) error {
	updateCh := startUpdateCheck()

	flags := exposeFlags{}
	fs := utils.NewFlagSet("expose", printExposeUsage)

	utils.StringFlag(fs, &flags.relayCSV, "relays", "", "Additional Portal relay server API URLs (comma-separated; scheme omitted defaults to https)")
	utils.StringFlagEnv(fs, &flags.multiHopCSV, "multi-hop", "", "Ordered multi-hop relay API URLs, comma-separated", "MULTI_HOP")
	utils.BoolFlag(fs, &flags.discovery, "discovery", true, "Include public registry relays and discover additional relay bootstraps")
	utils.BoolFlagEnv(fs, &flags.banMITM, "ban-mitm", true, "Ban relay when the MITM self-probe detects TLS termination", "BAN_MITM")
	utils.StringFlagEnv(fs, &flags.identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	utils.StringFlagEnv(fs, &flags.identityJSON, "identity-json", "", "identity json payload; overrides --identity-path contents and is persisted there when both are set", "IDENTITY_JSON")
	utils.StringFlag(fs, &flags.name, "name", "", "Public hostname prefix (single DNS label); auto-generated when omitted")
	utils.StringFlag(fs, &flags.desc, "description", "", "Service description metadata")
	utils.StringFlag(fs, &flags.tags, "tags", "", "Service tags metadata (comma-separated)")
	utils.StringFlag(fs, &flags.owner, "owner", "", "Service owner metadata")
	utils.StringFlag(fs, &flags.thumbnail, "thumbnail", "", "Service thumbnail URL metadata")
	utils.BoolFlag(fs, &flags.hide, "hide", false, "Hide service from relay listing screens")
	utils.RepeatedStringFlag(fs, &flags.httpRoutes, "http-route", "HTTP route mapping in PATH=UPSTREAM form; repeat to aggregate multiple local HTTP services behind one public URL")
	utils.BoolFlagEnv(fs, &flags.udp, "udp", false, "Enable public UDP relay in addition to the default TCP relay", "UDP_ENABLED")
	utils.StringFlagEnv(fs, &flags.udpAddr, "udp-addr", "", "Local UDP target address for relayed datagrams (host:port or port only); defaults to the target when --udp is enabled", "UDP_ADDR")
	utils.BoolFlagEnv(fs, &flags.tcp, "tcp", false, "Request a dedicated TCP port on the relay for raw TCP services (no TLS; e.g., Minecraft, game servers)", "TCP_ENABLED")
	utils.IntFlagEnv(fs, &flags.maxActiveRelays, "max-active-relays", 3, nil, "Maximum number of auto-selected relays to keep connected; explicit --relays are always included", "MAX_ACTIVE_RELAYS")
	utils.IntFlagEnv(fs, &flags.multiHopDepth, "multi-hop-depth", 0, nil, "Automatically select one multi-hop route with this hop count; 0 or 1 disables multi-hop", "MULTI_HOP_DEPTH")

	if err := utils.ParseFlagSet(fs, args, printExposeUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	var err error
	flags.targetAddr, err = utils.OptionalSingleArg(fs.Args(), "target")
	if err != nil {
		printExposeUsage(os.Stderr)
		return err
	}
	switch {
	case flags.targetAddr == "" && len(flags.httpRoutes) == 0:
		printExposeUsage(os.Stderr)
		return errors.New("target or at least one --http-route is required")
	case flags.targetAddr != "" && len(flags.httpRoutes) > 0:
		printExposeUsage(os.Stderr)
		return errors.New("target cannot be combined with --http-route")
	case len(flags.httpRoutes) > 0 && flags.udp:
		printExposeUsage(os.Stderr)
		return errors.New("--udp cannot be combined with --http-route")
	}
	ctx, stop := utils.SignalContext()
	defer stop()

	exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
		RelayURLs:       utils.SplitCSV(flags.relayCSV),
		Discovery:       flags.discovery,
		IdentityPath:    flags.identityPath,
		IdentityJSON:    flags.identityJSON,
		Name:            flags.name,
		TargetAddr:      flags.targetAddr,
		UDPAddr:         flags.udpAddr,
		UDPEnabled:      flags.udp,
		TCPEnabled:      flags.tcp,
		MultiHop:        utils.SplitCSV(flags.multiHopCSV),
		MultiHopDepth:   flags.multiHopDepth,
		BanMITM:         flags.banMITM,
		MaxActiveRelays: flags.maxActiveRelays,
		Metadata: types.LeaseMetadata{
			Description: flags.desc,
			Tags:        utils.SplitCSV(flags.tags),
			Owner:       flags.owner,
			Thumbnail:   flags.thumbnail,
			Hide:        flags.hide,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to start relays: %w", err)
	}
	printUpdateHint(updateCh)
	if len(flags.httpRoutes) > 0 {
		handler, err := newHTTPRouteHandler(flags.httpRoutes)
		if err != nil {
			_ = exposure.Close()
			return err
		}
		defer exposure.Close()
		return exposure.RunHTTP(ctx, handler, "")
	}
	return proxyExposure(ctx, exposure)
}

type listFlags struct {
	relayCSV      string
	defaultRelays bool
}

func runUpdateCommand(args []string) error {
	slug := runtime.GOOS + "-" + runtime.GOARCH
	if _, ok := installer.AssetFilename(slug); !ok {
		return fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Pre-check: verify that the binary's directory is writable before downloading.
	if err := checkWritable(filepath.Dir(execPath)); err != nil {
		return fmt.Errorf("cannot update %s: %w", execPath, err)
	}

	binURL, _ := installer.OfficialAssetURL(slug, false)

	latestVersion, err := detectLatestVersion(binURL)
	if err != nil {
		return fmt.Errorf("failed to detect latest version: %w", err)
	}

	if latestVersion == types.ReleaseVersion {
		fmt.Fprintf(os.Stderr, "Already up to date (%s).\n", types.ReleaseVersion)
		return nil
	}

	fmt.Fprintf(os.Stderr, "Updating %s → %s ...\n", types.ReleaseVersion, latestVersion)

	tmpFile, err := os.CreateTemp("", "portal-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if err := downloadBinary(binURL, tmpFile); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to download binary: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync downloaded binary: %w", err)
	}
	_ = tmpFile.Close()

	checksumURL, _ := installer.OfficialAssetURL(slug, true)
	if err := verifyChecksum(tmpFile.Name(), checksumURL); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	if err := replaceBinary(tmpFile.Name(), execPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Updated %s → %s\n", types.ReleaseVersion, latestVersion)
	return nil
}

func runListCommand(args []string) error {
	updateCh := startUpdateCheck()
	defer printUpdateHint(updateCh)

	flags := listFlags{}
	fs := utils.NewFlagSet("list", printListUsage)

	utils.StringFlag(fs, &flags.relayCSV, "relays", "", "Additional Portal relay server API URLs (comma-separated; scheme omitted defaults to https)")
	utils.BoolFlag(fs, &flags.defaultRelays, "default-relays", true, "Include public registry relays")

	if err := utils.ParseFlagSet(fs, args, printListUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "list"); err != nil {
		printListUsage(os.Stderr)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayInputs := utils.SplitCSV(flags.relayCSV)

	relayURLs, err := utils.ResolvePortalRelayURLs(ctx, relayInputs, flags.defaultRelays)
	if err != nil {
		return fmt.Errorf("resolve relay urls: %w", err)
	}
	if len(relayURLs) == 0 {
		return errors.New("no relay URLs configured")
	}

	versions := make([]string, len(relayURLs))
	var wg sync.WaitGroup
	wg.Add(len(relayURLs))
	for i, u := range relayURLs {
		go func(idx int, url string) {
			defer wg.Done()
			versions[idx] = utils.FetchRelayVersion(ctx, url)
		}(i, u)
	}
	wg.Wait()

	for i, relayURL := range relayURLs {
		ver := versions[i]
		if ver == "" {
			ver = "unknown"
		}
		fmt.Printf("%s\t%s\n", relayURL, ver)
	}
	return nil
}

func printRootUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"portal expose [flags] <target>",
			"portal expose [flags] --http-route PATH=UPSTREAM [--http-route PATH=UPSTREAM]",
			"portal list [flags]",
			"portal update",
			"portal version",
		},
		[]string{
			"portal expose 3000",
			"portal expose localhost:8080 --name my-app",
			"portal expose --http-route /api=http://127.0.0.1:3001 --http-route /=http://127.0.0.1:5173 --name my-app",
			"portal expose 3000 --udp --udp-addr 127.0.0.1:5353",
			"portal list",
			"portal update",
			"portal version",
		},
	)
}

func printExposeUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"portal expose [flags] <target>",
			"portal expose [flags] --http-route PATH=UPSTREAM [--http-route PATH=UPSTREAM]",
		},
		[]string{
			"portal expose 3000",
			"portal expose localhost:8080 --name my-app",
			"portal expose --http-route /api=http://127.0.0.1:3001 --http-route /=http://127.0.0.1:5173 --name my-app",
			"portal expose 3000 --udp --udp-addr 127.0.0.1:5353",
			"portal expose 3000 --ban-mitm",
			"portal expose 3000 --relays https://portal.example.com --discovery=false",
			"portal expose 3000 --multi-hop https://entry.example.com,https://transit.example.com,https://exit.example.com",
			"portal expose 3000 --multi-hop-depth 3",
		},
	)
}

func printListUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"portal list [flags]",
		},
		[]string{
			"portal list",
			"portal list --relays https://portal.example.com --default-relays=false",
		},
	)
}

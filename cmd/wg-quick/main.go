package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	wgquick "github.com/aksdb/wg-quick-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func printHelp() {
	fmt.Print("wg-quick [flags] [ up | down | sync ] [ config_file | interface ]\n\n")
	flag.Usage()
	os.Exit(1)
}

func main() {
	flag.String("iface", "", "interface")
	verbose := flag.Bool("v", false, "verbose")
	protocol := flag.Int("route-protocol", 0, "route protocol to use for our routes")
	metric := flag.Int("route-metric", 0, "route metric to use for our routes")
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		printHelp()
	}

	setupLogger(*verbose)

	iface := flag.Lookup("iface").Value.String()
	log := zap.L()
	if iface != "" {
		log = zap.L().With(zap.String("iface", iface))
	}

	cfg := args[1]

	_, err := os.Stat(cfg)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		if iface == "" {
			iface = cfg
			log = zap.L().With(zap.String("iface", iface))
		}
		cfg = "/etc/wireguard/" + cfg + ".conf"
		_, err = os.Stat(cfg)
		if err != nil {
			log.Error("cannot find config file", zap.Error(err))
			printHelp()
		}
	default:
		log.Error("error while reading config file", zap.Error(err))
		printHelp()
	}

	b, err := ioutil.ReadFile(cfg)
	if err != nil {
		log.Fatal("cannot read file", zap.Error(err))
	}
	c := &wgquick.Config{}
	if err := c.UnmarshalText(b); err != nil {
		log.Fatal("cannot parse config file", zap.Error(err))
	}

	c.RouteProtocol = *protocol
	c.RouteMetric = *metric

	switch args[0] {
	case "up":
		if err := wgquick.Up(c, iface, log); err != nil {
			log.Error("cannot up interface", zap.Error(err))

		}
	case "down":
		if err := wgquick.Down(c, iface, log); err != nil {
			log.Error("cannot down interface", zap.Error(err))
		}
	case "sync":
		if err := wgquick.Sync(c, iface, log); err != nil {
			log.Error("cannot sync interface", zap.Error(err))
		}
	default:
		printHelp()
	}
}

func setupLogger(verbose bool) {
	cfg := zap.NewDevelopmentConfig()
	if !verbose {
		cfg.Level.SetLevel(zap.InfoLevel)
	}
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)
}

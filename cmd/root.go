package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/dennisstritzke/ipsec_exporter/exporter"
	"github.com/dennisstritzke/ipsec_exporter/ipsec"
	"github.com/spf13/cobra"
)

const (
	flagIpsecConfigFile  = "config-path"
	flagWebListenAddress = "web.listen-address"
	flagSudo             = "enable.sudo"
)

var Version string
var RootCmd = &cobra.Command{
	Use:     "ipsec_exporter",
	Short:   "Prometheus exporter for ipsec status.",
	Long:    "",
	Run:     defaultCommand,
	Version: Version,
}

func init() {
	RootCmd.PersistentFlags().StringVar(&exporter.IpSecConfigFile, flagIpsecConfigFile,
		"/etc/ipsec.conf",
		"Path to the ipsec config file.")

	configFiles, err := filepath.Glob(exporter.IpSecConfigFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if len(configFiles) > 1 {
		var buf bytes.Buffer
		for _, file := range configFiles {
			b, err := ioutil.ReadFile(file)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			buf.Write(b)
			buf.WriteString(fmt.Sprintln())
		}
		exporter.IpSecConfigFile = "/tmp/exporting-ipsec.conf"
		err := ioutil.WriteFile(exporter.IpSecConfigFile, buf.Bytes(), 0644)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	RootCmd.PersistentFlags().StringVar(&exporter.WebListenAddress, flagWebListenAddress,
		"0.0.0.0:9536",
		"Address on which to expose metrics.")
	RootCmd.PersistentFlags().BoolVar(&ipsec.UseSudo, flagSudo,
		false,
		"Executing command with sudo.")
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func defaultCommand(_ *cobra.Command, _ []string) {
	exporter.Serve()
}

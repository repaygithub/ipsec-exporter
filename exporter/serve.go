package exporter

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dennisstritzke/ipsec_exporter/ipsec"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

var IpSecConfigFile string
var WebListenAddress string

var ipSecConfiguration *ipsec.Configuration

func HandleGlobConfigPath() error {
	configFiles, err := filepath.Glob(IpSecConfigFile)
	if err != nil {
		return err
	}
	if len(configFiles) > 1 {
		var buf bytes.Buffer
		for _, file := range configFiles {
			b, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			buf.Write(b)
			buf.WriteString(fmt.Sprintln())
		}
		IpSecConfigFile = "/tmp/exporting-ipsec.conf"
		err := os.WriteFile(IpSecConfigFile, buf.Bytes(), 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

func Serve() {
	var err error
	err = HandleGlobConfigPath()
	if err != nil {
		log.Fatal(err)
		return
	}
	ipSecConfiguration, err = ipsec.NewConfiguration(IpSecConfigFile)
	if err != nil {
		log.Fatal(err)
		return
	}
	if !ipSecConfiguration.HasTunnels() {
		log.Warn("Found no configured connections in " + IpSecConfigFile)
	}

	collector := ipsec.NewCollector(ipSecConfiguration)
	prometheus.MustRegister(collector)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
             <head><title>IPsec Exporter</title></head>
             <body>
             <h1>IPsec Exporter</h1>
             <p><a href='/metrics'>Metrics</a></p>
             </body>
             </html>`))
	})
	http.Handle("/metrics", promhttp.Handler())

	log.Infoln("Listening on", WebListenAddress)
	err = http.ListenAndServe(WebListenAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
}

package ipsec

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type connection struct {
	name    string
	ignored bool
}

type Configuration struct {
	tunnel []connection
}

func (c *Configuration) HasTunnels() bool {
	return len(c.tunnel) != 0
}

// NewConfiguration creates a Configuration struct out of an IPsec configuration from the filesystem.
func NewConfiguration(fileName string) (*Configuration, error) {
	return newIpSecConfigLoader(fileName).Load()
}

type ipSecConfigurationLoader struct {
	FileName string
}

func newIpSecConfigLoader(fileName string) *ipSecConfigurationLoader {
	return &ipSecConfigurationLoader{
		FileName: fileName,
	}
}

func (l *ipSecConfigurationLoader) Load() (*Configuration, error) {
	var connections []connection
	var err error

	configFiles := []string{l.FileName}

	for i := 0; i < len(configFiles); i++ {
		content, err := l.loadConfig(configFiles[i])
		if err != nil {
			break
		}

		newConnections, includedFiles := l.getConfiguredIpSecConnection(content)
		connections = append(connections, newConnections...)

		for _, pattern := range includedFiles {
			matches, patternErr := filepath.Glob(pattern)
			if patternErr != nil {
				log.Printf("Unable to read include pattern '%s' in file '%s'", pattern, configFiles[i])
				continue
			}
			configFiles = append(configFiles, matches...)
		}
	}

	return &Configuration{
		tunnel: connections,
	}, err
}

func (l *ipSecConfigurationLoader) getConfiguredIpSecConnection(ipSecConfigContent string) ([]connection, []string) {
	var connections []connection
	var includeFiles []string

	ipSecConfigLines := l.extractLines(ipSecConfigContent)
	for _, line := range ipSecConfigLines {
		// Match connection definition lines
		re := regexp.MustCompile(`conn\s([.a-zA-Z0-9_-]+)`)
		match := re.FindStringSubmatch(line)
		if len(match) >= 2 {
			connections = append(connections, connection{name: match[1], ignored: false})
		}

		// Match auto=ignore lines
		reAutoIgnore := regexp.MustCompile(`auto=ignore`)
		matchAutoIgnore := reAutoIgnore.FindStringSubmatch(line)
		if len(matchAutoIgnore) >= 1 {
			connectionIndex := len(connections) - 1
			if len(connections) > connectionIndex {
				connections[connectionIndex].ignored = true
			}
		}

		reIgnore := regexp.MustCompile(`include\s(.*)`)
		matchIgnore := reIgnore.FindStringSubmatch(line)
		if len(matchIgnore) >= 2 {
			includeFiles = append(includeFiles, matchIgnore[1])
		}
	}

	return connections, includeFiles
}

func (l *ipSecConfigurationLoader) loadConfig(fileName string) (string, error) {
	buf, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	s := string(buf)
	return s, nil
}

func (l *ipSecConfigurationLoader) extractLines(ipsecConfig string) []string {
	return l.dropComments(strings.Split(ipsecConfig, "\n"))
}

func (l *ipSecConfigurationLoader) dropComments(lines []string) []string {
	var filteredLines []string

	for _, line := range lines {
		if !strings.HasPrefix(line, "#") {
			filteredLines = append(filteredLines, line)
		}
	}

	return filteredLines
}

func HandleGlobConfigPath(configPath string) (string, error) {
	configFiles, err := filepath.Glob(configPath)
	if err != nil {
		return "", err
	}
	if len(configFiles) > 0 && configFiles[0] != configPath {
		var buf bytes.Buffer
		for _, file := range configFiles {
			b, err := os.ReadFile(file)
			if err != nil {
				return "", err
			}
			buf.Write(b)
			buf.WriteString(fmt.Sprintln())
		}
		mergedConfigFile := "/tmp/exporting-ipsec.conf"
		err := os.WriteFile(mergedConfigFile, buf.Bytes(), 0644)
		if err != nil {
			return "", err
		}
		return mergedConfigFile, nil
	}
	return configPath, nil
}

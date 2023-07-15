package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"net/http"
)

var (
	serviceMap                        = make(map[int]map[string]string)
	services                          = make(map[string]bool)
	packets    *prometheus.CounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "xxx_tcpdump_packets_total",
		Help: "Total packets transferred",
	}, []string{"src", "dst", "service", "proto"})
	throughput *prometheus.CounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "xxx_tcpdump_bytes_total",
		Help: "Total bytes transferred",
	}, []string{"src", "dst", "service", "proto"})

	packetRegex = regexp.MustCompile(`.*proto (?P<proto>\w+) .*length (?P<length>\d+).*\n\s*(?P<src>[\w\d\.-]+)\.(?P<srcp>[\w\d-]+) > (?P<dst>[\w\d\.-]+)\.(?P<dstp>[\w\d-]+).*`)
)

func init() {
	prometheus.MustRegister(packets)
	prometheus.MustRegister(throughput)
}

func extractDomain(s string, fqdn bool) string {
	parts := strings.Split(s, ".")
	l := len(parts)
	if l == 4 {
		isIP := true
		for _, p := range parts {
			if _, err := strconv.Atoi(p); err != nil {
				isIP = false
				break
			}
		}
		if isIP {
			return s
		}
	}
	if fqdn {
		return s
	}
	if l > 2 {
		return strings.Join(parts[l-2:], ".")
	}
	return s
}

func lookupService(port int, proto string) string {
	if _, ok := serviceMap[port]; !ok {
		return ""
	}
	if _, ok := serviceMap[port][proto]; !ok {
		return ""
	}
	return serviceMap[port][proto]
}

func parsePacket(line string, fqdn bool) {
	match := packetRegex.FindStringSubmatch(line)
	if match == nil {
		fmt.Println("[SKIP] " + strings.ReplaceAll(line, "\n", "\t"))
		return
	}

	result := make(map[string]string)
	for i, name := range packetRegex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}

	labels := prometheus.Labels{
		"src":     extractDomain(result["src"], fqdn),
		"dst":     extractDomain(result["dst"], fqdn),
		"proto":   strings.ToLower(result["proto"]),
		"service": "",
	}

	if services[result["dstp"]] {
		labels["service"] = result["dstp"]
	} else if services[result["srcp"]] {
		labels["service"] = result["srcp"]
	}

	if labels["service"] == "" {
		dstp, _ := strconv.Atoi(result["dstp"])
		labels["service"] = lookupService(dstp, labels["proto"])
		srcp, _ := strconv.Atoi(result["srcp"])
		if labels["service"] == "" {
			labels["service"] = lookupService(srcp, labels["proto"])
		}
	}

	packets.With(labels).Inc()
	length, _ := strconv.Atoi(result["length"])
	throughput.With(labels).Add(float64(length))
	fmt.Println(labels, length)
}

func streamPackets(interfaceName string, filters string, fqdn bool) {
	cmd := exec.Command("tcpdump", "-i", interfaceName, "-v", "-l", filters)
	stdout, _ := cmd.StdoutPipe()
	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			parsePacket(scanner.Text(), fqdn)
		}
	}()
	cmd.Start()
}

func main() {
	interfaceName := pflag.StringP("interface", "i", "eth0", "The network interface to monitor.")
	port := pflag.IntP("port", "p", 8000, "The Prometheus metrics port.")
	fqdn := pflag.BoolP("fqdn", "f", false, "Include the FQDN (will increase cardinality of metrics significantly)")
	filters := pflag.StringP("filters", "f", "", "The TCPdump filters, e.g., \"src net 192.168.1.1/24\"")
	pflag.Parse()

	re := regexp.MustCompile(`(?P<service>\w+)\s*(?P<port>\d+)/(?P<proto>\w+)`)
	file, _ := os.Open("/etc/services")
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := re.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		result := make(map[string]string)
		for i, name := range re.SubexpNames() {
			if i != 0 && name != "" {
				result[name] = match[i]
			}
		}
		port, _ := strconv.Atoi(result["port"])
		if _, ok := serviceMap[port]; !ok {
			serviceMap[port] = make(map[string]string)
		}
		serviceMap[port][result["proto"]] = result["service"]
		services[result["service"]] = true
	}

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":"+strconv.Itoa(*port), nil)

	streamPackets(*interfaceName, *filters, *fqdn)

	for {
		time.Sleep(1 * time.Second)
	}
}

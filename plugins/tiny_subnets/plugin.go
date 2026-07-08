/*
This plugin supports assignment with  /30 addresses for small, segmented subnets
*/
package tiny_subnets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

var TEST_PREFIX = os.Getenv("TEST_PREFIX")
var UNIX_API_DHCP_LISTENER = TEST_PREFIX + "/state/dhcp/apisock"

type DHCPRequest struct {
	MAC          string
	Identifier   string
	Name         string
	Iface        string
	ParamReqList string
	VendorClass  string
}

type DHCPResponse struct {
	IP        string
	RouterIP  string
	DNSIP     string
	LeaseTime string
}

func requestIP(req DHCPRequest) (DHCPResponse, error) {
	//dial into UNIX_API_DHCP_LISTENER and make a POST request

	jsonValue, _ := json.Marshal(req)
	dhcp_resp := DHCPResponse{}

	c := http.Client{}
	c.Transport = &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("unix", UNIX_API_DHCP_LISTENER)
		},
	}
	defer c.CloseIdleConnections()

	r, err := http.NewRequest(http.MethodPut, "http://localhost/dhcpRequest", bytes.NewBuffer(jsonValue))
	if err != nil {
		fmt.Println("[-] Failed to make dhcpRequest")
		return dhcp_resp, err
	}

	resp, err := c.Do(r)
	if err != nil {
		fmt.Println("[-] Failed to make API HTTP request")
		return dhcp_resp, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&dhcp_resp)
	if err != nil {
		fmt.Println("[-] Failed to decode API HTTP dhcp response")
		return dhcp_resp, err
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Println("[-] API HTTP DHCP Request error", resp.StatusCode)
		return dhcp_resp, fmt.Errorf("failed to get API HTTP dhcp response", resp.StatusCode)
	}

	return dhcp_resp, nil
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

var log = logger.GetLogger("plugins/tiny_subnets")

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name:   "tiny_subnets",
	Setup4: setupPoint,
}

// PluginState is the data held by an instance of the range plugin
type PluginState struct {
}

// Handler4 handles DHCPv4 packets for the range plugin
func (p *PluginState) Handler4(state *handler.PropagateState, req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {

	reg, err := regexp.Compile("[^A-Za-z0-9.-_]+")
	if err != nil {
		log.Fatalf("regexp failed: %v", err)
	}
	filteredHostName := reg.ReplaceAllString(req.HostName(), "")
	if filteredHostName == "" {
		filteredHostName = "DefaultMissingName"
	}

	interfaceName := string(state.InterfaceName)
	interfaceName = reg.ReplaceAllString(interfaceName, "")

	wanif := os.Getenv("WANIF")
	if wanif != "" && wanif == interfaceName {
		log.Printf("Refusing to handle DHCP request from upstream WANIF for " + req.ClientHWAddr.String())
		return nil, true
	}

	paramReqList := []string{}
	for _, code := range req.ParameterRequestList() {
		paramReqList = append(paramReqList, strconv.Itoa(int(code.Code())))
	}

	dhcp_req := DHCPRequest{
		MAC:          req.ClientHWAddr.String(),
		Name:         filteredHostName,
		Iface:        interfaceName,
		ParamReqList: strings.Join(paramReqList, ","),
		VendorClass:  reg.ReplaceAllString(req.ClassIdentifier(), ""),
	}

	record, success := requestIP(dhcp_req)
	if success != nil {
		return nil, true
	}

	resp.YourIPAddr = net.ParseIP(record.IP).To4()

	lt, err := time.ParseDuration(record.LeaseTime)
	if err == nil {
		resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(lt.Round(time.Second)))
	}
	routers := []net.IP{net.ParseIP(record.RouterIP)}
	resp.Options.Update(dhcpv4.OptRouter(routers...))

	serverId := net.ParseIP(record.RouterIP)

	//override DNS settings
	if record.DNSIP != "" {
		dns_parsed := net.ParseIP(record.DNSIP)
		if dns_parsed != nil {
			if req.IsOptionRequested(dhcpv4.OptionDomainNameServer) {
				dns_servers := []net.IP{dns_parsed}
				resp.Options.Update(dhcpv4.OptDNS(dns_servers...))
			}
			//update the server id to match the DNSIP
			serverId = net.ParseIP(record.DNSIP)
		} else {
			log.Printf("[-] Failed to parse record DNS IP: %s", record.DNSIP)
		}
	}

	resp.UpdateOption(dhcpv4.OptServerIdentifier(serverId))

	//set netmask /30 for tinynets.
	netmask := net.IPv4Mask(255, 255, 255, 252)
	resp.Options.Update(dhcpv4.OptSubnetMask(netmask))

	log.Printf("found IP address %s for ClientAddr %s", record.IP, req.ClientHWAddr.String())
	return resp, false
}

func setupPoint(args ...string) (handler.Handler4, error) {
	var (
		p PluginState
	)

	/* config arguments were deprecated  */

	return p.Handler4, nil
}

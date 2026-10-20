package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/client6"
	"github.com/insomniacslk/dhcp/netboot"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

var (
	ver       = flag.Int("v", 6, "IP version to use")
	ifname    = flag.String("i", "eth0", "Interface name")
	dryrun    = flag.Bool("dryrun", false, "Do not change network configuration")
	debug     = flag.Bool("d", false, "Print debug output")
	retries   = flag.Int("r", 3, "Number of retries before giving up")
	noIfup    = flag.Bool("noifup", false, "If set, don't wait for the interface to be up")
	leaseFile = flag.String("lf", "", "If set, write lease file")
	nf        = flag.Bool("nf", false, "If set, do not fork for renewing the lease")
	child     = flag.Bool("child", false, "If set, this is a child process for renewal")
)

func dhclient6(ifname string, attempts int, verbose bool) (*netboot.BootConf, error) {
	if attempts < 1 {
		attempts = 1
	}
	llAddr, err := dhcpv6.GetLinkLocalAddr(ifname)
	if err != nil {
		return nil, err
	}
	laddr := net.UDPAddr{
		IP:   llAddr,
		Port: dhcpv6.DefaultClientPort,
		Zone: ifname,
	}
	raddr := net.UDPAddr{
		IP:   dhcpv6.AllDHCPRelayAgentsAndServers,
		Port: dhcpv6.DefaultServerPort,
		Zone: ifname,
	}
	c := client6.NewClient()
	c.LocalAddr = &laddr
	c.RemoteAddr = &raddr
	var conv []dhcpv6.DHCPv6
	for attempt := 0; attempt < attempts; attempt++ {
		log.Printf("Attempt %d of %d", attempt+1, attempts)
		conv, err = c.Exchange(ifname, dhcpv6.WithNetboot)
		if err != nil && attempt < attempts {
			log.Printf("Error: %v", err)
			continue
		}
		break
	}
	if verbose {
		for _, m := range conv {
			log.Print(m.Summary())
		}
	}
	if err != nil {
		return nil, err
	}
	// extract the network configuration
	netconf, err := netboot.ConversationToNetconf(conv)
	return netconf, err
}

func dhclient4(ifname string, attempts int, verbose bool) (*netboot.BootConf, error) {
	if attempts < 1 {
		attempts = 1
	}
	// nclient4 sends from 0.0.0.0 on a packet socket. client4's raw IP
	// socket leaves the source to the kernel, which takes another
	// interface's address while ifname has none, and netfilter sees it.
	client, err := nclient4.New(ifname)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	var conv []*dhcpv4.DHCPv4
	for attempt := 0; attempt < attempts; attempt++ {
		log.Printf("Attempt %d of %d", attempt+1, attempts)
		var lease *nclient4.Lease
		lease, err = client.Request(context.Background())
		if lease != nil {
			conv = []*dhcpv4.DHCPv4{lease.Offer, lease.ACK}
		}
		if err != nil && attempt < attempts {
			log.Printf("Error: %v", err)
			continue
		}
		break
	}
	if verbose {
		for _, m := range conv {
			log.Print(m.Summary())
		}
	}
	if err != nil {
		return nil, err
	}
	// extract the network configuration
	netconf, err := netboot.ConversationToNetconfv4(conv)
	return netconf, err
}

func dhcp() error {
	var (
		err      error
		bootconf *netboot.BootConf
	)
	// bring interface up
	if !*noIfup {
		_, err = netboot.IfUp(*ifname, 5*time.Second)
		if err != nil {
			log.Printf("[-] failed to bring interface %s up: %v", *ifname, err)
			return err
		}
	}
	if *ver == 6 {
		bootconf, err = dhclient6(*ifname, *retries+1, *debug)
	} else {
		bootconf, err = dhclient4(*ifname, *retries+1, *debug)
	}
	if err != nil {
		log.Printf("[-] dhclient failed", err)
		return err
	}
	// configure the interface
	log.Printf("Setting network configuration:")
	log.Printf("%+v", bootconf)

	if *dryrun {
		log.Printf("dry run requested, not changing network configuration")
	} else {

		if *leaseFile != "" {
			data, _ := json.MarshalIndent(bootconf.NetConf, "", " ")
			ioutil.WriteFile(*leaseFile, data, 0600)
		}

		//set lease time
		for _, entry := range bootconf.NetConf.Addresses {
			if entry.ValidLifetime != 0 {
				lts := fmt.Sprintf("%d", int64(entry.ValidLifetime/1000000000))
				os.Setenv("LEASE_TIME", lts)
				break
			}
		}

		if err := netboot.ConfigureInterface(*ifname, &bootconf.NetConf); err != nil {
			log.Println("failed to configure interface", err)
			return err
		}
	}

	return nil
}

func main() {
	flag.Parse()

	//by default, nf no fork is false,
	//fork a child runner and return

	if *child {
		for {
			lts := os.Getenv("LEASE_TIME")
			lt := 0
			if lts != "" {
				x, err := strconv.Atoi(lts)
				if err == nil {
					lt = x
				}
			}
			if lt != 0 {
				//sleep half of lease time first
				time.Sleep(time.Duration(lt/2) * time.Second)
			}
			//run indefinitely
			for dhcp() != nil {
				//back off every minute
				time.Sleep(60 * time.Second)
			}
			//okay succeeded. wait until lease time
		}
	} else if !*nf {
		dhcp()

		args := append(os.Args, "-child")
		cmd := exec.Command(args[0], args[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
		}

		if err := cmd.Start(); err != nil {
			log.Printf("Error starting child process: %v\n", err)
			return
		}
		log.Printf("Child process started with PID %d\n", cmd.Process.Pid)
		return
	} else {
		// run once. no fork set. child not set
		dhcp()
	}

}

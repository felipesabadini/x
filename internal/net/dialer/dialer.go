package dialer

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/go-gost/core/logger"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/vishvananda/netns"
)

const (
	DefaultTimeout = 10 * time.Second
)

var (
	DefaultNetDialer = &Dialer{}
)

type Dialer struct {
	Interface string
	Netns     string
	Mark      int
	DialFunc  func(ctx context.Context, network, addr string) (net.Conn, error)
	Log       logger.Logger
}

func (d *Dialer) Dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	if d == nil {
		d = DefaultNetDialer
	}

	log := d.Log
	if log == nil {
		log = logger.Default()
	}
	log = log.WithFields(map[string]any{
		"sid": ctxvalue.SidFromContext(ctx),
	})

	if d.Netns != "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		originNs, err := netns.Get()
		if err != nil {
			return nil, fmt.Errorf("netns.Get(): %v", err)
		}
		defer netns.Set(originNs)

		var ns netns.NsHandle
		if strings.HasPrefix(d.Netns, "/") {
			ns, err = netns.GetFromPath(d.Netns)
		} else {
			ns, err = netns.GetFromName(d.Netns)
		}
		if err != nil {
			return nil, fmt.Errorf("netns.Get(%s): %v", d.Netns, err)
		}
		defer ns.Close()

		if err := netns.Set(ns); err != nil {
			return nil, fmt.Errorf("netns.Set(%s): %v", d.Netns, err)
		}
	}

	if d.DialFunc != nil {
		return d.DialFunc(ctx, network, addr)
	}

	switch network {
	case "unix":
		netd := net.Dialer{}
		return netd.DialContext(ctx, network, addr)
	default:
	}

	ifces := strings.Split(d.Interface, ",")
	for _, ifce := range ifces {
		strict := strings.HasSuffix(ifce, "!")
		ifce = strings.TrimSuffix(ifce, "!")
		var ifceName string
		var ifAddrs []net.Addr
		ifceName, ifAddrs, err = xnet.ParseInterfaceAddr(ifce, network)
		if err != nil && strict {
			return
		}

		for _, ifAddr := range ifAddrs {
			conn, err = d.dialOnce(ctx, network, addr, ifceName, ifAddr, log)
			if err == nil {
				return
			}

			log.Debugf("dial %s/%s via interface %s@%v failed: %s", addr, network, ifceName, ifAddr, err)

			if strict &&
				!strings.Contains(err.Error(), "no suitable address found") &&
				!strings.Contains(err.Error(), "mismatched local address type") {
				return
			}
		}
	}

	return
}

func (d *Dialer) dialOnce(ctx context.Context, network, addr, ifceName string, ifAddr net.Addr, log logger.Logger) (net.Conn, error) {
	if ifceName != "" {
		log.Debugf("dial %s/%s via interface %s@%s", addr, network, ifceName, ifAddr)
	}

	switch network {
	case "udp", "udp4", "udp6":
		if addr == "" {
			var laddr *net.UDPAddr
			if ifAddr != nil {
				laddr, _ = ifAddr.(*net.UDPAddr)
			}

			c, err := net.ListenUDP(network, laddr)
			if err != nil {
				return nil, err
			}
			sc, err := c.SyscallConn()
			if err != nil {
				log.Error(err)
				return nil, err
			}
			err = sc.Control(func(fd uintptr) {
				if ifceName != "" {
					if err := bindDevice(network, addr, fd, ifceName); err != nil {
						log.Warnf("bind device: %v", err)
					}
				}
				if d.Mark != 0 {
					if err := setMark(fd, d.Mark); err != nil {
						log.Warnf("set mark: %v", err)
					}
				}
			})
			if err != nil {
				log.Error(err)
			}
			return c, nil
		}
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("dial: unsupported network %s", network)
	}

	var localAddr net.Addr
	if ifAddr != nil && ifceName != "" {
		// When binding to an interface, we need to use the IP from ifAddr
		// but let the system choose an ephemeral port (port 0).
		// The Control function below will handle binding to the interface.
		switch addr := ifAddr.(type) {
		case *net.TCPAddr:
			localAddr = &net.TCPAddr{
				IP:   addr.IP,
				Port: 0, // Let system choose ephemeral port
				Zone: addr.Zone,
			}
			log.Debugf("Binding to interface %s with IP %s (zone: %s)", ifceName, addr.IP, addr.Zone)
		case *net.UDPAddr:
			localAddr = &net.UDPAddr{
				IP:   addr.IP,
				Port: 0, // Let system choose ephemeral port
				Zone: addr.Zone,
			}
			log.Debugf("Binding to interface %s with IP %s (zone: %s)", ifceName, addr.IP, addr.Zone)
		default:
			localAddr = ifAddr
			log.Debugf("Using ifAddr as-is for interface %s: %s (type: %T)", ifceName, ifAddr, ifAddr)
		}
	} else {
		localAddr = ifAddr
		log.Debugf("No interface binding (ifAddr: %v, ifceName: %s)", localAddr, ifceName)
	}

	netd := net.Dialer{
		LocalAddr: localAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if ifceName != "" {
					if err := bindDevice(network, address, fd, ifceName); err != nil {
						log.Warnf("%s/%s bind device: %v", address, network, err)
					}
				}
				if d.Mark != 0 {
					if err := setMark(fd, d.Mark); err != nil {
						log.Warnf("%s/%s set mark: %v", address, network, err)
					}
				}
			})
		},
	}
	if d.Netns != "" {
		// https://github.com/golang/go/issues/44922#issuecomment-796645858
		netd.FallbackDelay = -1
	}

	return netd.DialContext(ctx, network, addr)
}

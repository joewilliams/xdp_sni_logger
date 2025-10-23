package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Error("removing memlock", "error", err)
		os.Exit(1)
	}

	var objs xdp_sni_loggerObjects
	if err := loadXdp_sni_loggerObjects(&objs, nil); err != nil {
		logger.Error("loading eBPF objects", "error", err)
		os.Exit(1)
	}
	defer objs.Close()

	args := os.Args[1:]
	ifname := "eth0"
	if len(args) == 1 {
		ifname = args[0]
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		logger.Error("getting interface", "iface", ifname, "error", err)
		os.Exit(1)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		logger.Error("attaching XDP", "error", err)
		os.Exit(1)
	}
	defer link.Close()

	logger.Info("looking for SNIs", "iface", ifname)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		logger.Error("opening ringbuf reader", "error", err)
		os.Exit(1)
	}
	defer rd.Close()

	go func() {
		<-stop
		if err := rd.Close(); err != nil {
			logger.Error("closing ringbuf reader", "error", err)
			os.Exit(1)
		}
	}()

	var sni xdp_sni_loggerSni
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Info("received signal, exiting")
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &sni); err != nil {
			logger.Error("parsing ringbuf event", "error", err)
			continue
		}

		// TODO: similar to the C side, maybe there's a better way?
		name := make([]byte, int(sni.Len))
		for i := 0; i < int(sni.Len); i++ {
			name[i] = byte(sni.Name[i])
		}

		logger.Info("got sni", "sni", string(name))
	}
}

// Command ssserver is a test helper: a Shadowsocks server plus an HTTP target,
// used by scripts/test-gateway-linux.sh to simulate "the internet".
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	sbservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/experimental/deprecated"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	mdns "github.com/miekg/dns"
)

func main() {
	ssListen := flag.String("ss", "0.0.0.0:8388", "shadowsocks listen address")
	httpListen := flag.String("http", "", "HTTP target listen address (optional)")
	dnsListen := flag.String("dns", "", "DNS server address answering every A query with -dns-answer (optional)")
	dnsAnswer := flag.String("dns-answer", "203.0.113.10", "IPv4 returned by the test DNS server")
	flag.Parse()

	if *dnsListen != "" {
		handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			for _, q := range req.Question {
				if q.Qtype == mdns.TypeA {
					rr, _ := mdns.NewRR(q.Name + " 60 IN A " + *dnsAnswer)
					resp.Answer = append(resp.Answer, rr)
				}
			}
			w.WriteMsg(resp)
		})
		for _, network := range []string{"udp", "tcp"} {
			srv := &mdns.Server{Addr: *dnsListen, Net: network, Handler: handler}
			go func() { log.Fatal(srv.ListenAndServe()) }()
		}
	}

	if *httpListen != "" {
		go func() {
			log.Fatal(http.ListenAndServe(*httpListen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "hello from the internet, you are %s\n", r.RemoteAddr)
			})))
		}()
	}

	ins := inbound.NewRegistry()
	shadowsocks.RegisterInbound(ins)
	outs := outbound.NewRegistry()
	direct.RegisterOutbound(outs)
	dnsReg := dns.NewTransportRegistry()
	local.RegisterTransport(dnsReg)
	ctx := box.Context(service.ContextWith(context.Background(), deprecated.NewStderrManager(sblog.StdLogger())),
		ins, outs, endpoint.NewRegistry(), dnsReg, sbservice.NewRegistry(), certificate.NewRegistry())

	host, port := splitHostPort(*ssListen)
	cfg := fmt.Sprintf(`{"log":{"level":"info"},
		"dns":{"servers":[{"type":"local","tag":"local"}]},
		"inbounds":[{"type":"shadowsocks","listen":%q,"listen_port":%s,"method":"aes-256-gcm","password":"pw"}],
		"outbounds":[{"type":"direct"}],"route":{"default_domain_resolver":"local"}}`, host, port)
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(cfg))
	if err != nil {
		log.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		log.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		log.Fatal(err)
	}
	defer instance.Close()
	log.Printf("shadowsocks on %s, http target on %q", *ssListen, *httpListen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}

func splitHostPort(addr string) (string, string) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:]
		}
	}
	return addr, "8388"
}

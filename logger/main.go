package main

import (
	"flag"
	"github.com/serverwentdown/bypass"
)

var listen string

func main() {
	flag.StringVar(&listen, "listen", ":8000", "listen on ip and port")
	flag.Parse()

	conf := &socks5.Config{}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	if err := server.ListenAndServe("tcp", listen); err != nil {
		panic(err)
	}
}

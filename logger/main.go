package main

import (
	"github.com/serverwentdown/bypass"
)

func main() {
	conf := &socks5.Config{}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
		panic(err)
	}
}

package main

import (
	"github.com/serverwentdown/bypass/socks"
)

func main() {
	conf := &socks.Config{
	}
	server, err := socks.New(conf)
	if err != nil {
		panic(err)
	}

	if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
		panic(err)
	}
}

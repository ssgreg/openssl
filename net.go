// Copyright (C) 2014 Space Monkey, Inc.

package openssl

import (
	"errors"
	"net"
)

type listener struct {
	net.Listener
	ctx *Ctx
}

func (l *listener) Accept() (c net.Conn, err error) {
	c, err = l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.ctx)
}

// NewListener wraps an existing net.Listener such that all accepted
// connections are wrapped as OpenSSL server connections using the provided
// context ctx.
func NewListener(inner net.Listener, ctx *Ctx) net.Listener {
	return &listener{
		Listener: inner,
		ctx:      ctx}
}

// Listen is a wrapper around net.Listen that wraps incoming connections with
// an OpenSSL server connection using the provided context ctx.
func Listen(network, laddr string, ctx *Ctx) (net.Listener, error) {
	if ctx == nil {
		return nil, errors.New("no ssl context provided")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, ctx), nil
}

type DialFlags int

const (
	InsecureSkipHostVerification DialFlags = 0x01
)

// Dial will connect to network/address and then wrap the corresponding
// underlying connection with an OpenSSL client connection using context ctx.
// If flags includes InsecureSkipHostVerification, the server certificate's
// hostname will not be checked to match the hostname in addr. Otherwise, flags
// should be 0.
//
// Dial probably won't work for you unless you set a verify location or add
// some certs to the certificate store of the client context you're using.
// This library is not nice enough to use the system certificate store by
// default for you yet.
func Dial(network, addr string, ctx *Ctx, flags DialFlags) (*Conn, error) {
	if ctx == nil {
		var err error
		ctx, err = NewCtx()
		if err != nil {
			return nil, err
		}
		// TODO: use operating system default certificate chain?
	}
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	conn, err := Client(c, ctx)
	if err != nil {
		c.Close()
		return nil, err
	}
	err = conn.Handshake()
	if err != nil {
		c.Close()
		return nil, err
	}
	if flags&InsecureSkipHostVerification == 0 {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			conn.Close()
			return nil, err
		}
		err = conn.VerifyHostname(host)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}
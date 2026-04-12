package portal

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

type proxy struct {
	activeConns  atomic.Int64
	tcpBytes     atomic.Int64
	tcpLoadMu    sync.Mutex
	tcpLoadAt    time.Time
	tcpLoadBytes int64
}

func (p *proxy) Bridge(left, right net.Conn) {
	p.activeConns.Add(1)
	defer p.activeConns.Add(-1)

	defer left.Close()
	defer right.Close()

	var group errgroup.Group
	group.Go(func() error {
		_, err := io.Copy(&countingConn{Conn: right, bytes: &p.tcpBytes}, left)
		closeWrite(right)
		return err
	})
	group.Go(func() error {
		_, err := io.Copy(&countingConn{Conn: left, bytes: &p.tcpBytes}, right)
		closeWrite(left)
		return err
	})
	_ = group.Wait()
}

func (p *proxy) ActiveConns() int64 {
	return p.activeConns.Load()
}

func (p *proxy) CurrentTCPBPS(now time.Time) float64 {
	totalTCPBytes := p.tcpBytes.Load()

	p.tcpLoadMu.Lock()
	defer p.tcpLoadMu.Unlock()

	if p.tcpLoadAt.IsZero() {
		p.tcpLoadAt = now
		p.tcpLoadBytes = totalTCPBytes
		return 0
	}

	if elapsed := now.Sub(p.tcpLoadAt); elapsed > 0 {
		tcpTrafficBPS := float64(totalTCPBytes-p.tcpLoadBytes) / elapsed.Seconds()
		p.tcpLoadAt = now
		p.tcpLoadBytes = totalTCPBytes
		return tcpTrafficBPS
	}

	return 0
}

type countingConn struct {
	net.Conn
	bytes *atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.bytes.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) ReadFrom(r io.Reader) (int64, error) {
	readerFrom, ok := c.Conn.(io.ReaderFrom)
	if !ok {
		return io.Copy(struct{ io.Writer }{Writer: c}, r)
	}

	n, err := readerFrom.ReadFrom(r)
	if n > 0 {
		c.bytes.Add(n)
	}
	return n, err
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

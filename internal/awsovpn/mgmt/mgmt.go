// Package mgmt is a minimal client for the OpenVPN management interface
// (doc/management-notes.txt in the OpenVPN sources).
package mgmt

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Conn struct {
	c   net.Conn
	r   *bufio.Reader
	wmu sync.Mutex
}

// Dial connects to a unix-socket management interface, retrying until the
// socket appears or ctx is done (OpenVPN creates it shortly after start).
func Dial(ctx context.Context, path string) (*Conn, error) {
	var d net.Dialer
	for {
		c, err := d.DialContext(ctx, "unix", path)
		if err == nil {
			return &Conn{c: c, r: bufio.NewReader(c)}, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("management socket %s: %w", path, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// NewConn wraps an existing connection (used by tests).
func NewConn(c net.Conn) *Conn { return &Conn{c: c, r: bufio.NewReader(c)} }

func (c *Conn) Send(cmd string) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := io.WriteString(c.c, cmd+"\n")
	return err
}

// ReadLine returns the next line without its trailing newline.
func (c *Conn) ReadLine() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *Conn) Close() error { return c.c.Close() }

// Quote quotes s as a single management-interface parameter.
func Quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

type Kind int

const (
	Other Kind = iota
	Info
	Hold
	Password
	State
	Log
	Fatal
	Echo
	Success
	Error
)

type Message struct {
	Kind Kind
	Body string // text after ">TYPE:" (or after "SUCCESS:"/"ERROR:")
}

var realtime = map[string]Kind{
	"INFO": Info, "HOLD": Hold, "PASSWORD": Password, "STATE": State,
	"LOG": Log, "FATAL": Fatal, "ECHO": Echo,
}

func Parse(line string) Message {
	if rest, ok := strings.CutPrefix(line, ">"); ok {
		typ, body, _ := strings.Cut(rest, ":")
		if k, ok := realtime[typ]; ok {
			return Message{Kind: k, Body: body}
		}
		return Message{Kind: Other, Body: line}
	}
	if rest, ok := strings.CutPrefix(line, "SUCCESS:"); ok {
		return Message{Kind: Success, Body: strings.TrimSpace(rest)}
	}
	if rest, ok := strings.CutPrefix(line, "ERROR:"); ok {
		return Message{Kind: Error, Body: strings.TrimSpace(rest)}
	}
	return Message{Kind: Other, Body: line}
}

// StateInfo is a parsed >STATE: body:
// "1784914078,CONNECTED,SUCCESS,10.0.0.5,203.0.113.10,443,,"
type StateInfo struct {
	Time       time.Time
	Name       string // CONNECTING, WAIT, AUTH, GET_CONFIG, ASSIGN_IP, CONNECTED, RECONNECTING, EXITING, ...
	Desc       string
	LocalIP    string
	RemoteIP   string
	RemotePort string
}

func ParseState(body string) StateInfo {
	f := strings.Split(body, ",")
	for len(f) < 6 {
		f = append(f, "")
	}
	var t time.Time
	if sec, err := strconv.ParseInt(f[0], 10, 64); err == nil {
		t = time.Unix(sec, 0)
	}
	return StateInfo{Time: t, Name: f[1], Desc: f[2], LocalIP: f[3], RemoteIP: f[4], RemotePort: f[5]}
}

// ParseLog splits a >LOG: body ("<time>,<flags>,<text>") into flags and text.
func ParseLog(body string) (flags, text string) {
	f := strings.SplitN(body, ",", 3)
	if len(f) < 3 {
		return "", body
	}
	return f[1], f[2]
}

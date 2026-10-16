package mgmt

import (
	"net"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		line string
		kind Kind
		body string
	}{
		{">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info", Info, "OpenVPN Management Interface Version 5 -- type 'help' for more info"},
		{">HOLD:Waiting for hold release:0", Hold, "Waiting for hold release:0"},
		{">PASSWORD:Need 'Auth' username/password", Password, "Need 'Auth' username/password"},
		{">STATE:1784914078,AUTH,,,,,,", State, "1784914078,AUTH,,,,,,"},
		{">LOG:1784914078,D,MANAGEMENT: CMD 'hold release'", Log, "1784914078,D,MANAGEMENT: CMD 'hold release'"},
		{">FATAL:ERROR: could not read Auth username/password/ok/string from management interface", Fatal, "ERROR: could not read Auth username/password/ok/string from management interface"},
		{"SUCCESS: real-time state notification set to ON", Success, "real-time state notification set to ON"},
		{"ERROR: unknown command, enter 'help' for more options", Error, "unknown command, enter 'help' for more options"},
		{">BYTECOUNT:1,2", Other, ">BYTECOUNT:1,2"},
		{"END", Other, "END"},
	} {
		m := Parse(tc.line)
		if m.Kind != tc.kind || m.Body != tc.body {
			t.Errorf("Parse(%q) = %+v", tc.line, m)
		}
	}
}

func TestParseState(t *testing.T) {
	s := ParseState("1791824034,CONNECTED,SUCCESS,10.0.0.5,203.0.113.10,443,,")
	if s.Name != "CONNECTED" || s.Desc != "SUCCESS" || s.LocalIP != "10.0.0.5" ||
		s.RemoteIP != "203.0.113.10" || s.RemotePort != "443" || s.Time.Unix() != 1791824034 {
		t.Errorf("got %+v", s)
	}
	if s := ParseState("1,RECONNECTING,ping-restart"); s.Name != "RECONNECTING" || s.Desc != "ping-restart" {
		t.Errorf("short state: %+v", s)
	}
}

func TestParseLog(t *testing.T) {
	flags, text := ParseLog("1791824014,I,SIGUSR1[soft,auth-failure] received, process restarting")
	if flags != "I" || text != "SIGUSR1[soft,auth-failure] received, process restarting" {
		t.Errorf("got %q %q", flags, text)
	}
}

func TestQuote(t *testing.T) {
	if got := Quote(`a"b\c`); got != `"a\"b\\c"` {
		t.Errorf("got %s", got)
	}
}

func TestConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	c := NewConn(a)
	go func() {
		buf := make([]byte, 64)
		n, _ := b.Read(buf)
		b.Write([]byte("SUCCESS: got " + string(buf[:n-1]) + "\r\n"))
	}()
	if err := c.Send("hold release"); err != nil {
		t.Fatal(err)
	}
	line, err := c.ReadLine()
	if err != nil || line != "SUCCESS: got hold release" {
		t.Fatalf("got %q, %v", line, err)
	}
}

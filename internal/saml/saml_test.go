package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeliverPostsToLoopback(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm.Get("SAMLResponse") + "|" + r.PostForm.Get("RelayState")
	}))
	defer srv.Close()
	f := &PostForm{Action: srv.URL + "/", SAMLResponse: "abc", RelayState: "rs"}
	if err := f.Deliver(context.Background(), srv.Client()); err != nil {
		t.Fatal(err)
	}
	if got != "abc|rs" {
		t.Fatalf("server got %q", got)
	}
}

func TestDeliverRefusesNonLoopback(t *testing.T) {
	for _, action := range []string{"https://evil.example.com/acs", "http://10.0.0.5:35001/", "file:///etc/passwd"} {
		f := &PostForm{Action: action, SAMLResponse: "abc"}
		err := f.Deliver(context.Background(), nil)
		if err == nil {
			t.Fatalf("delivered to %s", action)
		}
	}
}

func TestDeliverNeedsAssertion(t *testing.T) {
	f := &PostForm{Action: "http://127.0.0.1:35001/"}
	if err := f.Deliver(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "without SAMLResponse") {
		t.Fatalf("got %v", err)
	}
}

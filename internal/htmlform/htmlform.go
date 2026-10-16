// Package htmlform extracts forms and visible error messages from login pages.
package htmlform

import (
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Input is one form control.
type Input struct {
	Name, Type, Value, ID string
	Checked               bool
}

// Form is one <form> element with its controls.
type Form struct {
	ID, Action, Method string
	Inputs             []Input
}

// Has reports whether the form has a control with that name.
func (f Form) Has(name string) bool {
	for _, in := range f.Inputs {
		if in.Name == name {
			return true
		}
	}
	return false
}

// Value returns the value of the first control with that name.
func (f Form) Value(name string) string {
	for _, in := range f.Inputs {
		if in.Name == name {
			return in.Value
		}
	}
	return ""
}

// Values returns the hidden fields plus checked radios/checkboxes, the way a
// browser would submit the form before the user types anything.
func (f Form) Values() url.Values {
	v := url.Values{}
	for _, in := range f.Inputs {
		if in.Name == "" {
			continue
		}
		switch strings.ToLower(in.Type) {
		case "hidden":
			v.Set(in.Name, in.Value)
		case "radio", "checkbox":
			if in.Checked {
				v.Set(in.Name, in.Value)
			}
		}
	}
	return v
}

// Page is a parsed HTML document.
type Page struct {
	Title  string
	Forms  []Form
	Errors []string
}

// errorIDs and errorClasses are where Keycloak themes (v1 and PatternFly 5)
// and similar login pages render "invalid username or password".
var errorIDPrefixes = []string{"input-error", "kc-feedback-text"}
var errorClasses = []string{"pf-v5-c-alert__title", "alert-error", "kc-feedback-text", "kc-alert-error"}

// Parse reads an HTML document.
func Parse(r io.Reader) (*Page, error) {
	root, err := html.Parse(r)
	if err != nil {
		return nil, err
	}
	p := &Page{}
	cur := -1 // index into p.Forms; an index survives append, a pointer may not
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if p.Title == "" {
					p.Title = strings.TrimSpace(text(n))
				}
			case "form":
				p.Forms = append(p.Forms, Form{ID: attr(n, "id"), Action: attr(n, "action"), Method: strings.ToUpper(attr(n, "method"))})
				prev := cur
				cur = len(p.Forms) - 1
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c)
				}
				cur = prev
				return
			case "input", "button", "textarea", "select":
				if cur >= 0 {
					_, checked := hasAttr(n, "checked")
					p.Forms[cur].Inputs = append(p.Forms[cur].Inputs, Input{
						Name: attr(n, "name"), Type: attr(n, "type"), Value: attr(n, "value"),
						ID: attr(n, "id"), Checked: checked,
					})
				}
			}
			if isError(n) {
				if t := strings.Join(strings.Fields(text(n)), " "); t != "" {
					p.Errors = append(p.Errors, t)
				}
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return p, nil
}

func isError(n *html.Node) bool {
	id := attr(n, "id")
	for _, pfx := range errorIDPrefixes {
		if strings.HasPrefix(id, pfx) && !strings.HasPrefix(id, "input-error-container") {
			return true
		}
	}
	cls := " " + attr(n, "class") + " "
	for _, c := range errorClasses {
		if strings.Contains(cls, " "+c+" ") {
			return true
		}
	}
	return false
}

func attr(n *html.Node, key string) string {
	v, _ := hasAttr(n, key)
	return v
}

func hasAttr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func text(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

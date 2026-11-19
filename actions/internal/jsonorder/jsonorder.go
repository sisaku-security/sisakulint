// Package jsonorder reads the names of the members of a JSON object in the
// order its text writes them; encoding/json reads an object into a map,
// which does not keep the order.
package jsonorder

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Keys are the names of the members of the object at path in b, in the
// order of the text. path is the names of the members to go into from the
// top object; the value of each is an object.
func Keys(b []byte, path ...string) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	for _, name := range path {
		if err := into(dec, name); err != nil {
			return nil, err
		}
	}
	if err := open(dec); err != nil {
		return nil, err
	}
	var out []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, err
		}
		out = append(out, k.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// open reads the start of an object.
func open(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t != json.Delim('{') {
		return fmt.Errorf("an object is needed, not %v", t)
	}
	return nil
}

// into reads the next object up to the value of its member name.
func into(dec *json.Decoder, name string) error {
	if err := open(dec); err != nil {
		return err
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return err
		}
		if k == name {
			return nil
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return fmt.Errorf("no member %q", name)
}

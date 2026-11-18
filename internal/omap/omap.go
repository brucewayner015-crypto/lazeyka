// Package omap provides an insertion-ordered map that marshals to JSON with
// keys in the order they were added. mihomo reads YAML, and JSON is valid
// YAML, so the generated config keeps a stable, readable key order.
package omap

import (
	"bytes"
	"encoding/json"
)

// KV is a single key/value pair.
type KV struct {
	K string
	V any
}

// M is an ordered map.
type M []KV

// New builds an ordered map from alternating key, value arguments.
func New(kv ...any) M {
	m := make(M, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		k, _ := kv[i].(string)
		m = append(m, KV{K: k, V: kv[i+1]})
	}
	return m
}

// Set replaces the value for k or appends it.
func (m *M) Set(k string, v any) {
	for i := range *m {
		if (*m)[i].K == k {
			(*m)[i].V = v
			return
		}
	}
	*m = append(*m, KV{K: k, V: v})
}

// Get returns the value for k.
func (m M) Get(k string) (any, bool) {
	for _, kv := range m {
		if kv.K == k {
			return kv.V, true
		}
	}
	return nil, false
}

// MarshalJSON implements json.Marshaler.
func (m M) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, kv := range m {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := Marshal(kv.K)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		vb, err := Marshal(kv.V)
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Marshal encodes v as compact JSON without HTML escaping.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// MarshalIndent encodes v as indented JSON without HTML escaping.
func MarshalIndent(v any) ([]byte, error) {
	raw, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

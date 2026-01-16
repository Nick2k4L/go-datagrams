package datagrams

import (
	"bytes"
	"testing"
)

// TestOptionsFromBytes_Empty tests parsing an empty options Mapping.
func TestOptionsFromBytes_Empty(t *testing.T) {
	// Empty mapping: 2-byte size of 0
	data := []byte{0x00, 0x00}

	opts, consumed, err := OptionsFromBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if consumed != 2 {
		t.Errorf("expected 2 bytes consumed, got %d", consumed)
	}

	if !opts.IsEmpty() {
		t.Errorf("expected empty options")
	}
}

// TestOptionsFromBytes_SinglePair tests parsing a Mapping with one key/value pair.
func TestOptionsFromBytes_SinglePair(t *testing.T) {
	// Build a mapping: key="foo", value="bar"
	// String format: 1-byte length + data
	// Mapping format: 2-byte size + key=value;
	// "foo" = 03 66 6f 6f
	// "bar" = 03 62 61 72
	// Total content: 03 66 6f 6f 3d 03 62 61 72 3b = 10 bytes
	content := []byte{
		0x03, 0x66, 0x6f, 0x6f, // key "foo"
		0x3d,                   // '='
		0x03, 0x62, 0x61, 0x72, // value "bar"
		0x3b, // ';'
	}

	data := make([]byte, 2+len(content))
	data[0] = 0x00
	data[1] = byte(len(content))
	copy(data[2:], content)

	opts, consumed, err := OptionsFromBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if consumed != len(data) {
		t.Errorf("expected %d bytes consumed, got %d", len(data), consumed)
	}

	if opts.Get("foo") != "bar" {
		t.Errorf("expected foo=bar, got foo=%s", opts.Get("foo"))
	}
}

// TestOptionsFromBytes_MultiplePairs tests parsing a Mapping with multiple key/value pairs.
func TestOptionsFromBytes_MultiplePairs(t *testing.T) {
	// Build a mapping with two pairs: "a"="1", "b"="2"
	content := []byte{
		0x01, 0x61, // key "a"
		0x3d,       // '='
		0x01, 0x31, // value "1"
		0x3b,       // ';'
		0x01, 0x62, // key "b"
		0x3d,       // '='
		0x01, 0x32, // value "2"
		0x3b, // ';'
	}

	data := make([]byte, 2+len(content))
	data[0] = 0x00
	data[1] = byte(len(content))
	copy(data[2:], content)

	opts, consumed, err := OptionsFromBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if consumed != len(data) {
		t.Errorf("expected %d bytes consumed, got %d", len(data), consumed)
	}

	m := opts.ToMap()
	if len(m) != 2 {
		t.Errorf("expected 2 pairs, got %d", len(m))
	}

	if opts.Get("a") != "1" {
		t.Errorf("expected a=1, got a=%s", opts.Get("a"))
	}

	if opts.Get("b") != "2" {
		t.Errorf("expected b=2, got b=%s", opts.Get("b"))
	}
}

// TestOptionsFromBytes_TooShort tests error handling for truncated data.
func TestOptionsFromBytes_TooShort(t *testing.T) {
	// Only 1 byte - not enough for size field
	_, _, err := OptionsFromBytes([]byte{0x00})
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

// TestOptionsFromBytes_SizeMismatch tests error handling when size field exceeds data length.
func TestOptionsFromBytes_SizeMismatch(t *testing.T) {
	// Size field says 10 bytes, but only 2 bytes total
	_, _, err := OptionsFromBytes([]byte{0x00, 0x0a})
	if err == nil {
		t.Error("expected error for size mismatch")
	}
}

// TestOptionsFromBytes_MissingSeparator tests error handling for malformed pairs.
func TestOptionsFromBytes_MissingSeparator(t *testing.T) {
	// Missing '=' separator
	content := []byte{
		0x03, 0x66, 0x6f, 0x6f, // key "foo"
		// missing '='
		0x03, 0x62, 0x61, 0x72, // would be value
		0x3b, // ';'
	}

	data := make([]byte, 2+len(content))
	data[0] = 0x00
	data[1] = byte(len(content))
	copy(data[2:], content)

	_, _, err := OptionsFromBytes(data)
	if err == nil {
		t.Error("expected error for missing separator")
	}
}

// TestOptions_Bytes_Empty tests encoding an empty Options.
func TestOptions_Bytes_Empty(t *testing.T) {
	opts := EmptyOptions()

	data, err := opts.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []byte{0x00, 0x00}
	if !bytes.Equal(data, expected) {
		t.Errorf("expected %x, got %x", expected, data)
	}
}

// TestOptions_Bytes_SinglePair tests encoding a single key/value pair.
func TestOptions_Bytes_SinglePair(t *testing.T) {
	opts := NewOptions(map[string]string{"foo": "bar"})

	data, err := opts.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be parseable
	parsed, consumed, err := OptionsFromBytes(data)
	if err != nil {
		t.Fatalf("roundtrip parse error: %v", err)
	}

	if consumed != len(data) {
		t.Errorf("expected %d bytes consumed, got %d", len(data), consumed)
	}

	if parsed.Get("foo") != "bar" {
		t.Errorf("expected foo=bar, got foo=%s", parsed.Get("foo"))
	}
}

// TestOptions_Bytes_SortedKeys tests that keys are sorted for encoding.
func TestOptions_Bytes_SortedKeys(t *testing.T) {
	// Add keys in unsorted order
	opts := NewOptions(map[string]string{"c": "3", "a": "1", "b": "2"})

	data, err := opts.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Keys should appear in sorted order: a, b, c
	// Check that "a" appears before "b" which appears before "c"
	aPos := bytes.Index(data, []byte{0x01, 'a'})
	bPos := bytes.Index(data, []byte{0x01, 'b'})
	cPos := bytes.Index(data, []byte{0x01, 'c'})

	if aPos == -1 || bPos == -1 || cPos == -1 {
		t.Fatal("could not find all keys in encoded data")
	}

	if !(aPos < bPos && bPos < cPos) {
		t.Errorf("keys not sorted: a=%d, b=%d, c=%d", aPos, bPos, cPos)
	}
}

// TestOptions_Bytes_KeyTooLong tests error handling for keys exceeding 255 bytes.
func TestOptions_Bytes_KeyTooLong(t *testing.T) {
	longKey := string(make([]byte, 256))
	opts := NewOptions(map[string]string{longKey: "value"})

	_, err := opts.Bytes()
	if err == nil {
		t.Error("expected error for key too long")
	}
}

// TestOptions_Bytes_ValueTooLong tests error handling for values exceeding 255 bytes.
func TestOptions_Bytes_ValueTooLong(t *testing.T) {
	longValue := string(make([]byte, 256))
	opts := NewOptions(map[string]string{"key": longValue})

	_, err := opts.Bytes()
	if err == nil {
		t.Error("expected error for value too long")
	}
}

// TestOptions_Roundtrip tests encoding then decoding produces the same data.
func TestOptions_Roundtrip(t *testing.T) {
	testCases := []map[string]string{
		{},
		{"key": "value"},
		{"a": "1", "b": "2", "c": "3"},
		{"empty": ""},
	}

	for i, tc := range testCases {
		opts := NewOptions(tc)

		data, err := opts.Bytes()
		if err != nil {
			t.Errorf("case %d: encode error: %v", i, err)
			continue
		}

		parsed, _, err := OptionsFromBytes(data)
		if err != nil {
			t.Errorf("case %d: decode error: %v", i, err)
			continue
		}

		parsedMap := parsed.ToMap()
		if len(parsedMap) != len(tc) {
			t.Errorf("case %d: expected %d entries, got %d", i, len(tc), len(parsedMap))
			continue
		}

		for k, v := range tc {
			if parsed.Get(k) != v {
				t.Errorf("case %d: expected %s=%s, got %s=%s", i, k, v, k, parsed.Get(k))
			}
		}
	}
}

// TestOptions_Len tests the Len() method.
func TestOptions_Len(t *testing.T) {
	// Test empty options
	emptyOpts := EmptyOptions()
	if emptyOpts.Len() != 2 {
		t.Errorf("expected empty options len 2, got %d", emptyOpts.Len())
	}

	// Verify against actual encoded length
	data, err := emptyOpts.Bytes()
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	if len(data) != 2 {
		t.Errorf("expected encoded len 2, got %d", len(data))
	}
}

// TestOptions_Methods tests helper methods (Get, Set, Has, IsEmpty).
func TestOptions_Methods(t *testing.T) {
	opts := EmptyOptions()

	// IsEmpty should return true initially
	if !opts.IsEmpty() {
		t.Error("new options should be empty")
	}

	// Has should return false for missing key
	if opts.Has("foo") {
		t.Error("should not have 'foo' key")
	}

	// Get should return empty string for missing key
	if opts.Get("foo") != "" {
		t.Error("Get on missing key should return empty string")
	}

	// Set a value
	opts.Set("foo", "bar")

	// IsEmpty should return false now
	if opts.IsEmpty() {
		t.Error("options should not be empty after Set")
	}

	// Has should return true
	if !opts.Has("foo") {
		t.Error("should have 'foo' key after Set")
	}

	// Get should return the value
	if opts.Get("foo") != "bar" {
		t.Errorf("expected 'bar', got '%s'", opts.Get("foo"))
	}

	// Set to update existing value
	opts.Set("foo", "baz")
	if opts.Get("foo") != "baz" {
		t.Errorf("expected 'baz' after update, got '%s'", opts.Get("foo"))
	}
}

// TestOptions_ToMap tests the ToMap() method.
func TestOptions_ToMap(t *testing.T) {
	opts := NewOptions(map[string]string{"a": "1", "b": "2"})

	m := opts.ToMap()
	if len(m) != 2 {
		t.Errorf("expected 2 entries, got %d", len(m))
	}

	if m["a"] != "1" || m["b"] != "2" {
		t.Errorf("unexpected map contents: %v", m)
	}

	// Verify it's a copy (modifying returned map doesn't affect original)
	m["c"] = "3"
	if opts.Has("c") {
		t.Error("modifying returned map should not affect original")
	}
}

// TestOptions_NilSafety tests that nil Options doesn't panic.
func TestOptions_NilSafety(t *testing.T) {
	var opts *Options

	// These should not panic
	if !opts.IsEmpty() {
		t.Error("nil options should be empty")
	}

	if opts.Get("key") != "" {
		t.Error("nil options Get should return empty string")
	}

	if opts.Has("key") {
		t.Error("nil options Has should return false")
	}

	if opts.Len() != 2 {
		t.Error("nil options Len should return 2")
	}

	m := opts.ToMap()
	if m == nil || len(m) != 0 {
		t.Error("nil options ToMap should return empty map")
	}

	data, err := opts.Bytes()
	if err != nil {
		t.Errorf("nil options Bytes should not error: %v", err)
	}
	if !bytes.Equal(data, []byte{0x00, 0x00}) {
		t.Errorf("nil options Bytes should return empty mapping: %x", data)
	}
}

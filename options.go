package datagrams

import (
	"fmt"

	"github.com/go-i2p/common/data"
)

// Options represents an I2P Mapping structure for datagram options.
// This is a wrapper around github.com/go-i2p/common/data.Mapping that provides
// a simpler interface for datagram-specific use cases.
//
// A Mapping is a set of key/value pairs encoded as:
//   - 2-byte size integer (total bytes that follow)
//   - Series of String=String; pairs
//
// Each String is 1-byte length followed by UTF-8 data (max 255 bytes).
// Keys and values should not exceed 255 bytes each.
//
// Per I2P spec: Mappings in signed structures must be sorted by key.
type Options struct {
	mapping *data.Mapping
	values  map[string]string // cached Go map for fast access
}

// EmptyOptions returns an empty Options Mapping.
// When encoded, this produces a 2-byte zero size field.
func EmptyOptions() *Options {
	return &Options{
		mapping: nil,
		values:  make(map[string]string),
	}
}

// OptionsFromBytes parses an I2P Mapping from binary data using common/data.Mapping.
// Returns the Options, number of bytes consumed, and any error.
//
// Format:
//
//	+----+----+----+----+----+----+----+----+
//	|  size   | key_string (len + data)| =  |
//	+----+----+----+----+----+----+----+----+
//	| val_string (len + data)     | ;  | ...
//	+----+----+----+----+----+----+----+
func OptionsFromBytes(rawData []byte) (*Options, int, error) {
	if len(rawData) < 2 {
		return nil, 0, fmt.Errorf("options: data too short for size field (need 2 bytes, got %d)", len(rawData))
	}

	// Check for empty mapping (size=0) - common/data.ReadMapping doesn't handle this
	size := int(rawData[0])<<8 | int(rawData[1])
	if size == 0 {
		return &Options{
			mapping: nil,
			values:  make(map[string]string),
		}, 2, nil
	}

	// Use common/data.ReadMapping to parse the mapping
	mapping, remainder, errs := data.ReadMapping(rawData)
	if len(errs) > 0 {
		return nil, 0, fmt.Errorf("options: failed to parse mapping: %v", errs[0])
	}

	// Calculate consumed bytes
	consumed := len(rawData) - len(remainder)

	// Convert MappingValues to Go map
	values := make(map[string]string)
	mappingValues := mapping.Values()
	for _, pair := range mappingValues {
		keyStr, keyErr := pair[0].Data()
		valStr, valErr := pair[1].Data()
		if keyErr != nil || valErr != nil {
			continue // Skip invalid entries
		}
		values[keyStr] = valStr
	}

	return &Options{
		mapping: &mapping,
		values:  values,
	}, consumed, nil
}

// Bytes encodes the Options as an I2P Mapping.
// Keys are sorted for signature stability (handled by common/data.Mapping).
//
// Format:
//
//	+----+----+----+----+----+----+----+----+
//	|  size   | key_string (len + data)| =  |
//	+----+----+----+----+----+----+----+----+
//	| val_string (len + data)     | ;  | ...
//	+----+----+----+----+----+----+----+----+
func (o *Options) Bytes() ([]byte, error) {
	if o == nil || len(o.values) == 0 {
		// Empty mapping: 2-byte size of 0
		return []byte{0x00, 0x00}, nil
	}

	// If we have a parsed mapping, use its serialization
	if o.mapping != nil {
		return o.mapping.Data(), nil
	}

	// Build mapping from Go map using GoMapToMapping
	mapping, err := data.GoMapToMapping(o.values)
	if err != nil {
		return nil, fmt.Errorf("options: failed to create mapping: %w", err)
	}

	return mapping.Data(), nil
}

// Len returns the encoded length of the Options in bytes.
// This includes the 2-byte size field plus the content.
func (o *Options) Len() int {
	if o == nil || len(o.values) == 0 {
		return 2 // Just size field for empty mapping
	}

	// If we have a mapping, use its data length
	if o.mapping != nil {
		return len(o.mapping.Data())
	}

	// Otherwise estimate by encoding
	data, err := o.Bytes()
	if err != nil {
		return 2
	}
	return len(data)
}

// IsEmpty returns true if the Options contains no key/value pairs.
func (o *Options) IsEmpty() bool {
	return o == nil || len(o.values) == 0
}

// Get retrieves a value by key, returning empty string if not found.
func (o *Options) Get(key string) string {
	if o == nil || o.values == nil {
		return ""
	}
	return o.values[key]
}

// Set adds or updates a key/value pair.
// This invalidates any cached mapping serialization.
func (o *Options) Set(key, value string) {
	if o.values == nil {
		o.values = make(map[string]string)
	}
	o.values[key] = value
	o.mapping = nil // Invalidate cached mapping
}

// Has returns true if the key exists in the Options.
func (o *Options) Has(key string) bool {
	if o == nil || o.values == nil {
		return false
	}
	_, ok := o.values[key]
	return ok
}

// ToMap returns a copy of the options as a Go map.
func (o *Options) ToMap() map[string]string {
	if o == nil || o.values == nil {
		return make(map[string]string)
	}
	result := make(map[string]string, len(o.values))
	for k, v := range o.values {
		result[k] = v
	}
	return result
}

// NewOptions creates Options from a Go map.
func NewOptions(m map[string]string) *Options {
	if m == nil {
		return EmptyOptions()
	}
	values := make(map[string]string, len(m))
	for k, v := range m {
		values[k] = v
	}
	return &Options{
		mapping: nil,
		values:  values,
	}
}

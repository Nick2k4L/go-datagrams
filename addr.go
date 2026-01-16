package datagrams

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// I2PAddr represents an I2P destination with a port number.
// It implements the net.Addr interface for compatibility with Go's networking APIs.
//
// I2P destinations are base64-encoded strings that uniquely identify an endpoint
// in the I2P network. Ports provide application-level multiplexing on top of a
// single I2CP session.
type I2PAddr struct {
	// Destination is the I2P destination string (base64-encoded)
	// Empty string represents an unknown or anonymous sender (e.g., Raw datagrams)
	Destination string

	// Port is the UDP port number for application-level routing (1-65535)
	Port uint16
}

// Network returns the network type identifier for I2P addresses.
// This implements net.Addr.Network().
func (a *I2PAddr) Network() string {
	return "i2p"
}

// String returns a human-readable representation of the I2P address.
// Format: "<destination>:<port>" or "<port>" if destination is unknown.
// This implements net.Addr.String().
func (a *I2PAddr) String() string {
	if a.Destination == "" {
		// Anonymous/unknown sender (e.g., Raw datagram)
		return fmt.Sprintf(":%d", a.Port)
	}

	// Truncate long destinations for readability (first 16 chars + "...")
	dest := a.Destination
	if len(dest) > 16 {
		dest = dest[:16] + "..."
	}

	return fmt.Sprintf("%s:%d", dest, a.Port)
}

// ParseI2PAddr parses a string into an I2PAddr.
// Accepts formats:
//   - "destination:port" - full address with destination and port
//   - ":port" - port only (destination left empty)
//   - "destination" - destination only (port defaults to 0)
//
// Returns an error if the port is invalid or out of range.
func ParseI2PAddr(addr string) (*I2PAddr, error) {
	if addr == "" {
		return nil, fmt.Errorf("empty address string")
	}

	// Split on last colon to handle destination strings containing colons
	parts := strings.Split(addr, ":")
	if len(parts) == 1 {
		// Destination only, no port specified
		return &I2PAddr{
			Destination: parts[0],
			Port:        0,
		}, nil
	}

	// Extract port from last segment
	portStr := parts[len(parts)-1]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	// Join all parts except the last as the destination
	destination := strings.Join(parts[:len(parts)-1], ":")

	return &I2PAddr{
		Destination: destination,
		Port:        uint16(port),
	}, nil
}

// Equal returns true if two I2P addresses are equal.
// Compares both destination string and port number.
func (a *I2PAddr) Equal(other *I2PAddr) bool {
	if a == nil || other == nil {
		return a == other
	}
	return a.Destination == other.Destination && a.Port == other.Port
}

// AsNetAddr returns the I2PAddr as a net.Addr interface.
// This is a convenience method for type assertion-free usage.
func (a *I2PAddr) AsNetAddr() net.Addr {
	return a
}

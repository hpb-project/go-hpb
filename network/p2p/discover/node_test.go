package discover

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

func init() {
	lookupIPFunc = func(name string) ([]net.IP, error) {
		if name == "node.example.org" {
			return []net.IP{{33, 44, 55, 66}}, nil
		}
		return nil, errors.New("no such host")
	}
}

var parseNodeTests = []struct {
	input      string
	wantError  string
	wantResult *Node
}{
	// Complete node URLs with IP address and ports
	{
		input:     "hnode://1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439@invalid.:3",
		wantError: `no such host`,
	},
	{
		input:     "hnode://1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439@127.0.0.1:foo",
		wantError: `invalid port`,
	},
	{
		input:     "hnode://1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439@127.0.0.1:3?discport=foo",
		wantError: `invalid discport in query`,
	},
	{
		input: "hnode://1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439@127.0.0.1:52150",
		wantResult: NewNode(
			hexID("1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
			net.IP{127, 0, 0, 1},
			52150,
			52150,
		),
	},
	{
		input: "Hnode://1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439@[2001:db8:3c4d:15::abcd:ef12]:52150",
		wantResult: NewNode(
			hexID("1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
			net.ParseIP("2001:db8:3c4d:15::abcd:ef12"),
			52150,
			52150,
		),
	},
	{
		input: "hnode://1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439@[::]:52150",
		wantResult: NewNode(
			hexID("1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
			net.ParseIP("::"),
			52150,
			52150,
		),
	},
	{
		input: "hnode://1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439@127.0.0.1:52150?discport=22334",
		wantResult: NewNode(
			hexID("1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
			net.IP{0x7f, 0x0, 0x0, 0x1},
			22334,
			52150,
		),
	},
	// Incomplete node URLs with no address
	{
		input: "hnode://1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439",
		wantResult: NewNode(
			hexID("1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
			nil, 0, 0,
		),
	},
	// Invalid URLs
	{
		input:     "",
		wantError: `invalid URL scheme, want "hnode"`,
	},
	{
		input:     "01010101",
		wantError: `invalid node ID (wrong length, want 128 hex chars)`,
	},
	{
		input:     "hnode://01010101@123.124.125.126:3",
		wantError: `invalid node ID (wrong length, want 128 hex chars)`,
	},
	{
		input:     "hnode://01010101",
		wantError: `invalid node ID (wrong length, want 128 hex chars)`,
	},
	{
		input:     "http://foobar",
		wantError: `invalid URL scheme, want "hnode"`,
	},
	// {
	// 	input:     "://foo",
	// 	wantError: `parse "://foo": missing protocol scheme`,
	// },
}

func hexID(h string) NodeID {
	k, err := HexID(h)
	if err != nil {
		panic(err)
	}
	return k
}

func TestParseNode(t *testing.T) {
	for _, test := range parseNodeTests {
		n, err := ParseNode(test.input)
		if test.wantError != "" {
			if err == nil {
				t.Errorf("test %q:\n  got nil error, expected %#q", test.input, test.wantError)
				continue
			} else if !strings.Contains(err.Error(), test.wantError) {
				t.Errorf("test %q:\n  got error %#q, expected %#q", test.input, err.Error(), test.wantError)
				continue
			}
		} else {
			if err != nil {
				t.Errorf("test %q:\n  unexpected error: %v", test.input, err)
				continue
			}
			if !reflect.DeepEqual(n, test.wantResult) {
				t.Errorf("test %q:\n  result mismatch:\ngot:  %#v\nwant: %#v", test.input, n, test.wantResult)
			}
		}
	}
}

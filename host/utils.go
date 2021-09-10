package host

import (
	"net"
	"strconv"
	"strings"
)

// SplitDomainName splits a name string into it's labels.
// www.miek.nl. returns []string{"www", "miek", "nl"}
// .www.miek.nl. returns []string{"", "www", "miek", "nl"},
// The root label (.) returns nil. Note that using
// strings.Split(s) will work in most cases, but does not handle
// escaped dots (\.) for instance.
// s must be a syntactically valid domain name, see IsDomainName.
func SplitDomainName(s string) (labels []string) {
	if s == "" {
		return nil
	}
	fqdnEnd := 0 // offset of the final '.' or the length of the name
	idx := Split(s)
	begin := 0
	if IsFqdn(s) {
		fqdnEnd = len(s) - 1
	} else {
		fqdnEnd = len(s)
	}

	switch len(idx) {
	case 0:
		return nil
	case 1:
		// no-op
	default:
		for _, end := range idx[1:] {
			labels = append(labels, s[begin:end-1])
			begin = end
		}
	}

	return append(labels, s[begin:fqdnEnd])
}

// Split splits a name s into its label indexes.
// www.miek.nl. returns []int{0, 4, 9}, www.miek.nl also returns []int{0, 4, 9}.
// The root name (.) returns nil. Also see SplitDomainName.
// s must be a syntactically valid domain name.
func Split(s string) []int {
	if s == "." {
		return nil
	}
	idx := make([]int, 1, 3)
	off := 0
	end := false

	for {
		off, end = NextLabel(s, off)
		if end {
			return idx
		}
		idx = append(idx, off)
	}
}

// NextLabel returns the index of the start of the next label in the
// string s starting at offset.
// The bool end is true when the end of the string has been reached.
// Also see PrevLabel.
func NextLabel(s string, offset int) (i int, end bool) {
	if s == "" {
		return 0, true
	}
	for i = offset; i < len(s)-1; i++ {
		if s[i] != '.' {
			continue
		}
		j := i - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-i)%2 == 0 {
			continue
		}

		return i + 1, false
	}
	return i + 1, true
}

// PrevLabel returns the index of the label when starting from the right and
// jumping n labels to the left.
// The bool start is true when the start of the string has been overshot.
// Also see NextLabel.
func PrevLabel(s string, n int) (i int, start bool) {
	if s == "" {
		return 0, true
	}
	if n == 0 {
		return len(s), false
	}

	l := len(s) - 1
	if s[l] == '.' {
		l--
	}

	for ; l >= 0 && n > 0; l-- {
		if s[l] != '.' {
			continue
		}
		j := l - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-l)%2 == 0 {
			continue
		}

		n--
		if n == 0 {
			return l + 1, false
		}
	}

	return 0, n > 1
}

// IsFqdn checks if a domain name is fully qualified.
func IsFqdn(s string) bool {
	s2 := strings.TrimSuffix(s, ".")
	if s == s2 {
		return false
	}

	i := strings.LastIndexFunc(s2, func(r rune) bool {
		return r != '\\'
	})

	// Test whether we have an even number of escape sequences before
	// the dot or none.
	return (len(s2)-i)%2 != 0
}

type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "host: <nil>"
	}
	return "host: " + e.err
}

const hexDigit = "0123456789abcdef"

// ReverseAddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address suitable for reverse DNS (PTR) record lookups or an error if it fails
// to parse the IP address.
func ReverseAddr(addr string) (arpa string, err error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", &Error{err: "unrecognized address: " + addr}
	}
	if v4 := ip.To4(); v4 != nil {
		buf := make([]byte, 0, net.IPv4len*4+len("in-addr.arpa."))
		// Add it, in reverse, to the buffer
		for i := len(v4) - 1; i >= 0; i-- {
			buf = strconv.AppendInt(buf, int64(v4[i]), 10)
			buf = append(buf, '.')
		}
		// Append "in-addr.arpa." and return (buf already has the final .)
		buf = append(buf, "in-addr.arpa."...)
		return string(buf), nil
	}
	// Must be IPv6
	buf := make([]byte, 0, net.IPv6len*4+len("ip6.arpa."))
	// Add it, in reverse, to the buffer
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigit[v&0xF], '.', hexDigit[v>>4], '.')
	}
	// Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, "ip6.arpa."...)
	return string(buf), nil
}

func SetIfNotEmpty(s string, d string) string {
	if s != "" {
		return s
	}
	return d
}

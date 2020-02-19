package scanner

import (
	"errors"
	"math"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// IPProvider is an instance of the LCG-based IP address generator
type IPProvider struct {
	i, m, a, b int64
	seed       int64 // start position
	increment  int64 // how many IPs should be given out
	counter    int64
	offset     int64
	wrap       bool
	start      bool
}

// NewIPProvider returns a pointer to a new IPProvider struct
func NewIPProvider(seed string, increment, offset int64) *IPProvider {
	ip := new(IPProvider)

	ip.m = int64(math.Pow(2, 32))
	ip.a = 2147483655
	ip.b = 7

	tmp := net.ParseIP(seed)
	if tmp == nil {
		log.WithFields(log.Fields{
			"seed": seed,
		}).Fatal("Invalid seed")
	}
	ip.seed = ipToInt(tmp)

	if increment < 0 {
		increment = 0 // values lower than zero are not allowed
	}
	ip.increment = increment
	ip.counter = 0

	ip.i = (ip.seed % ip.m)

	ip.wrap = false
	ip.start = true

	if offset != 0 {
		for i := int64(0); i < offset; i++ {
			ip.generateRand()
		}
	}
	return ip
}

// generateRand updates the LCG and returns a new random number
func (ip *IPProvider) generateRand() int64 {
	// Update LCG
	ip.i = ((ip.a * ip.i) + ip.b) % ip.m

	// Check if we wrapped around
	if ip.wrap == false {
		if ip.i == (ip.seed % ip.m) {
			ip.wrap = true
		}
		return ip.i
	}

	return 0
}

// GenerateNextRandomIP returns the next IP address skipping private and other reserved ranges
func (ip *IPProvider) GenerateNextRandomIP() (net.IP, error) {
	if ip.increment == 0 || ip.counter < ip.increment {

		if ip.start {
			ip.start = false
			ip.counter++
			return intToIP(ip.seed), nil
		}

		ipAddrInt := ip.generateRand()

		// If IP address is bad, regenerate
		for ip.wrap || isGoodIP(ipAddrInt) == false { // TODO: IP blacklist missing
			// Did wrap
			if ip.wrap {
				return intToIP(0), errors.New("wrapped around")
			}
			ipAddrInt = ip.generateRand()
		}
		ip.counter++
		return intToIP(ipAddrInt), nil
	}

	return intToIP(ip.i), errors.New("counter reached end")
}

// isGoodIP checks whether IP address is good (i.e. not in an invalid range)
func isGoodIP(ipAddrInt int64) bool {
	firstByte := (ipAddrInt & 0xff000000) >> 24

	// Fast evaluation for addresses which are *definitely not* in bad ranges
	if (firstByte > 0 && firstByte < 10) ||
		(firstByte > 10 && firstByte < 100) ||
		(firstByte > 100 && firstByte < 127) ||
		(firstByte > 127 && firstByte < 169) ||
		(firstByte > 169 && firstByte < 172) ||
		(firstByte > 172 && firstByte < 192) ||
		(firstByte > 192 && firstByte < 198) ||
		(firstByte > 198 && firstByte < 203) ||
		(firstByte > 203 && firstByte < 224) {
		return true
	}
	secondByte := (ipAddrInt & 0x00ff0000) >> 16

	// Edge cases for second byte, IP address is good
	if (firstByte == 100 && (secondByte < 64 || secondByte > 127)) ||
		(firstByte == 172 && (secondByte < 16 || secondByte > 31)) ||
		(firstByte == 169 && secondByte != 254) ||
		(firstByte == 192 && (secondByte != 0 && secondByte != 88 && secondByte != 168)) ||
		(firstByte == 198 && secondByte != 51) ||
		(firstByte == 203 && secondByte != 0) {
		return true
	}
	thirdByte := (ipAddrInt & 0x0000ff00) >> 8

	// Edge cases for third byte, IP address is good
	if (firstByte == 192 && secondByte == 0 && (thirdByte != 0 && thirdByte != 2)) ||
		(firstByte == 192 && secondByte == 88 && thirdByte != 99) ||
		(firstByte == 198 && secondByte == 51 && thirdByte != 100) ||
		(firstByte == 213 && secondByte == 0 && thirdByte != 113) {
		return true
	}
	// IP must be bad as good edge cases were not met
	return false
}

// intToIP converts the generated integer to a net.IPv4
func intToIP(ipnr int64) net.IP {
	var bytes [4]byte
	bytes[0] = byte(ipnr & 0xFF)
	bytes[1] = byte((ipnr >> 8) & 0xFF)
	bytes[2] = byte((ipnr >> 16) & 0xFF)
	bytes[3] = byte((ipnr >> 24) & 0xFF)

	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
}

// ipToInt converts a net.IP to the corresponding int64
func ipToInt(ipnr net.IP) int64 {
	bits := strings.Split(ipnr.String(), ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum int64

	sum += int64(b0) << 24
	sum += int64(b1) << 16
	sum += int64(b2) << 8
	sum += int64(b3)

	return sum
}

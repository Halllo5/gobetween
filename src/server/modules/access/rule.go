package access

/**
 * rule.go - access rule
 *
 * @author Yaroslav Pogrebnyak <yyyaroslav@gmail.com>
 */

import (
	"errors"
	"net"
	"strings"

	country "github.com/mikekonan/go-countries"
	"github.com/yyyar/gobetween/geoip"
)

/**
 * AccessRule defines order (access, deny)
 * and IP or Network
 */
type AccessRule struct {
	Allow     bool
	IsNetwork bool
	IsGeoIP   bool
	Ip        *net.IP
	Network   *net.IPNet
	Country   *string
}

/**
 * Parses string to AccessRule
 */
func ParseAccessRule(rule string) (*AccessRule, error) {
	parts := strings.Split(rule, " ")
	if len(parts) != 2 {
		return nil, errors.New("Bad access rule format: " + rule)
	}

	r := parts[0]
	cidrOrIp := parts[1]

	if r != "allow" && r != "deny" {
		return nil, errors.New("Cant parse rule definition " + rule)
	}

	// try check if cidrOrIp is ip and handle

	ipShould := net.ParseIP(cidrOrIp)
	if ipShould != nil {
		return &AccessRule{
			Allow:     r == "allow",
			Ip:        &ipShould,
			IsNetwork: false,
			Network:   nil,
			IsGeoIP:   false,
			Country:   nil,
		}, nil
	}

	_, ipNetShould, _ := net.ParseCIDR(cidrOrIp)
	if ipNetShould != nil {
		return &AccessRule{
			Allow:     r == "allow",
			Ip:        nil,
			IsNetwork: true,
			Network:   ipNetShould,
			IsGeoIP:   false,
			Country:   nil,
		}, nil
	}

	_, ok := country.ByAlpha2CodeStr(cidrOrIp)
	if ok {
		return &AccessRule{
			Allow:     r == "allow",
			Ip:        nil,
			IsNetwork: false,
			Network:   nil,
			IsGeoIP:   true,
			Country:   &cidrOrIp,
		}, nil
	}

	return nil, errors.New("Cant parse acces rule target, not an ip or cidr: " + cidrOrIp)
}

/**
 * Checks if ip matches access rule
 */
func (this *AccessRule) Matches(ip *net.IP) bool {
	if this.IsGeoIP {
		return geoip.Lookup(ip) == *this.Country
	}
	switch this.IsNetwork {
	case true:
		return this.Network.Contains(*ip)
	case false:
		return (*this.Ip).Equal(*ip)
	}

	return false
}

/**
 * Checks is it's allow or deny rule
 */
func (this *AccessRule) Allows() bool {
	return this.Allow
}

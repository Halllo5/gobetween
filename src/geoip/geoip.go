package geoip

import (
	"net"

	"github.com/oschwald/geoip2-golang"
	"github.com/yyyar/gobetween/config"
	"github.com/yyyar/gobetween/logging"
)

var db *geoip2.Reader

func Load(cfg config.Config) error {
	var err error
	if !cfg.GeoIP.Enabled {
		return nil
	}
	db, err = geoip2.Open(cfg.GeoIP.Location)
	if err != nil {
		return err
	}
	return nil
}

func Lookup(ip *net.IP) string {
	if db == nil {
		log := logging.For("geoip")
		log.Warn("geoip2 db not init")
		return ""
	}
	record, err := db.Country(*ip)
	if err != nil {
		return ""
	}
	return record.Country.IsoCode
}

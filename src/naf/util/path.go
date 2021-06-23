//+build !debug

package util

import (
	"free5gc/lib/path_util"
)

var NafLogPath = path_util.Gofree5gcPath("free5gc/nafsslkey.log")
var NafPemPath = path_util.Gofree5gcPath("free5gc/support/TLS/naf.pem")
var NafKeyPath = path_util.Gofree5gcPath("free5gc/support/TLS/naf.key")
var DefaultNafConfigPath = path_util.Gofree5gcPath("free5gc/config/nafcfg.conf")

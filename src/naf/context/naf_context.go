package context

import (
	"regexp"
	"sync"

	"free5gc/lib/openapi/models"
	"free5gc/src/naf/logger"
)

type NAFContext struct {
	suciSupiMap  sync.Map
	UePool       sync.Map
	NfId         string
	GroupID      string
	SBIPort      int
	RegisterIPv4 string
	BindingIPv4  string
	Url          string
	UriScheme    models.UriScheme
	NrfUri       string
	NfService    map[models.ServiceName]models.NfService
	PlmnList     []models.PlmnId
	UdmUeauUrl   string
	snRegex      *regexp.Regexp
}

type NafUeContext struct {
	Supi               string
	Knaf               string
	Kseaf              string
	ServingNetworkName string
	AuthStatus         models.AuthResult
	UdmUeauUrl         string

	// for 5G AKA
	XresStar string

	// for EAP-AKA'
	K_aut string
	XRES  string
	Rand  string
}

type SuciSupiMap struct {
	SupiOrSuci string
	Supi       string
}

const (
	EAP_AKA_PRIME_TYPENUM = 50
)

// Attribute Types for EAP-AKA'
const (
	AT_RAND_ATTRIBUTE         = 1
	AT_AUTN_ATTRIBUTE         = 2
	AT_RES_ATTRIBUTE          = 3
	AT_MAC_ATTRIBUTE          = 11
	AT_NOTIFICATION_ATTRIBUTE = 12
	AT_IDENTITY_ATTRIBUTE     = 14
	AT_KDF_INPUT_ATTRIBUTE    = 23
	AT_KDF_ATTRIBUTE          = 24
)

var nafContext NAFContext

func Init() {
	if snRegex, err := regexp.Compile("5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org"); err != nil {
		logger.ContextLog.Warnf("SN compile error: %+v", err)
	} else {
		nafContext.snRegex = snRegex
	}
	InitNafContext(&nafContext)
}

func NewNafUeContext(identifier string) (nafUeContext *NafUeContext) {
	nafUeContext = new(NafUeContext)
	nafUeContext.Supi = identifier // supi
	return nafUeContext
}

func AddNafUeContextToPool(nafUeContext *NafUeContext) {
	nafContext.UePool.Store(nafUeContext.Supi, nafUeContext)
}

func CheckIfNafUeContextExists(ref string) bool {
	_, ok := nafContext.UePool.Load(ref)
	return ok
}

func GetNafUeContext(ref string) *NafUeContext {
	context, _ := nafContext.UePool.Load(ref)
	nafUeContext := context.(*NafUeContext)
	return nafUeContext
}

func AddSuciSupiPairToMap(supiOrSuci string, supi string) {
	newPair := new(SuciSupiMap)
	newPair.SupiOrSuci = supiOrSuci
	newPair.Supi = supi
	nafContext.suciSupiMap.Store(supiOrSuci, newPair)
}

func CheckIfSuciSupiPairExists(ref string) bool {
	_, ok := nafContext.suciSupiMap.Load(ref)
	return ok
}

func GetSupiFromSuciSupiMap(ref string) (supi string) {
	val, _ := nafContext.suciSupiMap.Load(ref)
	suciSupiMap := val.(*SuciSupiMap)
	supi = suciSupiMap.Supi
	return supi
}

func IsServingNetworkAuthorized(lookup string) bool {
	if nafContext.snRegex.MatchString(lookup) {
		return true
	} else {
		return false
	}
}

func GetSelf() *NAFContext {
	return &nafContext
}

func (a *NAFContext) GetSelfID() string {
	return a.NfId
}

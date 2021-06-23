/*
 * Namf_Communication
 *
 * AMF Communication Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package models

type UeContext struct {
	Supi                     string                  `json:"supi,omitempty"`
	SupiUnauthInd            bool                    `json:"supiUnauthInd,omitempty"`
	GpsiList                 []string                `json:"gpsiList,omitempty"`
	Pei                      string                  `json:"pei,omitempty"`
	UdmGroupId               string                  `json:"udmGroupId,omitempty"`
	// AusfGroupId              string                  `json:"ausfGroupId,omitempty"`
	NafGroupId               string                  `json:"ausfGroupId,omitempty"`
	RoutingIndicator         string                  `json:"routingIndicator,omitempty"`
	GroupList                []string                `json:"groupList,omitempty"`
	DrxParameter             string                  `json:"drxParameter,omitempty"`
	SubRfsp                  int32                   `json:"subRfsp,omitempty"`
	UsedRfsp                 int32                   `json:"usedRfsp,omitempty"`
	SubUeAmbr                *Ambr                   `json:"subUeAmbr,omitempty"`
	SmsSupport               SmsSupport              `json:"smsSupport,omitempty"`
	SmsfId                   string                  `json:"smsfId,omitempty"`
	SeafData                 *SeafData               `json:"seafData,omitempty"`
	Var5gMmCapability        string                  `json:"5gMmCapability,omitempty"`
	PcfId                    string                  `json:"pcfId,omitempty"`
	PcfAmPolicyUri           string                  `json:"pcfAmPolicyUri,omitempty"`
	AmPolicyReqTriggerList   []AmPolicyReqTrigger    `json:"amPolicyReqTriggerList,omitempty"`
	HpcfId                   string                  `json:"hpcfId,omitempty"`
	RestrictedRatList        []RatType               `json:"restrictedRatList,omitempty"`
	ForbiddenAreaList        []Area                  `json:"forbiddenAreaList,omitempty"`
	ServiceAreaRestriction   *ServiceAreaRestriction `json:"serviceAreaRestriction,omitempty"`
	RestrictedCoreNwTypeList []CoreNetworkType       `json:"restrictedCoreNwTypeList,omitempty"`
	EventSubscriptionList    []AmfEventSubscription  `json:"eventSubscriptionList,omitempty"`
	MmContextList            []MmContext             `json:"mmContextList,omitempty"`
	SessionContextList       []PduSessionContext     `json:"sessionContextList,omitempty"`
	TraceData                *TraceData              `json:"traceData,omitempty"`
}

package producer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/bronze1man/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"free5gc/lib/UeauCommon"
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi/models"
	naf_context "free5gc/src/naf/context"
	"free5gc/src/naf/logger"
)

func HandleEapAuthComfirmRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.Auth5gAkaComfirmLog.Infof("EapAuthComfirmRequest")

	updateEapSession := request.Body.(models.EapSession)
	eapSessionID := request.Params["authCtxId"]

	response, problemDetails := EapAuthComfirmRequestProcedure(updateEapSession, eapSessionID)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleAuth5gAkaComfirmRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.Auth5gAkaComfirmLog.Infof("Auth5gAkaComfirmRequest")
	updateConfirmationData := request.Body.(models.ConfirmationData)
	ConfirmationDataResponseID := request.Params["authCtxId"]

	response, problemDetails := Auth5gAkaComfirmRequestProcedure(updateConfirmationData, ConfirmationDataResponseID)
	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleUeAuthPostRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.UeAuthPostLog.Infof("HandleUeAuthPostRequest")
	updateAuthenticationInfo := request.Body.(models.AuthenticationInfo)

	response, locationURI, problemDetails := UeAuthPostRequestProcedure(updateAuthenticationInfo)
	respHeader := make(http.Header)
	respHeader.Set("Location", locationURI)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusCreated, respHeader, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

//func UeAuthPostRequestProcedure(updateAuthenticationInfo models.AuthenticationInfo) (
//    response *models.UeAuthenticationCtx, locationURI string, problemDetails *models.ProblemDetails) {
func UeAuthPostRequestProcedure(updateAuthenticationInfo models.AuthenticationInfo) (*models.UeAuthenticationCtx,
	string, *models.ProblemDetails) {
	var responseBody models.UeAuthenticationCtx
	var authInfoReq models.AuthenticationInfoRequest

	supiOrSuci := updateAuthenticationInfo.SupiOrSuci

	snName := updateAuthenticationInfo.ServingNetworkName
	servingNetworkAuthorized := naf_context.IsServingNetworkAuthorized(snName)
	if !servingNetworkAuthorized {
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "SERVING_NETWORK_NOT_AUTHORIZED"
		problemDetails.Status = http.StatusForbidden
		logger.UeAuthPostLog.Infoln("403 forbidden: serving network NOT AUTHORIZED")
		return nil, "", &problemDetails
	}
	logger.UeAuthPostLog.Infoln("Serving network authorized")

	responseBody.ServingNetworkName = snName
	authInfoReq.ServingNetworkName = snName
	self := naf_context.GetSelf()
	authInfoReq.NafInstanceId = self.GetSelfID()

	if updateAuthenticationInfo.ResynchronizationInfo != nil {
		logger.UeAuthPostLog.Warningln("Auts: ", updateAuthenticationInfo.ResynchronizationInfo.Auts)
		nafCurrentSupi := naf_context.GetSupiFromSuciSupiMap(supiOrSuci)
		logger.UeAuthPostLog.Warningln(nafCurrentSupi)
		nafCurrentContext := naf_context.GetNafUeContext(nafCurrentSupi)
		logger.UeAuthPostLog.Warningln(nafCurrentContext.Rand)
		updateAuthenticationInfo.ResynchronizationInfo.Rand = nafCurrentContext.Rand
		logger.UeAuthPostLog.Warningln("Rand: ", updateAuthenticationInfo.ResynchronizationInfo.Rand)
		authInfoReq.ResynchronizationInfo = updateAuthenticationInfo.ResynchronizationInfo
	}

	udmUrl := getUdmUrl(self.NrfUri)
	client := createClientToUdmUeau(udmUrl)
	authInfoResult, _, err := client.GenerateAuthDataApi.GenerateAuthData(context.Background(), supiOrSuci, authInfoReq)
	if err != nil {
		logger.UeAuthPostLog.Infoln(err.Error())
		var problemDetails models.ProblemDetails
		if authInfoResult.AuthenticationVector == nil {
			problemDetails.Cause = "AV_GENERATION_PROBLEM"
		} else {
			problemDetails.Cause = "UPSTREAM_SERVER_ERROR"
		}
		problemDetails.Status = http.StatusInternalServerError
		return nil, "", &problemDetails
	}

	ueid := authInfoResult.Supi
	nafUeContext := naf_context.NewNafUeContext(ueid)
	nafUeContext.ServingNetworkName = snName
	nafUeContext.AuthStatus = models.AuthResult_ONGOING
	nafUeContext.UdmUeauUrl = udmUrl
	naf_context.AddNafUeContextToPool(nafUeContext)

	logger.UeAuthPostLog.Infof("Add SuciSupiPair (%s, %s) to map.\n", supiOrSuci, ueid)
	naf_context.AddSuciSupiPairToMap(supiOrSuci, ueid)

	locationURI := self.Url + "/nnaf-auth/v1/ue-authentications/" + supiOrSuci
	putLink := locationURI
	if authInfoResult.AuthType == models.AuthType__5_G_AKA {
		logger.UeAuthPostLog.Infoln("Use 5G AKA auth method")
		putLink += "/5g-aka-confirmation"

		// Derive HXRES* from XRES*
		concat := authInfoResult.AuthenticationVector.Rand + authInfoResult.AuthenticationVector.XresStar
		var hxresStarBytes []byte
		if bytes, err := hex.DecodeString(concat); err != nil {
			logger.Auth5gAkaComfirmLog.Warnf("decode error: %+v", err)
		} else {
			hxresStarBytes = bytes
		}
		hxresStarAll := sha256.Sum256(hxresStarBytes)
		hxresStar := hex.EncodeToString(hxresStarAll[16:]) // last 128 bits
		logger.Auth5gAkaComfirmLog.Infof("XresStar = %x\n", authInfoResult.AuthenticationVector.XresStar)

		// Derive Kseaf from Knaf
		Knaf := authInfoResult.AuthenticationVector.Knaf
		var KnafDecode []byte
		if nafDecode, err := hex.DecodeString(Knaf); err != nil {
			logger.Auth5gAkaComfirmLog.Warnf("NAF decode failed: %+v", err)
		} else {
			KnafDecode = nafDecode
		}
		P0 := []byte(snName)
		Kseaf := UeauCommon.GetKDFValue(KnafDecode, UeauCommon.FC_FOR_KSEAF_DERIVATION, P0, UeauCommon.KDFLen(P0))
		nafUeContext.XresStar = authInfoResult.AuthenticationVector.XresStar
		nafUeContext.Knaf = Knaf
		nafUeContext.Kseaf = hex.EncodeToString(Kseaf)
		nafUeContext.Rand = authInfoResult.AuthenticationVector.Rand

		var av5gAka models.Av5gAka
		av5gAka.Rand = authInfoResult.AuthenticationVector.Rand
		av5gAka.Autn = authInfoResult.AuthenticationVector.Autn
		av5gAka.HxresStar = hxresStar

		responseBody.Var5gAuthData = av5gAka

	} else if authInfoResult.AuthType == models.AuthType_EAP_AKA_PRIME {
		logger.UeAuthPostLog.Infoln("Use EAP-AKA' auth method")
		putLink += "/eap-session"

		identity := ueid
		ikPrime := authInfoResult.AuthenticationVector.IkPrime
		ckPrime := authInfoResult.AuthenticationVector.CkPrime
		RAND := authInfoResult.AuthenticationVector.Rand
		AUTN := authInfoResult.AuthenticationVector.Autn
		XRES := authInfoResult.AuthenticationVector.Xres
		nafUeContext.XRES = XRES

		nafUeContext.Rand = authInfoResult.AuthenticationVector.Rand

		K_encr, K_aut, K_re, MSK, EMSK := eapAkaPrimePrf(ikPrime, ckPrime, identity)
		_, _, _, _, _ = K_encr, K_aut, K_re, MSK, EMSK
		nafUeContext.K_aut = K_aut
		Knaf := EMSK[0:32]
		nafUeContext.Knaf = Knaf
		var KnafDecode []byte
		if nafDecode, err := hex.DecodeString(Knaf); err != nil {
			logger.Auth5gAkaComfirmLog.Warnf("AUSF decode failed: %+v", err)
		} else {
			KnafDecode = nafDecode
		}
		P0 := []byte(snName)
		Kseaf := UeauCommon.GetKDFValue(KnafDecode, UeauCommon.FC_FOR_KSEAF_DERIVATION, P0, UeauCommon.KDFLen(P0))
		nafUeContext.Kseaf = hex.EncodeToString(Kseaf)

		var eapPkt radius.EapPacket
		var randIdentifier int
		rand.Seed(time.Now().Unix())

		eapPkt.Code = radius.EapCode(1)
		randIdentifier = rand.Intn(256)
		eapPkt.Identifier = uint8(randIdentifier)
		eapPkt.Type = radius.EapType(50) // accroding to RFC5448 6.1
		var atRand, atAutn, atKdf, atKdfInput, atMAC string
		if atRandTmp, err := EapEncodeAttribute("AT_RAND", RAND); err != nil {
			logger.Auth5gAkaComfirmLog.Warnf("EAP encode RAND failed: %+v", err)
		} else {
			atRand = atRandTmp
		}
		if atAutnTmp, err := EapEncodeAttribute("AT_AUTN", AUTN); err != nil {
			logger.Auth5gAkaComfirmLog.Warnf("EAP encode AUTN failed: %+v", err)
		} else {
			atAutn = atAutnTmp
		}
		if atKdfTmp, err := EapEncodeAttribute("AT_KDF", snName); err != nil {
			logger.Auth5gAkaComfirmLog.Warnf("EAP encode KDF failed: %+v", err)
		} else {
			atKdf = atKdfTmp
		}
		if atKdfInputTmp, err := EapEncodeAttribute("AT_KDF_INPUT", snName); err != nil {
			logger.Auth5gAkaComfirmLog.Warnf("EAP encode KDF failed: %+v", err)
		} else {
			atKdfInput = atKdfInputTmp
		}
		if atMACTmp, err := EapEncodeAttribute("AT_MAC", ""); err != nil {
			logger.Auth5gAkaComfirmLog.Warnf("EAP encode MAC failed: %+v", err)
		} else {
			atMAC = atMACTmp
		}

		dataArrayBeforeMAC := atRand + atAutn + atMAC + atKdf + atKdfInput
		eapPkt.Data = []byte(dataArrayBeforeMAC)
		encodedPktBeforeMAC := eapPkt.Encode()

		MACvalue := CalculateAtMAC([]byte(K_aut), encodedPktBeforeMAC)
		atMacNum := fmt.Sprintf("%02x", naf_context.AT_MAC_ATTRIBUTE)
		var atMACfirstRow []byte
		if atMACfirstRowTmp, err := hex.DecodeString(atMacNum + "05" + "0000"); err != nil {
			logger.Auth5gAkaComfirmLog.Warnf("MAC decode failed: %+v", err)
		} else {
			atMACfirstRow = atMACfirstRowTmp
		}
		wholeAtMAC := append(atMACfirstRow, MACvalue...)

		atMAC = string(wholeAtMAC)
		dataArrayAfterMAC := atRand + atAutn + atMAC + atKdf + atKdfInput

		eapPkt.Data = []byte(dataArrayAfterMAC)
		encodedPktAfterMAC := eapPkt.Encode()
		responseBody.Var5gAuthData = base64.StdEncoding.EncodeToString(encodedPktAfterMAC)
	}

	var linksValue = models.LinksValueSchema{Href: putLink}
	responseBody.Links = make(map[string]models.LinksValueSchema)
	responseBody.Links["link"] = linksValue
	responseBody.AuthType = authInfoResult.AuthType

	return &responseBody, locationURI, nil
}

//func Auth5gAkaComfirmRequestProcedure(updateConfirmationData models.ConfirmationData,
//	ConfirmationDataResponseID string) (response *models.ConfirmationDataResponse,
//  problemDetails *models.ProblemDetails) {

func Auth5gAkaComfirmRequestProcedure(updateConfirmationData models.ConfirmationData,
	ConfirmationDataResponseID string) (*models.ConfirmationDataResponse, *models.ProblemDetails) {
	var responseBody models.ConfirmationDataResponse
	success := false
	responseBody.AuthResult = models.AuthResult_FAILURE

	if !naf_context.CheckIfSuciSupiPairExists(ConfirmationDataResponseID) {
		logger.Auth5gAkaComfirmLog.Infof("supiSuciPair does not exist, confirmation failed (queried by %s)\n",
			ConfirmationDataResponseID)
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "USER_NOT_FOUND"
		problemDetails.Status = http.StatusBadRequest
		return nil, &problemDetails
	}

	currentSupi := naf_context.GetSupiFromSuciSupiMap(ConfirmationDataResponseID)
	if !naf_context.CheckIfNafUeContextExists(currentSupi) {
		logger.Auth5gAkaComfirmLog.Infof("SUPI does not exist, confirmation failed (queried by %s)\n", currentSupi)
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "USER_NOT_FOUND"
		problemDetails.Status = http.StatusBadRequest
		return nil, &problemDetails
	}

	nafCurrentContext := naf_context.GetNafUeContext(currentSupi)
	servingNetworkName := nafCurrentContext.ServingNetworkName

	// Compare the received RES* with the stored XRES*
	logger.Auth5gAkaComfirmLog.Infof("res*: %x\nXres*: %x\n", updateConfirmationData.ResStar, nafCurrentContext.XresStar)
	if strings.Compare(updateConfirmationData.ResStar, nafCurrentContext.XresStar) == 0 {
		nafCurrentContext.AuthStatus = models.AuthResult_SUCCESS
		responseBody.AuthResult = models.AuthResult_SUCCESS
		success = true
		logger.Auth5gAkaComfirmLog.Infoln("5G AKA confirmation succeeded")
		responseBody.Kseaf = nafCurrentContext.Kseaf
	} else {
		nafCurrentContext.AuthStatus = models.AuthResult_FAILURE
		responseBody.AuthResult = models.AuthResult_FAILURE
		logConfirmFailureAndInformUDM(ConfirmationDataResponseID, models.AuthType__5_G_AKA, servingNetworkName,
			"5G AKA confirmation failed", nafCurrentContext.UdmUeauUrl)
	}

	if sendErr := sendAuthResultToUDM(currentSupi, models.AuthType__5_G_AKA, success, servingNetworkName,
		nafCurrentContext.UdmUeauUrl); sendErr != nil {
		logger.Auth5gAkaComfirmLog.Infoln(sendErr.Error())
		var problemDetails models.ProblemDetails
		problemDetails.Status = http.StatusInternalServerError
		problemDetails.Cause = "UPSTREAM_SERVER_ERROR"

		return nil, &problemDetails
	}

	responseBody.Supi = currentSupi
	return &responseBody, nil
}

// return response, problemDetails
func EapAuthComfirmRequestProcedure(updateEapSession models.EapSession, eapSessionID string) (*models.EapSession,
	*models.ProblemDetails) {
	var responseBody models.EapSession

	if !naf_context.CheckIfSuciSupiPairExists(eapSessionID) {
		logger.Auth5gAkaComfirmLog.Infoln("supiSuciPair does not exist, confirmation failed")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "USER_NOT_FOUND"
		return nil, &problemDetails
	}

	currentSupi := naf_context.GetSupiFromSuciSupiMap(eapSessionID)
	if !naf_context.CheckIfNafUeContextExists(currentSupi) {
		logger.Auth5gAkaComfirmLog.Infoln("SUPI does not exist, confirmation failed")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "USER_NOT_FOUND"
		return nil, &problemDetails
	}

	nafCurrentContext := naf_context.GetNafUeContext(currentSupi)
	servingNetworkName := nafCurrentContext.ServingNetworkName
	var eapPayload []byte
	if eapPayloadTmp, err := base64.StdEncoding.DecodeString(updateEapSession.EapPayload); err != nil {
		logger.Auth5gAkaComfirmLog.Warnf("EAP Payload decode failed: %+v", err)
	} else {
		eapPayload = eapPayloadTmp
	}

	eapGoPkt := gopacket.NewPacket(eapPayload, layers.LayerTypeEAP, gopacket.Default)
	eapLayer := eapGoPkt.Layer(layers.LayerTypeEAP)
	eapContent, _ := eapLayer.(*layers.EAP)

	if eapContent.Code != layers.EAPCodeResponse {
		logConfirmFailureAndInformUDM(eapSessionID, models.AuthType_EAP_AKA_PRIME, servingNetworkName,
			"eap packet code error", nafCurrentContext.UdmUeauUrl)
		nafCurrentContext.AuthStatus = models.AuthResult_FAILURE
		responseBody.AuthResult = models.AuthResult_ONGOING
		failEapAkaNoti := ConstructFailEapAkaNotification(eapContent.Id)
		responseBody.EapPayload = failEapAkaNoti
		return &responseBody, nil
	}
	switch nafCurrentContext.AuthStatus {
	case models.AuthResult_ONGOING:
		responseBody.KSeaf = nafCurrentContext.Kseaf
		responseBody.Supi = currentSupi
		Kautn := nafCurrentContext.K_aut
		XRES := nafCurrentContext.XRES
		RES, decodeOK := decodeResMac(eapContent.TypeData, eapContent.Contents, Kautn)
		if !decodeOK {
			nafCurrentContext.AuthStatus = models.AuthResult_FAILURE
			responseBody.AuthResult = models.AuthResult_ONGOING
			logConfirmFailureAndInformUDM(eapSessionID, models.AuthType_EAP_AKA_PRIME, servingNetworkName,
				"eap packet decode error", nafCurrentContext.UdmUeauUrl)
			failEapAkaNoti := ConstructFailEapAkaNotification(eapContent.Id)
			responseBody.EapPayload = failEapAkaNoti

		} else if XRES == string(RES) { // decodeOK && XRES == res, auth success
			logger.EapAuthComfirmLog.Infoln("Correct RES value, EAP-AKA' auth succeed")
			responseBody.AuthResult = models.AuthResult_SUCCESS
			eapSuccPkt := ConstructEapNoTypePkt(radius.EapCodeSuccess, eapContent.Id)
			responseBody.EapPayload = eapSuccPkt
			udmUrl := nafCurrentContext.UdmUeauUrl
			if sendErr := sendAuthResultToUDM(eapSessionID, models.AuthType_EAP_AKA_PRIME, true, servingNetworkName,
				udmUrl); sendErr != nil {
				logger.EapAuthComfirmLog.Infoln(sendErr.Error())
				var problemDetails models.ProblemDetails
				problemDetails.Cause = "UPSTREAM_SERVER_ERROR"
				return nil, &problemDetails
			}
			nafCurrentContext.AuthStatus = models.AuthResult_SUCCESS

		} else {
			nafCurrentContext.AuthStatus = models.AuthResult_FAILURE
			responseBody.AuthResult = models.AuthResult_ONGOING
			logConfirmFailureAndInformUDM(eapSessionID, models.AuthType_EAP_AKA_PRIME, servingNetworkName,
				"Wrong RES value, EAP-AKA' auth failed", nafCurrentContext.UdmUeauUrl)
			failEapAkaNoti := ConstructFailEapAkaNotification(eapContent.Id)
			responseBody.EapPayload = failEapAkaNoti
		}

	case models.AuthResult_FAILURE:
		eapFailPkt := ConstructEapNoTypePkt(radius.EapCodeFailure, uint8(eapPayload[1]))
		responseBody.EapPayload = eapFailPkt
		responseBody.AuthResult = models.AuthResult_FAILURE
	}

	return &responseBody, nil
}

package consumer

import (
	"context"
	"fmt"
	"free5gc/lib/openapi/Nnrf_NFManagement"
	"free5gc/lib/openapi/models"
	naf_context "free5gc/src/naf/context"
	"net/http"
	"strings"
	"time"
)

func BuildNFInstance(nafContext *naf_context.NAFContext) (profile models.NfProfile, err error) {
	profile.NfInstanceId = nafContext.NfId
	profile.NfType = models.NfType_NAF
	profile.NfStatus = models.NfStatus_REGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, nafContext.RegisterIPv4)
	services := []models.NfService{}
	for _, nfService := range nafContext.NfService {
		services = append(services, nfService)
	}
	if len(services) > 0 {
		profile.NfServices = &services
	}
	var nafInfo models.NafInfo
	nafInfo.GroupId = nafContext.GroupID
	profile.NafInfo = &nafInfo
	profile.PlmnList = &nafContext.PlmnList
	return
}

//func SendRegisterNFInstance(nrfUri, nfInstanceId string, profile models.NfProfile) (resouceNrfUri string,
//    retrieveNfInstanceID string, err error) {
func SendRegisterNFInstance(nrfUri, nfInstanceId string, profile models.NfProfile) (string, string, error) {
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	for {
		if _, resTmp, err := client.NFInstanceIDDocumentApi.RegisterNFInstance(context.TODO(), nfInstanceId,
			profile); err != nil || resTmp == nil {
			//TODO : add log
			fmt.Println(fmt.Errorf("NAF register to NRF Error[%v]", err))
			time.Sleep(2 * time.Second)
			continue
		} else {
			res = resTmp
		}
		status := res.StatusCode
		if status == http.StatusOK {
			// NFUpdate
			break
		} else if status == http.StatusCreated {
			// NFRegister
			resourceUri := res.Header.Get("Location")
			resourceNrfUri := resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
			retrieveNfInstanceID := resourceUri[strings.LastIndex(resourceUri, "/")+1:]
			return resourceNrfUri, retrieveNfInstanceID, nil
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("NRF return wrong status code %d", status))
		}
	}
	return "", "", nil
}

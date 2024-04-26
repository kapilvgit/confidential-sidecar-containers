// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package adns

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	RegisterServiceRequestURITemplate = "https://%s:8443/app/register-service"
	GetCertificateRequestURITemplate  = "https://%s:8443/app/get-certificate"
)

type EndpointAddress struct {
	Name      string `json:"name"`
	IpAddress string `json:"ip"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
}

type aciAttestation struct {
	Source          string `json:"source"`
	Evidence        string `json:"evidence"`
	Endorsements    string `json:"endorsements"`
	UvmEndorsements string `json:"uvm_endorsements"`
}

type endpointInformation struct {
	Address     EndpointAddress `json:"address"`
	Attestation string          `json:"attestation"`
}

type nodeInformation struct {
	Endpoint endpointInformation `json:"default"`
}

type registerServiceRequestBody struct {
	Csr             string          `json:"csr"`
	Contact         []string        `json:"contact"`
	NodeInformation nodeInformation `json:"node_information"`
}

type getCertificateRequestBody struct {
	ServiceName string `json:"service_dns_name"`
}

func GenerateCSR(privateKey *rsa.PrivateKey, domain string) ([]byte, error) {
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames: []string{domain},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create CSR")
	}

	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	logrus.Trace("CSR PEM: {}", string(csrPem))

	return csrBytes, nil
}

func RegisterService(adnsEndpoint *string, addr EndpointAddress, certState attest.CertState, uvmInfo common.UvmInformation) (key *rsa.PrivateKey, err error) {
	logrus.Info("Registering service with adns...")
	logrus.Debugf("adns endpoint: %v", adnsEndpoint)

	// Generate an RSA pair that will be used for TLS signing.
	logrus.Trace("Generating RSA key pair...")
	privateSigningKey, err := rsa.GenerateKey(rand.Reader, common.RSASize)
	if err != nil {
		return nil, errors.Wrapf(err, "rsa key pair generation failed")
	}

	logrus.Trace("Converting RSA key to PEM...")
	publicKeyDer := x509.MarshalPKCS1PublicKey(&(privateSigningKey.PublicKey))
	runtimeDataBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicKeyDer})

	// base64 decode the incoming encoded security policy
	inittimeDataBytes, err := base64.StdEncoding.DecodeString(uvmInfo.EncodedSecurityPolicy)
	if err != nil {
		return nil, err
	}

	logrus.Trace("Fetching attestation report...")
	var attestationReportFetcher attest.AttestationReportFetcher
	if attest.IsSNPVM() {
		attestationReportFetcher, err = attest.NewAttestationReportFetcher()
		if err != nil {
			return nil, err
		}
	} else {
		// Use dummy report if SEV device is not available
		hostData := attest.GenerateMAAHostData(inittimeDataBytes)
		attestationReportFetcher = attest.UnsafeNewFakeAttestationReportFetcher(hostData)
	}

	reportData := attest.GenerateMAAReportData(runtimeDataBytes)

	rawReport, err := attestationReportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		return nil, err
	}

	var uvmReferenceInfoBytes []byte
	if len(uvmInfo.EncodedUvmReferenceInfo) > 0 {
		uvmReferenceInfoBytes, err = base64.StdEncoding.DecodeString(uvmInfo.EncodedUvmReferenceInfo)
	}

	if err != nil {
		return nil, errors.Wrap(err, "Decoding UVM encoded security policy from Base64 format failed")
	}

	var base64urlEncodedUvmReferenceInfo string
	if len(uvmReferenceInfoBytes) > 0 {
		base64urlEncodedUvmReferenceInfo = base64.StdEncoding.EncodeToString(uvmReferenceInfoBytes)
	}
	logrus.Infof("base64urlEncodedUvmReferenceInfo: %s", base64urlEncodedUvmReferenceInfo)

	certString := uvmInfo.InitialCerts.VcekCert + uvmInfo.InitialCerts.CertificateChain
	vcekCertChain := []byte(certString)

	attestation := aciAttestation{
		Source:          "aci",
		Evidence:        base64.StdEncoding.EncodeToString(rawReport),
		Endorsements:    base64.StdEncoding.EncodeToString(vcekCertChain),
		UvmEndorsements: base64urlEncodedUvmReferenceInfo,
	}

	attestationBytes, _ := json.Marshal(attestation)
	nodeInfo := nodeInformation{
		Endpoint: endpointInformation{
			Address:     addr,
			Attestation: string(attestationBytes),
		},
	}

	csr, _ := GenerateCSR(privateSigningKey, addr.Name)

	contacts := [1]string{"kapilv@microsoft.com"}
	registerServiceBody := registerServiceRequestBody{
		Contact:         contacts[:],
		Csr:             base64.StdEncoding.EncodeToString(csr),
		NodeInformation: nodeInfo,
	}

	registerRequestJson, err := json.Marshal(registerServiceBody)
	if err != nil {
		return nil, errors.Wrapf(err, "marhalling register request failed")
	}

	logrus.Infof("ADNS register-service request %s:", registerRequestJson)

	if err := os.WriteFile("/request.json", []byte(registerRequestJson), 0666); err != nil {
		log.Fatal(err)
	}

	uri := fmt.Sprintf(RegisterServiceRequestURITemplate, *adnsEndpoint)
	logrus.Debugf("Posting register-service request to %s", uri)
	httpResponse, err := common.HTTPPRequest("POST", uri, registerRequestJson, "")
	if err != nil {
		return nil, errors.Wrapf(err, "ADNS register-service post request failed")
	}

	httpResponseBodyBytes, err := common.HTTPResponseBody(httpResponse)
	if err != nil {
		logrus.Debugf("ADNS Response header: %v", httpResponse)
		logrus.Debugf("ADNS Response body bytes: %s", string(httpResponseBodyBytes))
		return nil, errors.Wrapf(err, "pulling adns post response failed")
	}

	logrus.Debugf("Service registered with ADNS")
	logrus.Debugf("Waiting to fetch certificate")

	time.Sleep(10 * time.Second)

	getCertificateBody := getCertificateRequestBody{
		ServiceName: addr.Name,
	}

	getCertificateJson, err := json.Marshal(getCertificateBody)
	if err != nil {
		return nil, errors.Wrapf(err, "marhalling register request failed")
	}

	uri = fmt.Sprintf(GetCertificateRequestURITemplate, *adnsEndpoint)
	logrus.Debugf("Posting get-certificate request to %s", uri)
	httpResponse, err = common.HTTPPRequest("POST", uri, getCertificateJson, "")
	if err != nil {
		return nil, errors.Wrapf(err, "ADNS register-service post request failed")
	}

	httpResponseBodyBytes, err = common.HTTPResponseBody(httpResponse)
	if err != nil {
		logrus.Debugf("ADNS get-certificate response header: %v", httpResponse)
		logrus.Debugf("ADNS get-certificate response body bytes: %s", string(httpResponseBodyBytes))
		return nil, errors.Wrapf(err, "pulling adns post response failed")
	}

	// Retrieve MAA token from the JWT response returned by MAA
	var getCertificateResponse struct {
		Certificate string `json:"certificate"`
	}

	logrus.Info("Unmarshalling get-certificate Response...")
	if err = json.Unmarshal(httpResponseBodyBytes, &getCertificateResponse); err != nil {
		return nil, errors.Wrapf(err, "unmarshalling get-certificate http response body failed")
	}

	if getCertificateResponse.Certificate == "" {
		return nil, errors.New("empty certificate in adns response")
	}

	return privateSigningKey, nil
}

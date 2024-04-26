// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/adns"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	server "github.com/Microsoft/confidential-sidecar-containers/pkg/grpc/grpcserver"
	"github.com/sirupsen/logrus"
)

func usage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	serviceFQDN := flag.String("serviceFQDN", "", "Fully qualified domain name of service")
	ipAddress := flag.String("ipAddress", "", "IP address of the service")
	adnsEndpoint := flag.String("adnsEndpoint", "", "adns endpoint for service registration")
	azureInfoBase64string := flag.String("base64", "", "optional base64-encoded json string with azure information")
	logLevel := flag.String("loglevel", "warning", "Logging Level: trace, debug, info, warning, error, fatal, panic.")
	logFile := flag.String("logfile", "", "Logging Target: An optional file name/path. Omit for console output.")

	flag.Usage = usage

	flag.Parse()

	if *logFile != "" {
		// If the file doesn't exist, create it. If it exists, append to it.
		file, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatal(err)
		}
		defer file.Close()
		logrus.SetOutput(file)
	}

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: false, DisableQuote: true, DisableTimestamp: true})

	logrus.Infof("Starting %s...", os.Args[0])

	logrus.Infof("Args:")
	logrus.Infof("   Service FQDN:  %s", *serviceFQDN)
	logrus.Infof("   aDNS endpoint: %s", *adnsEndpoint)
	logrus.Infof("   IP address:    %s", *ipAddress)
	logrus.Infof("   Log Level:     %s", *logLevel)
	logrus.Infof("   Log File:      %s", *logFile)
	logrus.Debugf("  Azure info:    %s", *azureInfoBase64string)

	info := server.AzureInformation{}

	// Decode base64 attestation information only if it s not empty
	logrus.Info("Decoding base64 attestation information if not empty...")
	if *azureInfoBase64string != "" {
		bytes, err := base64.StdEncoding.DecodeString(*azureInfoBase64string)
		if err != nil {
			logrus.Fatalf("Failed to decode base64 attestation info: %s", err.Error())
		}

		err = json.Unmarshal(bytes, &info)
		if err != nil {
			logrus.Fatalf("Failed to unmarshal attestion info json into AzureInformation: %s", err.Error())
		}
	}

	EncodedUvmInformation, err := common.GetUvmInformation() // from the env.
	if err != nil {
		logrus.Infof("Failed to extract UVM_* environment variables: %s", err.Error())
	}

	if common.ThimCertsAbsent(&EncodedUvmInformation.InitialCerts) {
		logrus.Info("ThimCerts is absent, retrieving THIMCerts from THIM endpoint.")
		thimCerts, err := info.CertFetcher.GetThimCerts("")
		if err != nil {
			logrus.Fatalf("Failed to retrieve thim certs: %s", err.Error())
		}

		EncodedUvmInformation.InitialCerts = *thimCerts
	}

	logrus.Trace("Getting initial TCBM value...")
	var tcbm string
	logrus.Debugf("setting tcbm to EncodedUvmInformation.InitialCerts.Tcbm value: %s\n", EncodedUvmInformation.InitialCerts.Tcbm)
	tcbm = EncodedUvmInformation.InitialCerts.Tcbm

	thimTcbm, err := strconv.ParseUint(tcbm, 16, 64)
	if err != nil {
		logrus.Fatal("Unable to convert intial TCBM to a uint64")
	}

	certState := attest.CertState{
		CertFetcher: info.CertFetcher,
		Tcbm:        thimTcbm,
	}

	addr := adns.EndpointAddress{
		Name:      *serviceFQDN,
		IpAddress: *ipAddress,
		Protocol:  "tcp",
		Port:      8000,
	}

	adns.RegisterService(adnsEndpoint, addr, certState, EncodedUvmInformation)
}

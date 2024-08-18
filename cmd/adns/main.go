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

	"io/ioutil"
	"crypto/x509"
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"net"
	"encoding/pem"

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
	task:= flag.String("task", "", "which task to perform")
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
	logrus.Infof("   task:          %s", *task)
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
		Port:      443,
	}

	if *task == "register" {
		certs, key, err := adns.RegisterService(adnsEndpoint, addr, certState, EncodedUvmInformation)
		if err != nil {
			logrus.Fatal("Service registration fails")
		}

		err = os.WriteFile(addr.Name+".crt", []byte(certs), 0644)
		if err != nil {
			logrus.Fatal("Unable to write certificates")
		}

		err = os.WriteFile(addr.Name+".key", []byte(key), 0644)
		if err != nil {
			logrus.Fatal("Unable to write certificates")
		}


		
		cert, err := tls.X509KeyPair([]byte(certs), []byte(key))
		if err != nil {
			log.Fatalf("failed to load client certificate: %v", err)
		}
		
		caCert, err := ioutil.ReadFile("/usr/local/share/ca-certificates/adns-root.crt")
		if err != nil {
			log.Fatalf("failed to read CA certificate: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// tlsConfig := &tls.Config{
		// 	Certificates: []tls.Certificate{cert},
		// 	RootCAs:      caCertPool,
		// 	// InsecureSkipVerify: true, // Temporarily skip verification
		// 	ServerName:   "test2.acidns10.attested.name", 
		// }

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
			ServerName:   "test2.acidns10.attested.name",
			InsecureSkipVerify: true, // Disable default verification
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				// Parse the server certificate
				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}
	
				// Print the server certificate
				fmt.Printf("Server Certificate:\n%s\n", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	
				// Perform the verification
				opts := x509.VerifyOptions{
					Roots:         caCertPool,
					Intermediates: x509.NewCertPool(),
				}
	
				// Add intermediates if any
				for _, cert := range rawCerts[1:] {
					intermediateCert, err := x509.ParseCertificate(cert)
					if err != nil {
						return err
					}
					opts.Intermediates.AddCert(intermediateCert)
				}
	
				// Perform the verification
				if _, err := cert.Verify(opts); err != nil {
					return err
				}
	
				return nil
			},
		}

		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		client := &http.Client{
			Transport: transport,
		}

		resp, err := client.Get("https://test2.acidns10.attested.name:443")
		if err != nil {
			fmt.Printf("failed to make HTTPS request: %v\n", err)
			if urlErr, ok := err.(*url.Error); ok {
				fmt.Printf("URL Error: %v\n", urlErr)
				if opErr, ok := urlErr.Err.(*net.OpError); ok {
					fmt.Printf("Op Error: %v\n", opErr)
					if dnsErr, ok := opErr.Err.(*net.DNSError); ok {
						fmt.Printf("DNS Error: %v\n", dnsErr)
					}
				}
			}
			log.Fatalf("failed to make HTTPS request: %v", err)
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("failed to read response body: %v", err)
		}

		fmt.Printf("Response from test2: %s\n", body)
	}
	
}

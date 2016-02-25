/*
Copyright
*/
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/BurntSushi/ty/fun"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/xenolf/lego/acme"
	"io/ioutil"
	fmtlog "log"
	"net/http"
	"net/url"
	"os"
)

const (
	rsaKeySize = 2048
)

// ACMEAccount is used to store lets encrypt registration info
type ACMEAccount struct {
	Email           string
	Registration    *acme.RegistrationResource
	PrivateKey      *rsa.PrivateKey
	CertificatesMap map[string]AcmeCertificate
}

// GetEmail returns email
func (a ACMEAccount) GetEmail() string {
	return a.Email
}

// GetRegistration returns lets encrypt registration resource
func (a ACMEAccount) GetRegistration() *acme.RegistrationResource {
	return a.Registration
}

// GetPrivateKey returns private key
func (a ACMEAccount) GetPrivateKey() *rsa.PrivateKey {
	return a.PrivateKey
}

// AcmeCertificate is used to store certificate info
type AcmeCertificate struct {
	Domain        string
	CertURL       string
	CertStableURL string
	PrivateKey    []byte
	Certificate   []byte
}

func (a *ACME) createACMEConfig(acmeConfig *ACME, router *mux.Router) (*tls.Config, error) {
	acme.Logger = fmtlog.New(ioutil.Discard, "", 0)

	// if certificates in storage, load them
	if _, err := os.Stat(acmeConfig.StorageFile); err == nil {
		// load account
		acmeAccount, err := a.loadACMEAccount(acmeConfig)
		if err != nil {
			return nil, err
		}

		// build client
		client, err := a.buildACMEClient(acmeConfig, acmeAccount)
		if err != nil {
			return nil, err
		}
		config := &tls.Config{}
		log.Debugf("Loaded certificates %+v", fun.Keys(acmeAccount.CertificatesMap))
		config.Certificates = []tls.Certificate{}
		for _, certificateResource := range acmeAccount.CertificatesMap {
			cert, err := tls.X509KeyPair(certificateResource.Certificate, certificateResource.PrivateKey)
			if err != nil {
				return nil, err
			}
			config.Certificates = append(config.Certificates, cert)
		}
		config.BuildNameToCertificate()
		if acmeConfig.OnDemand {
			config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if !router.Match(&http.Request{URL: &url.URL{}, Host: clientHello.ServerName}, &mux.RouteMatch{}) {
					return nil, errors.New("No route found for " + clientHello.ServerName)
				}
				return a.loadCertificateOnDemand(client, acmeAccount, acmeConfig, clientHello)
			}
		}
		return config, nil
	}

	// Create a user. New accounts need an email and private key to start
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, err
	}
	acmeAccount := &ACMEAccount{
		Email:      acmeConfig.Email,
		PrivateKey: privateKey,
	}

	client, err := a.buildACMEClient(acmeConfig, acmeAccount)
	if err != nil {
		return nil, err
	}

	//client.SetTLSAddress(acmeConfig.TLSAddress)
	// New users will need to register; be sure to save it
	reg, err := client.Register()
	if err != nil {
		return nil, err
	}
	acmeAccount.Registration = reg

	// The client has a URL to the current Let's Encrypt Subscriber
	// Agreement. The user will need to agree to it.
	err = client.AgreeToTOS()
	if err != nil {
		return nil, err
	}

	config := &tls.Config{}
	config.Certificates = []tls.Certificate{}
	acmeAccount.CertificatesMap = map[string]AcmeCertificate{}

	certificateResource, err := a.getDomainsCertificates(client, acmeConfig.Domains)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certificateResource.Certificate, certificateResource.PrivateKey)
	if err != nil {
		return nil, err
	}
	config.Certificates = append(config.Certificates, cert)

	for _, domain := range acmeConfig.Domains {
		acmeAccount.CertificatesMap[domain] = *certificateResource
	}
	// BuildNameToCertificate parses the CommonName and SubjectAlternateName fields
	// in each certificate and populates the config.NameToCertificate map.
	config.BuildNameToCertificate()
	if acmeConfig.OnDemand {
		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !router.Match(&http.Request{URL: &url.URL{}, Host: clientHello.ServerName}, &mux.RouteMatch{}) {
				return nil, errors.New("No route found for " + clientHello.ServerName)
			}
			return a.loadCertificateOnDemand(client, acmeAccount, acmeConfig, clientHello)
		}
	}
	if err = a.saveACMEAccount(acmeAccount, acmeConfig); err != nil {
		return nil, err
	}
	return config, nil
}

func (a *ACME) buildACMEClient(acmeConfig *ACME, acmeAccount *ACMEAccount) (*acme.Client, error) {

	// A client facilitates communication with the CA server. This CA URL is
	// configured for a local dev instance of Boulder running in Docker in a VM.
	caServer := "https://acme-v01.api.letsencrypt.org/directory"
	if len(acmeConfig.CAServer) > 0 {
		caServer = acmeConfig.CAServer
	}
	client, err := acme.NewClient(caServer, acmeAccount, rsaKeySize)
	if err != nil {
		return nil, err
	}

	// We specify an http port of 5002 and an tls port of 5001 on all interfaces because we aren't running as
	// root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges).
	// Keep in mind that we still need to proxy challenge traffic to port 5002 and 5001.
	client.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.DNS01})
	client.SetHTTPAddress(acmeConfig.HTTPAddress)

	return client, nil
}

func (a *ACME) loadCertificateOnDemand(client *acme.Client, acmeAccount *ACMEAccount, acmeConfig *ACME, clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if certificateResource, ok := acmeAccount.CertificatesMap[clientHello.ServerName]; ok {
		cert, err := tls.X509KeyPair(certificateResource.Certificate, certificateResource.PrivateKey)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
	certificateResource, err := a.getDomainsCertificates(client, []string{clientHello.ServerName})
	if err != nil {
		return nil, err
	}
	log.Debugf("Got certificate on demand for domain %s", clientHello.ServerName)
	acmeAccount.CertificatesMap[clientHello.ServerName] = *certificateResource
	if err = a.saveACMEAccount(acmeAccount, acmeConfig); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certificateResource.Certificate, certificateResource.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (a *ACME) loadACMEAccount(acmeConfig *ACME) (*ACMEAccount, error) {
	acmeAccount := ACMEAccount{
		CertificatesMap: map[string]AcmeCertificate{},
	}
	file, err := ioutil.ReadFile(acmeConfig.StorageFile)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(file, &acmeAccount); err != nil {
		return nil, err
	}
	return &acmeAccount, nil
}

func (a *ACME) saveACMEAccount(acmeAccount *ACMEAccount, acmeConfig *ACME) error {
	// write account to file
	data, err := json.MarshalIndent(acmeAccount, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(acmeConfig.StorageFile, data, 0644)
}

func (a *ACME) getDomainsCertificates(client *acme.Client, domains []string) (*AcmeCertificate, error) {
	// The acme library takes care of completing the challenges to obtain the certificate(s).
	// Of course, the hostnames must resolve to this machine or it will fail.
	bundle := false
	certificate, failures := client.ObtainCertificate(domains, bundle, nil)
	if len(failures) > 0 {
		log.Error(failures)
		return nil, fmt.Errorf("Cannot obtain certificates %s+v", failures)
	}
	return &AcmeCertificate{
		Domain:        certificate.Domain,
		CertURL:       certificate.CertURL,
		CertStableURL: certificate.CertStableURL,
		PrivateKey:    certificate.PrivateKey,
		Certificate:   certificate.Certificate,
	}, nil
}

// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth2clientauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/oauth2clientauthextension"

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/golang-jwt/jwt"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc/credentials"
	grpcOAuth "google.golang.org/grpc/credentials/oauth"
	"net/url"
)

// clientAuthenticator provides implementation for providing client authentication using OAuth2 client credentials
// workflow for both gRPC and HTTP clients.
type clientAuthenticator struct {
	clientCredentials *clientcredentials.Config
	logger            *zap.Logger
	client            *http.Client
}

type errorWrappingTokenSource struct {
	ts       oauth2.TokenSource
	tokenURL string
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// errorWrappingTokenSource implements TokenSource
var _ oauth2.TokenSource = (*errorWrappingTokenSource)(nil)

// errFailedToGetSecurityToken indicates a problem communicating with OAuth2 server.
var errFailedToGetSecurityToken = fmt.Errorf("failed to get security token from token endpoint")

func newClientAuthenticator(cfg *Config, logger *zap.Logger) (*clientAuthenticator, error) {
	if cfg.ClientID == "" {
		return nil, errNoClientIDProvided
	}
	// if cfg.ClientSecret == "" {
	// 	return nil, errNoClientSecretProvided
	// }
	if cfg.TokenURL == "" {
		return nil, errNoTokenURLProvided
	}

	if cfg.ClientSecret != "" {
		// use user id and password
		return createClientAuthenticatorFromFid(cfg, logger)
	} else if cfg.Resource != "" {
		// use certificate
		return createClientAuthenticatorFromCertificate(cfg, logger)
	} else {
		return nil, errNoClientSecretNorCertificateProvided
	}

	////privateKey := getPrivateKey()
	////certificate := []byte(getCertificate())
	//privateKey, err := getSecret("us-east-1", "/application/otel-collector-client-private-key")
	//tempCert, err := getSecret("us-east-1", "/application/otel-collector-client-certificate")
	//certificate := []byte(tempCert)
	//
	//claims := jwt.MapClaims{}
	//claims["iss"] = "CC-110593-K018317-183711-UAT"
	//claims["aud"] = "https://idauatg2.jpmorganchase.com/adfs/oauth2/token"
	//claims["sub"] = "CC-110593-K018317-183711-UAT"
	//claims["iat"] = time.Now().Unix()
	//claims["exp"] = time.Now().Add(time.Minute * 5).Unix()
	//claims["jti"] = "1111"
	//token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	//
	//block, _ := pem.Decode(certificate)
	//
	//cert, err := x509.ParseCertificate(block.Bytes)
	//
	//fingerprint := sha1.Sum(cert.Raw)
	//keyId := strings.ToUpper(hex.EncodeToString(fingerprint[:]))
	//fmt.Println("keyId: " + keyId)
	//
	//fmt.Println("***target: 98D1C13921520B9D50199795A316D04D23417153")
	//
	//headers := token.Header
	//headers["kid"] = keyId
	//fmt.Println("***headers: %x", token.Header)
	//
	//signKey, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	//fmt.Println("***signKey: %x", signKey)
	//
	//signedString, err := token.SignedString(signKey)
	//fmt.Println("***signed String: " + signedString)
	//fmt.Println("***error: %x", err)

	//transport := http.DefaultTransport.(*http.Transport).Clone()
	//
	//tlsCfg, err := cfg.TLSSetting.LoadTLSConfig()
	//if err != nil {
	//	return nil, err
	//}
	//transport.TLSClientConfig = tlsCfg
	//
	//return &clientAuthenticator{
	//	clientCredentials: &clientcredentials.Config{
	//		ClientID:       cfg.ClientID,
	//		ClientSecret:   cfg.ClientSecret,
	//		TokenURL:       cfg.TokenURL,
	//		Scopes:         cfg.Scopes,
	//		EndpointParams: cfg.EndpointParams,
	//	},
	//	logger: logger,
	//	client: &http.Client{
	//		Transport: transport,
	//		Timeout:   cfg.Timeout,
	//	},
	//}, nil
}

func createClientAuthenticatorFromFid(cfg *Config, logger *zap.Logger) (*clientAuthenticator, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	tlsCfg, err := cfg.TLSSetting.LoadTLSConfig()
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsCfg

	username := cfg.Username
	if username == "" {
		username = cfg.ClientID
	}

	endpointParams := cfg.EndpointParams
	if endpointParams == nil {
		endpointParams = url.Values{}
	}
	endpointParams.Set("client_id", cfg.ClientID)
	endpointParams.Set("resource", cfg.Resource)
	endpointParams.Set("username", username)
	endpointParams.Set("password", cfg.ClientSecret)
	endpointParams.Set("grant_type", "password")

	return &clientAuthenticator{
		clientCredentials: &clientcredentials.Config{
			ClientID:       cfg.ClientID,
			ClientSecret:   "",
			TokenURL:       cfg.TokenURL,
			Scopes:         cfg.Scopes,
			EndpointParams: endpointParams,
		},
		logger: logger,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
	}, nil
}

func createClientAuthenticatorFromCertificate(cfg *Config, logger *zap.Logger) (*clientAuthenticator, error) {
	//privateKey := getPrivateKey()
	//tempCert := []byte(getCertificate())
	privateKey, err := getSecret("us-east-1", "/application/otel-collector-client-private-key")
	tempCert, err := getSecret("us-east-1", "/application/otel-collector-client-certificate")
	certificate := []byte(tempCert)

	claims := jwt.MapClaims{}
	//claims["iss"] = "CC-110593-K018317-183711-UAT"
	//claims["aud"] = "https://idauatg2.jpmorganchase.com/adfs/oauth2/token"
	//claims["sub"] = "CC-110593-K018317-183711-UAT"
	claims["iss"] = cfg.ClientID
	claims["aud"] = cfg.Audience
	claims["sub"] = cfg.ClientID
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Minute * 5).Unix()
	claims["jti"] = "1111"
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	block, _ := pem.Decode(certificate)

	cert, err := x509.ParseCertificate(block.Bytes)

	fingerprint := sha1.Sum(cert.Raw)
	keyId := strings.ToUpper(hex.EncodeToString(fingerprint[:]))
	fmt.Println("keyId: " + keyId)

	fmt.Println("***target: 98D1C13921520B9D50199795A316D04D23417153")

	headers := token.Header
	headers["kid"] = keyId
	fmt.Println("***headers: %x", token.Header)

	signKey, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	fmt.Println("***signKey: %x", signKey)

	signedString, err := token.SignedString(signKey)
	fmt.Println("***signed String: " + signedString)
	fmt.Println("***error: %x", err)

	transport := http.DefaultTransport.(*http.Transport).Clone()

	tlsCfg, err := cfg.TLSSetting.LoadTLSConfig()
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsCfg

	endpointParams := cfg.EndpointParams
	if endpointParams == nil {
		endpointParams = url.Values{}
	}
	endpointParams.Set("client_id", cfg.ClientID)
	endpointParams.Set("resource", cfg.Resource)
	endpointParams.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	endpointParams.Set("client_assertion", signedString)
	endpointParams.Set("grant_type", "client_credentials")

	return &clientAuthenticator{
		clientCredentials: &clientcredentials.Config{
			ClientID:       cfg.ClientID,
			ClientSecret:   cfg.ClientSecret,
			TokenURL:       cfg.TokenURL,
			Scopes:         cfg.Scopes,
			EndpointParams: endpointParams,
		},
		logger: logger,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
	}, nil
}

func getSecret(region string, secretName string) (string, error) {
	//secretName := "/application/otel-collector-client-private-key"
	//region := "us-east-1"

	//Create a Secrets Manager client
	sess, err := session.NewSession()
	if err != nil {
		// Handle session creation error
		fmt.Println(err.Error())
		return "", err
	}
	svc := secretsmanager.New(sess,
		aws.NewConfig().WithRegion(region))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	// In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
	// See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html

	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return "", err
	}

	// Decrypts secret using the associated KMS key.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	var decodedBinarySecret string
	if result.SecretString != nil {
		decodedBinarySecret = *result.SecretString
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			fmt.Println("Base64 Decode Error:", err)
			return "", err
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
	}
	return decodedBinarySecret, nil
}

func getPrivateKey() string {
	return "-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6DBIrOh5C0+3/\n" +
		"DqgWxPLsmXZEmFfwPYFhFGh2awS312TercThDxz8esrpmR1pzt1RfQG+bCbTpR39\n" +
		"TB/arMWW++kydK+NSSy8CKot/3+7MzeuzKf2TYa3foZ4ogu6oTmKXOQSwS9Ou2Jg\n" +
		"eyRG8sez0tqQCUk/5BUhqWiTl+RnBRWjIyHNjF8r93//ldTDe7mgpn5uA1bOnGwi\n" +
		"dHs7QvgBB8AWbcaGDxKGH4IZJT9v44cFXNk4YmrGaFsF4RtWTCFl+MnnDhkgp1Sp\n" +
		"T5HhE59f5//oq9+mKotgGWbyDo4AsFvTVBwNreEe6YwI5bRRacVDBxEw3eFVSocZ\n" +
		"0vgmEu4DAgMBAAECggEAWYwl0piOqCvJidJMJWl2Y1saCbop2YBBHbDs9tJb2wDZ\n" +
		"lDSfZpQXp46SzAzek2b2L5qzlCwKJCR9YsWZL2+pSxrFC3wOYzqtRXQGNU2c9UWZ\n" +
		"r5Dh5zM5fGhx4O5eJt4jC+3Z+Qzy8DpRB489zshcRrleaaWOlCn74c/gfenGDa8a\n" +
		"DNFh6UGwiZEHsHmCVDwvFyAsDFNEsKN3LpGpv49wx1A5GaKSUhs6x+NvUXco+FWz\n" +
		"JT7sLy4KsxKrcgQN3Dbp/5ibeWVbSc3/KyrVCg2BH+zKbv37HS5taZvE258LhRjv\n" +
		"9f/a0EaUQqhDgXWF37K8Ji4UtH8y36/d0ZA670T0QQKBgQDsn9s3TqvepWfXiVYL\n" +
		"BUWebwMwqIh6Pz0nFq3KrxA7Yyc+whYUVhwYtIAPnDOFiJv2pJEsvowTFGAMrVhH\n" +
		"1q0oZC2VBUMfDHH41/ogh+rL/bji4Ez1islHMN4D3ZjKmGgb9UNBZKjT2AcTHVHn\n" +
		"zWKO39nJ2TloAUIKdTbMqfCXFQKBgQDJSAJC95vL8Th0Dhl1nke9J8Z3rTQVuji0\n" +
		"oskGPSyyLIJs3OpUdlkQQfU4Rnv/P2TRJkf+bUnk5g8R/ghnuHTqaTLNYAAtcQqA\n" +
		"CVkTr7/AQF/7oWVj0OXzzox9tEYuHFk4BSb8rhKVnBg+zFcIyfKZle4l4oz546Ab\n" +
		"gNojDHa2twKBgQDROVfAQ5O8vkxfTFQEUpkISehsMdjbHueXlHn+6WRU3oto9nxH\n" +
		"ZwxY2+EP7HGx9OTS5Rhok+OPS0jSbMPOYYeiW1HinlCHN53fBjloYkW+MY41LVdf\n" +
		"FWR7yj3E9T+Qg8oqTmc1fye4iR9YS2iMqhInes87pxMXX2VhkdruhKTzMQKBgQCe\n" +
		"Mc41O85i929bJ0mzO3c+n2hI3wQ0n2u57Mb59FKQppLLZMV3JJzTPkOwuxTxg62F\n" +
		"BAVJXjPZh0cI6RNKEZsyMQQQjgcVr+aEwtQTuOmH/BB0AGFjledlO00H7wvJadZl\n" +
		"RQdjSJyqoUgc8xTkf3QAaeoGNIyASfqoIxlOupkC+QKBgD8LOB5G1zvPjPmeg1sq\n" +
		"he77L0B37Ef8dEu1bCZ8brXWvbb6Uy3iLa4duajiCovonlP18Q7KRxxALFpX0d+h\n" +
		"yMH9D7adU9pnJNsOuF0aYBwuWP2r6KuI6y+1D4O1/kF4WXDYMZ2saQe/uJEo+uw4\n" +
		"E+Z/3dkJSOPkpwxY+7QVLwcl\n" +
		"-----END PRIVATE KEY-----"

}

func getCertificate() string {
	return "-----BEGIN CERTIFICATE-----\n" +
		"MIIH4DCCBcigAwIBAgITRQAvtDIYIFlWOzJy2wACAC+0MjANBgkqhkiG9w0BAQsF\n" +
		"ADBbMRMwEQYKCZImiZPyLGQBGRYDbmV0MRgwFgYKCZImiZPyLGQBGRYIanBtY2hh\n" +
		"c2UxFjAUBgoJkiaJk/IsZAEZFgZleGNoYWQxEjAQBgNVBAMTCVBTSU4wUDU1MTAe\n" +
		"Fw0yMjEwMDcxMjU2NDNaFw0yMzEwMDcxMjU2NDNaMIGSMQswCQYDVQQGEwJVUzEO\n" +
		"MAwGA1UECBMFVGV4YXMxDjAMBgNVBAcTBVBsYW5vMRgwFgYDVQQKEw9KUCBNb3Jn\n" +
		"YW4gQ2hhc2UxDDAKBgNVBAsTA0dUSTE7MDkGA1UEAxMydHJhY2luZy1vdGVsLWNv\n" +
		"bGxlY3Rvci1jbGllbnQuZGV2LmF3cy5qcG1jaGFzZS5uZXQwggEiMA0GCSqGSIb3\n" +
		"DQEBAQUAA4IBDwAwggEKAoIBAQC6DBIrOh5C0+3/DqgWxPLsmXZEmFfwPYFhFGh2\n" +
		"awS312TercThDxz8esrpmR1pzt1RfQG+bCbTpR39TB/arMWW++kydK+NSSy8CKot\n" +
		"/3+7MzeuzKf2TYa3foZ4ogu6oTmKXOQSwS9Ou2JgeyRG8sez0tqQCUk/5BUhqWiT\n" +
		"l+RnBRWjIyHNjF8r93//ldTDe7mgpn5uA1bOnGwidHs7QvgBB8AWbcaGDxKGH4IZ\n" +
		"JT9v44cFXNk4YmrGaFsF4RtWTCFl+MnnDhkgp1SpT5HhE59f5//oq9+mKotgGWby\n" +
		"Do4AsFvTVBwNreEe6YwI5bRRacVDBxEw3eFVSocZ0vgmEu4DAgMBAAGjggNjMIID\n" +
		"XzAdBgNVHQ4EFgQU/2WscbmjJagRf8A9x0SAg3945akwHwYDVR0jBBgwFoAUCIIB\n" +
		"/5cG8Ty5ol8VtoNnwmR19okwggEGBgNVHR8Egf4wgfswgfiggfWggfKGLWh0dHA6\n" +
		"Ly9hZGNzLmpwbWNoYXNlLm5ldC9jcmwvUFNJTjBQNTUxKDIpLmNybIaBwGxkYXA6\n" +
		"Ly8vQ049UFNJTjBQNTUxKDIpLENOPVBTSU4wUDU1MSxDTj1DRFAsQ049UHVibGlj\n" +
		"JTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixE\n" +
		"Qz1leGNoYWQsREM9anBtY2hhc2UsREM9bmV0P2NlcnRpZmljYXRlUmV2b2NhdGlv\n" +
		"bkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCCAS4G\n" +
		"CCsGAQUFBwEBBIIBIDCCARwwOQYIKwYBBQUHMAKGLWh0dHA6Ly9hZGNzLmpwbWNo\n" +
		"YXNlLm5ldC9jcmwvUFNJTjBQNTUxKDIpLmNydDApBggrBgEFBQcwAYYdaHR0cDov\n" +
		"L2FkY3MuanBtY2hhc2UubmV0L29jc3AwgbMGCCsGAQUFBzAChoGmbGRhcDovLy9D\n" +
		"Tj1QU0lOMFA1NTEsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENO\n" +
		"PVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZXhjaGFkLERDPWpwbWNoYXNl\n" +
		"LERDPW5ldD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh\n" +
		"dGlvbkF1dGhvcml0eTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDA8Bgkr\n" +
		"BgEEAYI3FQcELzAtBiUrBgEEAYI3FQiBg5o1g/PQQIKBkwyC3ZYCk506RIOUsA+E\n" +
		"tq87AgFkAgEcMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAnBgkrBgEE\n" +
		"AYI3FQoEGjAYMAoGCCsGAQUFBwMBMAoGCCsGAQUFBwMCMD0GA1UdEQQ2MDSCMnRy\n" +
		"YWNpbmctb3RlbC1jb2xsZWN0b3ItY2xpZW50LmRldi5hd3MuanBtY2hhc2UubmV0\n" +
		"MA0GCSqGSIb3DQEBCwUAA4ICAQDpwr3wnyxlp8Mxrzhmr0h2naXcfStABIHK5EZN\n" +
		"R8w+h/LIYV+oKAVxxi1xXBrOg3lrQ8RZobZ81mcVZnvP+q5BmPXZh2Omv2ER4XXe\n" +
		"NZJmWEkB/QR9sinWG9y/+ptFQEw6vr4OKJ0DczyQP84UCt5HiobbpRHmwX4sW9cS\n" +
		"Zv8vjGbC9VKGq6VQpQVUkQPAwzOtEv4Rei+IhnCRKY+hZgzgtqJstQQmqBxTfCWm\n" +
		"kOjR1WuQK4oTU+x7pAR2cnVtquH7wlvkLENAfWfKuko81yJ0chXkJuuKpQmvptI8\n" +
		"6uEXOwj4+U3r8oTTSwAqSCjFOUHuFmsqkdU7pJ0pOZq46cw7rII8IuB1PGhv20T+\n" +
		"xxbri5fVPaIUCWJ8//ZVw1VzSUKx3NkuWQD+4La6XUoZnPwoPO5BSk9jBlUKfmSQ\n" +
		"t8fyJVGsgvUP/VWHPZn2EF1gjPpA3JR1MyUIi4b68SdJ9xte490WSmY77q8KnM6y\n" +
		"Nz7kB8R09Api39lqcmFEJlFKVmdmDkogs8jXk13WhXON20ClxGUeSJ02iyHHD2W9\n" +
		"TUBLqRQ9h9rfiVjVi1K5cLePKoPZZ9dwAoFadDYpHc/SVxpvRPY0aC870Af0ZreC\n" +
		"oymGyWppcIYduI5SntfSVrNA9ldOcnFtiSOtC2lEF4MnbLmpui2bPb6dQ+CKsy92\n" +
		"eO4LyQ==\n" +
		"-----END CERTIFICATE-----"
}

func (ewts errorWrappingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := ewts.ts.Token()
	if err != nil {
		return tok, multierr.Combine(
			fmt.Errorf("%w (endpoint %q)", errFailedToGetSecurityToken, ewts.tokenURL),
			err)
	}
	return tok, nil
}

// roundTripper returns oauth2.Transport, an http.RoundTripper that performs "client-credential" OAuth flow and
// also auto refreshes OAuth tokens as needed.
func (o *clientAuthenticator) roundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, o.client)
	return &oauth2.Transport{
		Source: errorWrappingTokenSource{
			ts:       o.clientCredentials.TokenSource(ctx),
			tokenURL: o.clientCredentials.TokenURL,
		},
		Base: base,
	}, nil
}

// perRPCCredentials returns gRPC PerRPCCredentials that supports "client-credential" OAuth flow. The underneath
// oauth2.clientcredentials.Config instance will manage tokens performing auto refresh as necessary.
func (o *clientAuthenticator) perRPCCredentials() (credentials.PerRPCCredentials, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, o.client)
	return grpcOAuth.TokenSource{
		TokenSource: errorWrappingTokenSource{
			ts:       o.clientCredentials.TokenSource(ctx),
			tokenURL: o.clientCredentials.TokenURL,
		},
	}, nil
}

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

package webauthnp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend wraps the backend framework and adds a map for storing key value pairs.
type backend struct {
	*framework.Backend
	webAuthN                   *webauthn.WebAuthn
	users                      map[string]*User
	registrationSessionStore   map[string]webauthn.SessionData
	authenticationSessionStore map[string]webauthn.SessionData
}

var _ logical.Factory = Factory

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*backend, error) {
	// TODO: this should probably be a configurable endpoint
	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Codergs Test Corp.",
		RPID:          "localhost",
		RPOrigin:      "http://localhost:4200",
	})
	if err != nil {
		return nil, err
	}

	b := &backend{
		users:                      make(map[string]*User),
		registrationSessionStore:   make(map[string]webauthn.SessionData),
		authenticationSessionStore: make(map[string]webauthn.SessionData),
		webAuthN:                   webAuthn,
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(help),
		BackendType: logical.TypeCredential,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login/begin",
				"login/finish",
				// TODO: this should be behind authentication. Figure out how
				// vault ui can be tweaked to make sure auth is checked and sent
				// in the request.
				"register/begin",
				"register/finish",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathLoginBegin(),
				b.pathLoginFinish(),
				b.pathRegisterBegin(),
				b.pathRegisterFinish(),
			},
		),
	}
	return b, nil
}

func (b *backend) pathRegisterBegin() *framework.Path {
	return &framework.Path{
		Pattern: "register/begin$",
		Fields: map[string]*framework.FieldSchema{
			"user": {
				Type:        framework.TypeString,
				Description: "User to regsiter for webauthn",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleRegisterBegin,
				Summary:  "start webauthn user registration",
			},
		},
	}
}

func (b *backend) pathRegisterFinish() *framework.Path {
	return &framework.Path{
		Pattern: "register/finish$",
		Fields: map[string]*framework.FieldSchema{
			"data": {
				Type:        framework.TypeMap,
				Description: "register credential request",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleRegisterFinish,
				Summary:  "finish webauthn user registration",
			},
		},
	}
}

func (b *backend) pathLoginBegin() *framework.Path {
	return &framework.Path{
		Pattern: "login/begin$",
		Fields: map[string]*framework.FieldSchema{
			"user": {
				Type:        framework.TypeString,
				Description: "user to login with webauthn",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLoginBegin,
				Summary:  "start webauthn user login",
			},
		},
	}
}

func (b *backend) pathLoginFinish() *framework.Path {
	return &framework.Path{
		Pattern: "login/finish$",
		Fields: map[string]*framework.FieldSchema{
			"data": {
				Type:        framework.TypeMap,
				Description: "login request data",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLoginFinish,
				Summary:  "finish webauthn user login",
			},
		},
	}
}

func (b *backend) handleRegisterBegin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// get username/friendly name
	username := data.Get("user").(string)
	if username == "" {
		b.Backend.Logger().Error("user must be provided")
		return logical.ErrorResponse("user must be provided"), nil
	}

	// get user
	user, ok := b.users[username]
	// user doesn't exist, create new user
	if !ok {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		b.users[username] = user
	}
	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
		credCreationOpts.AuthenticatorSelection = protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		}
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := b.webAuthN.BeginRegistration(
		user,
		registerOptions,
	)
	if err != nil {
		b.Backend.Logger().Error("registration failed", err)
		return nil, fmt.Errorf("failed to beign webAuthN registration (err=%v)", err)
	}

	// store session data as marshaled JSON
	b.registrationSessionStore[username] = *sessionData

	// jsonResponse(w, options, http.StatusOK)
	dj, err := json.Marshal(options)
	if err != nil {
		b.Backend.Logger().Error("marshal failed", err)
		return nil, fmt.Errorf("failed to marshal session data (err=%v)", err)
	}

	dataVal := make(map[string]interface{})
	json.Unmarshal(dj, &dataVal)

	// Compose the response
	resp := &logical.Response{
		Data: dataVal,
	}

	return resp, nil
}

func (b *backend) handleRegisterFinish(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// get request data
	dataRead, ok := data.GetOk("data")
	if !ok {
		b.Backend.Logger().Error("data needed")
		return logical.ErrorResponse("data must be provided"), nil
	}

	dataMap := dataRead.(map[string]interface{})
	username, ok := dataMap["user"].(string)
	if !ok {
		b.Backend.Logger().Error("user must be provided")
		return logical.ErrorResponse("user must be provided"), nil
	}

	credentialData, ok := dataMap["credentialData"].(map[string]interface{})
	if !ok {
		b.Backend.Logger().Error("credential must be provided")
		return logical.ErrorResponse("credential must be provided"), nil
	}

	// get user
	user, ok := b.users[username]
	// user doesn't exist, create new user
	if !ok {
		b.Backend.Logger().Error("user not known")
		return logical.ErrorResponse("user not known"), nil
	}

	// load the sessionData
	sessionData, ok := b.registrationSessionStore[username]
	// user doesn't exist, create new user
	if !ok {
		b.Backend.Logger().Error("registration session data not present")
		return logical.ErrorResponse("registration session data not present"), nil
	}

	// since we don't have access to the request, we are going to create a io.Reader
	// and short circuit using inner methods on FinishRegistration
	dataBytes, err := json.Marshal(credentialData)
	if err != nil {
		b.Backend.Logger().Error("marshal failed", err)
		return nil, fmt.Errorf("failed to marshal credential data to bytes: (err=%v)", err)
	}
	reader := bytes.NewReader(dataBytes)
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(reader)
	if err != nil {
		b.Backend.Logger().Error("parsedresponse failed", err)
		return nil, err
	}

	credential, err := b.webAuthN.CreateCredential(user, sessionData, parsedResponse)
	if err != nil {
		b.Backend.Logger().Error("create credential failed", err)
		return nil, fmt.Errorf("error occurred while registering the user: %s (err =%v)", username, err)
	}

	user.AddCredential(*credential)
	b.Backend.Logger().Info("credentials", user.WebAuthnCredentials())

	// Compose the response
	return &logical.Response{}, nil
}

func (b *backend) handleLoginBegin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// get username/friendly name
	username := data.Get("user").(string)
	if username == "" {
		b.Backend.Logger().Error("user must be provided")
		return logical.ErrorResponse("user must be provided"), nil
	}

	// get user
	user, ok := b.users[username]
	// user doesn't exist, create new user
	if !ok {
		b.Backend.Logger().Error("user not registered")
		return logical.ErrorResponse("user is not registered"), nil
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := b.webAuthN.BeginLogin(user)
	if err != nil {
		b.Backend.Logger().Error("auth login begin failed", err)
		return nil, fmt.Errorf("failed to beign webAuthN registration (err=%v)", err)
	}

	// store session data as marshaled JSON
	b.authenticationSessionStore[username] = *sessionData

	// jsonResponse(w, options, http.StatusOK)
	dj, err := json.Marshal(options)
	if err != nil {
		b.Backend.Logger().Error("marshal error")
		return nil, fmt.Errorf("failed to marshal session data (err=%v)", err)
	}

	dataVal := make(map[string]interface{})
	json.Unmarshal(dj, &dataVal)

	// Compose the response
	resp := &logical.Response{
		Data: dataVal,
	}

	return resp, nil
}

func (b *backend) handleLoginFinish(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// get request data
	dataRead, ok := data.GetOk("data")
	if !ok {
		b.Backend.Logger().Error("no data supplied")
		return logical.ErrorResponse("data must be provided"), nil
	}

	dataMap := dataRead.(map[string]interface{})
	username, ok := dataMap["user"].(string)
	if !ok {
		b.Backend.Logger().Error("no user data")
		return logical.ErrorResponse("user must be provided"), nil
	}

	credentialData, ok := dataMap["credentialData"].(map[string]interface{})
	if !ok {
		b.Backend.Logger().Error("no credential")
		return logical.ErrorResponse("credential must be provided"), nil
	}

	// get user
	user, ok := b.users[username]
	// user doesn't exist, create new user
	if !ok {
		b.Backend.Logger().Error("user not present")
		return logical.ErrorResponse("user not known"), nil
	}

	// load the sessionData
	sessionData, ok := b.authenticationSessionStore[username]
	// user doesn't exist, create new user
	if !ok {
		b.Backend.Logger().Error("no auth session data")
		return logical.ErrorResponse("no session data was found for the user"), nil
	}

	// since we don't have access to the request, we are going to create a io.Reader
	// and short circuit using inner methods on FinishRegistration
	dataBytes, err := json.Marshal(credentialData)
	if err != nil {
		b.Backend.Logger().Error("marshal failed")
		return nil, fmt.Errorf("failed to marshal credential data to bytes: (err=%v)", err)
	}
	reader := bytes.NewReader(dataBytes)
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(reader)
	if err != nil {
		b.Backend.Logger().Info("parsed error response")
		return nil, err
	}
	b.Backend.Logger().Info("before validation logic")
	credential, err := b.webAuthN.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		b.Backend.Logger().Info("failed validation", err)
		return nil, fmt.Errorf("error occurred while registering the user: %s (err =%v)", username, err)
	}

	b.Backend.Logger().Info("success validation logic")
	// Compose the response
	resp := &logical.Response{
		Auth: &logical.Auth{
			// Policies can be passed in as a parameter to the request
			Policies: []string{"default"},
			Metadata: map[string]string{
				"user": username,
				// TODO: utf-8 string
				// "authenticator_aaguid":     string(credential.Authenticator.AAGUID),
				// "id":               string(credential.ID),
				"attestation_type":         credential.AttestationType,
				"authenticator_sign_count": fmt.Sprintf("%d", credential.Authenticator.SignCount),
			},
			// Lease options can be passed in as parameters to the request
			LeaseOptions: logical.LeaseOptions{
				TTL:       30 * time.Second,
				MaxTTL:    1 * time.Minute,
				Renewable: false,
			},
		},
	}
	b.Backend.Logger().Info("done", resp)
	return resp, nil
}

const help = `
The is an experimental backend that makes use of webauthn protocol to register and log in
users in to Vault.
`

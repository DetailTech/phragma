package authz

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultStepUpTTL = 5 * time.Minute

// StepUpChallenge is a short-lived, one-time acknowledgement token for
// privileged actions. It is a functional guardrail, not an MFA attestation.
type StepUpChallenge struct {
	Token      string
	Action     string
	Actor      string
	Role       string
	AuthSource string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Comment    string
}

type stepUpStore struct {
	mu         sync.Mutex
	challenges map[string]StepUpChallenge
	now        func() time.Time
}

var defaultStepUps = &stepUpStore{
	challenges: map[string]StepUpChallenge{},
	now:        func() time.Time { return time.Now().UTC() },
}

// CreateStepUpChallenge issues one short-lived token bound to the current actor
// and requested action. Callers must already be authenticated and authorized.
func CreateStepUpChallenge(ctx context.Context, action, comment string) (StepUpChallenge, error) {
	id, ok := IdentityFromContext(ctx)
	if !ok || id.AuthSource == "" || id.AuthSource == AuthSourceDisabledLocal {
		return StepUpChallenge{}, status.Error(codes.FailedPrecondition, "step-up requires authenticated API identity")
	}
	action = normalizeStepUpAction(action)
	if action == "" {
		return StepUpChallenge{}, status.Error(codes.InvalidArgument, "step-up action is required")
	}
	token, err := randomStepUpToken()
	if err != nil {
		return StepUpChallenge{}, status.Errorf(codes.Internal, "create step-up token: %v", err)
	}
	now := defaultStepUps.now()
	challenge := StepUpChallenge{
		Token:      token,
		Action:     action,
		Actor:      id.Name,
		Role:       id.Role.String(),
		AuthSource: id.AuthSource,
		IssuedAt:   now,
		ExpiresAt:  now.Add(defaultStepUpTTL),
		Comment:    strings.TrimSpace(comment),
	}
	defaultStepUps.mu.Lock()
	defaultStepUps.reapLocked(now)
	defaultStepUps.challenges[token] = challenge
	defaultStepUps.mu.Unlock()
	return challenge, nil
}

// RequireStepUp consumes a matching token for the current authenticated actor.
// Direct in-process tests and explicitly disabled local-auth deployments remain
// compatible; production hardening must replace this with real MFA/reauth proof.
func RequireStepUp(ctx context.Context, action, token string) error {
	id, ok := IdentityFromContext(ctx)
	if !ok || id.AuthSource == "" || id.AuthSource == AuthSourceDisabledLocal {
		return nil
	}
	action = normalizeStepUpAction(action)
	token = strings.TrimSpace(token)
	if token == "" {
		return status.Errorf(codes.FailedPrecondition, "step_up_token is required for %s", action)
	}
	now := defaultStepUps.now()
	defaultStepUps.mu.Lock()
	defer defaultStepUps.mu.Unlock()
	defaultStepUps.reapLocked(now)
	challenge, ok := defaultStepUps.challenges[token]
	if !ok {
		return status.Error(codes.FailedPrecondition, "step-up token is invalid, expired, or already consumed")
	}
	delete(defaultStepUps.challenges, token)
	if now.After(challenge.ExpiresAt) {
		return status.Error(codes.FailedPrecondition, "step-up token expired")
	}
	if challenge.Action != action {
		return status.Errorf(codes.FailedPrecondition, "step-up token action mismatch: got %s want %s", challenge.Action, action)
	}
	if challenge.Actor != id.Name || challenge.AuthSource != id.AuthSource {
		return status.Error(codes.FailedPrecondition, "step-up token actor mismatch")
	}
	return nil
}

func (s *stepUpStore) reapLocked(now time.Time) {
	for token, challenge := range s.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(s.challenges, token)
		}
	}
}

func normalizeStepUpAction(action string) string {
	return strings.ToLower(strings.TrimSpace(action))
}

func randomStepUpToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return "stepup_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

package userpresence

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

// ConfirmMethod represents the method used for user confirmation
type ConfirmMethod int

const (
	ConfirmMethodFprintd ConfirmMethod = iota
	ConfirmMethodZenity
)

// UserPresence handles user presence confirmation via fingerprint reader
type UserPresence struct {
	mu            sync.Mutex
	activeRequest *request
	confirmMethod ConfirmMethod
}

type request struct {
	timeout          time.Duration
	pendingResult    chan Result
	extendTimeout    chan time.Duration
	challengeParam   [32]byte
	applicationParam [32]byte
}

// Result represents the outcome of a user presence check
type Result struct {
	OK    bool
	Error error
}

// New creates a new UserPresence handler, detecting available confirmation methods
func New() *UserPresence {
	method := detectConfirmMethod()
	if method == nil {
		log.Printf("userpresence: warning - no confirmation method available")
	}
	return &UserPresence{
		confirmMethod: *method,
	}
}

// detectConfirmMethod checks which confirmation methods are available
func detectConfirmMethod() *ConfirmMethod {
	// Check for fprintd-verify first (preferred)
	if _, err := exec.LookPath("fprintd-verify"); err == nil {
		log.Printf("userpresence: using fprintd-verify for confirmation")
		method := ConfirmMethodFprintd
		return &method
	}

	// Fall back to zenity
	if _, err := exec.LookPath("zenity"); err == nil {
		log.Printf("userpresence: using zenity for confirmation")
		method := ConfirmMethodZenity
		return &method
	}

	log.Printf("userpresence: no confirmation method found (fprintd-verify or zenity)")
	return nil
}

// ConfirmPresence requests user presence confirmation
func (up *UserPresence) ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan Result, error) {
	up.mu.Lock()
	defer up.mu.Unlock()

	timeout := 30 * time.Second

	if up.activeRequest != nil {
		if challengeParam != up.activeRequest.challengeParam || applicationParam != up.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		extendTimeoutChan := up.activeRequest.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(2 * time.Second):
			}
		}()

		return up.activeRequest.pendingResult, nil
	}

	up.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
		extendTimeout:    make(chan time.Duration),
	}

	go up.confirmPrompt(up.activeRequest, prompt)

	return up.activeRequest.pendingResult, nil
}

func (up *UserPresence) confirmPrompt(req *request, prompt string) {
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(2 * time.Second):
			// Client likely gone
		}

		up.mu.Lock()
		up.activeRequest = nil
		up.mu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), req.timeout)
	defer cancel()

	log.Printf("userpresence: prompt=%s", prompt)

	// Send notification to user (non-blocking)
	notifyCmd := exec.Command("notify-send", "-u", "critical", "-t", "30000",
		"TPM-FIDO", prompt+"\n\nConfirm to proceed.")
	if err := notifyCmd.Start(); err != nil {
		log.Printf("userpresence: notify-send failed to start: %v", err)
	}

	var err error
	switch up.confirmMethod {
	case ConfirmMethodFprintd:
		err = up.confirmWithFprintd(ctx)
	case ConfirmMethodZenity:
		err = up.confirmWithZenity(ctx, prompt)
	default:
		sendResult(Result{OK: false, Error: errors.New("no confirmation method available")})
		return
	}

	if err != nil {
		log.Printf("userpresence: confirmation failed: %v", err)
		if ctx.Err() == context.DeadlineExceeded {
			sendResult(Result{OK: false, Error: errors.New("confirmation timed out")})
		} else {
			sendResult(Result{OK: false, Error: err})
		}
		return
	}

	log.Printf("userpresence: confirmed successfully")
	sendResult(Result{OK: true, Error: nil})
}

func (up *UserPresence) confirmWithFprintd(ctx context.Context) error {
	log.Printf("userpresence: launching fprintd-verify")
	cmd := exec.CommandContext(ctx, "fprintd-verify")
	cmd.Stdout = os.Stderr // Must not use stdout - Native Messaging uses it
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func (up *UserPresence) confirmWithZenity(ctx context.Context, prompt string) error {
	log.Printf("userpresence: launching zenity")
	cmd := exec.CommandContext(ctx,
		"zenity",
		"--question",
		"--title=TPM-FIDO",
		"--text="+prompt,
		"--ok-label=Allow",
		"--cancel-label=Deny")
	cmd.Stdout = os.Stderr // Must not use stdout - Native Messaging uses it
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

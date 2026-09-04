// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package managedidentity

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
)

// The IMDSv2 legs retry on the same conditions and with the same timing as
// MSAL .NET's ImdsRetryPolicy, so that a host which is slow to bring IMDS up
// behaves the same way whichever library is asking.
//
// Two strategies exist because 410 Gone means something different from the
// other retriable answers. IMDS returns it while the endpoint is being brought
// up or moved, which resolves on a scale of a minute rather than seconds, so it
// is retried longer and at a flat interval instead of backing off.
const (
	// imdsExponentialRetries is the number of retries after the first attempt
	// for every retriable status except 410.
	imdsExponentialRetries = 3
	// imdsLinearRetries is the number of retries after the first attempt for
	// 410 Gone.
	imdsLinearRetries = 7

	imdsMinBackoff     = 1 * time.Second
	imdsMaxBackoff     = 4 * time.Second
	imdsDeltaBackoff   = 2 * time.Second
	imdsGoneRetryAfter = 10 * time.Second
)

// imdsRetriableStatus reports whether an IMDS response should be retried on the
// acquisition path. It mirrors HttpRetryConditions.Imds in MSAL .NET.
//
// 404 is retriable even though this package treats a persistent 404 as the
// capability answer "this host only serves IMDSv1". A caller on this path has
// asked for IMDSv2, so a 404 contradicts the request, and a single one can come
// from an agent that has not finished starting: the answer is only believed
// after the retries are exhausted. Capability discovery asks a different
// question and uses imdsProbeRetriableStatus instead.
func imdsRetriableStatus(status int) bool {
	switch status {
	case http.StatusNotFound, http.StatusRequestTimeout, http.StatusGone, http.StatusTooManyRequests:
		return true
	}
	return status >= 500 && status <= 599
}

// imdsProbeRetriableStatus reports whether a capability probe should be
// retried. It mirrors HttpRetryConditions.ImdsProbe in MSAL .NET: the same
// answers as the acquisition path, except that a 404 is taken at face value.
//
// The two differ because they are asking different questions. An acquisition
// has been told to use IMDSv2, so a 404 contradicts the caller and is worth
// re-checking in case the agent is still starting. A probe is asking whether
// this host serves v2 at all, and "no" is a perfectly good answer: retrying it
// cannot change a v1-only host into a v2 host, and only makes every caller on
// such a host wait out the full backoff before hearing it.
func imdsProbeRetriableStatus(status int) bool {
	if status == http.StatusNotFound {
		return false
	}
	return imdsRetriableStatus(status)
}

// retriableTransportError reports whether a transport-level failure should be
// retried. MSAL .NET retries exactly one exception here, TaskCanceledException,
// which is what its HTTP client raises on a timeout; the Go equivalent is a
// timeout from the client or from a per-request deadline.
//
// A context that the caller canceled is never retried: the caller has already
// given up, so another attempt would only delay the error it is waiting for.
func retriableTransportError(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// imdsRetryDelay is how long to wait before the retry numbered retry, counting
// from zero. It reproduces ExponentialRetryStrategy.CalculateDelay: the first
// wait is the floor, and every later one doubles from the delta up to the
// ceiling, giving 1s, 2s, 4s.
func imdsRetryDelay(retry int) time.Duration {
	if retry <= 0 {
		return imdsMinBackoff
	}
	delay := time.Duration(1<<(retry-1)) * imdsDeltaBackoff
	if delay > imdsMaxBackoff {
		return imdsMaxBackoff
	}
	return delay
}

// retryWait sleeps for d unless ctx ends first. It is a variable so tests
// can observe the schedule without waiting out a real backoff.
var retryWait = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sendIMDSRequest sends req and retries it while IMDS answers with something
// transient. It returns the last response received, so the caller applies its
// own meaning to a status that survived the retries.
//
// retriableStatus selects the policy. MSAL .NET picks one the same way, through
// RetryPolicyFactory: RequestType.Imds for an acquisition and
// RequestType.ImdsProbe for capability discovery.
//
// req is cloned per attempt and its body rewound from GetBody, because a body
// is consumed by the attempt that sent it. http.NewRequest populates GetBody
// for the in-memory body types this package uses; a request without one is sent
// once rather than replayed empty.
func sendIMDSRequest(ctx context.Context, client ops.HTTPClient, req *http.Request, retryEnabled bool, retriableStatus func(int) bool) (*http.Response, error) {
	// Guarding here rather than at each construction site makes this the single
	// choke point both plain-HTTP IMDS legs pass through, so a new leg cannot
	// forget the refusal.
	client = imdsRedirectGuarded(client)
	if !retryEnabled {
		return client.Do(req)
	}

	// The number of retries is fixed by the first answer, as MSAL .NET does:
	// a request that starts out as 410 keeps the longer schedule even if a
	// later attempt fails differently.
	maxRetries := -1

	var resp *http.Response
	var err error
	for retry := 0; ; retry++ {
		attempt := req
		if retry > 0 {
			attempt, err = rewindRequest(req)
			if err != nil {
				return nil, err
			}
		}

		resp, err = client.Do(attempt)

		retriable := false
		switch {
		case err != nil:
			retriable = retriableTransportError(ctx, err)
			if maxRetries < 0 {
				maxRetries = imdsExponentialRetries
			}
		default:
			retriable = retriableStatus(resp.StatusCode)
			if maxRetries < 0 {
				maxRetries = imdsExponentialRetries
				if resp.StatusCode == http.StatusGone {
					maxRetries = imdsLinearRetries
				}
			}
		}

		if !retriable || retry >= maxRetries {
			return resp, err
		}

		delay := imdsRetryDelay(retry)
		if resp != nil && resp.StatusCode == http.StatusGone {
			delay = imdsGoneRetryAfter
		}

		// The response is discarded, so its body is drained before it is
		// closed: that lets the transport reuse the connection for the retry
		// instead of opening a new one.
		drainResponse(resp)

		if waitErr := retryWait(ctx, delay); waitErr != nil {
			return nil, waitErr
		}
	}
}

// The Entra token endpoint is retried on different terms from IMDS. It is a
// remote service rather than a local agent, so a 404 or a 410 is an answer
// about the request rather than a service that has not finished starting, and
// only a server error is worth repeating. MSAL .NET uses HttpRetryConditions.Sts
// and DefaultRetryPolicy for RequestType.STS here.
const (
	// stsRetries is the number of retries after the first attempt.
	stsRetries      = 1
	stsRetryBackoff = 1 * time.Second
)

// stsRetriableStatus reports whether an Entra token response should be retried.
//
// A response carrying Retry-After is never retried: the service has said how
// long to wait, and repeating the request sooner ignores it. MSAL .NET declines
// the retry in the same case rather than honouring the delay, so that a caller
// is not silently held for whatever period the service asked for.
func stsRetriableStatus(resp *http.Response) bool {
	if hasRetryAfter(resp) {
		return false
	}
	return resp.StatusCode >= 500 && resp.StatusCode <= 599
}

// hasRetryAfter reports whether the response carries a Retry-After the caller
// could act on. A value that parses as neither a delay nor a date is treated as
// absent, matching what .NET's typed header does with an unusable value.
func hasRetryAfter(resp *http.Response) bool {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return false
	}
	if _, err := strconv.Atoi(v); err == nil {
		return true
	}
	_, err := http.ParseTime(v)
	return err == nil
}

// sendSTSRequest sends the mutual-TLS token request and retries it once if
// Entra answers with a server error.
//
// This is separate from the certificate re-mint in acquireTokenForIMDSv2, which
// reacts to a rejected certificate rather than to a failing service; the two do
// not overlap, because a server error is not a reason to mint a new
// certificate.
func sendSTSRequest(ctx context.Context, client *http.Client, req *http.Request, retryEnabled bool) (*http.Response, error) {
	if !retryEnabled {
		return client.Do(req)
	}

	var resp *http.Response
	var err error
	for retry := 0; ; retry++ {
		attempt := req
		if retry > 0 {
			attempt, err = rewindRequest(req)
			if err != nil {
				return nil, err
			}
		}

		resp, err = client.Do(attempt)

		retriable := false
		if err != nil {
			retriable = retriableTransportError(ctx, err)
		} else {
			retriable = stsRetriableStatus(resp)
		}

		if !retriable || retry >= stsRetries {
			return resp, err
		}

		drainResponse(resp)
		if waitErr := retryWait(ctx, stsRetryBackoff); waitErr != nil {
			return nil, waitErr
		}
	}
}

// rewindRequest clones req with a fresh body so it can be sent again.
// rewindRequest clones req with a fresh body so it can be sent again.
//
// The clone shares req's body reader, which the previous attempt has already
// read to EOF, so the body is replaced from GetBody. net/http's own transport
// would rewind from GetBody too, but ops.HTTPClient is an interface and a
// caller-supplied client is under no obligation to do so, so the rewind is done
// here rather than relied upon.
func rewindRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return clone, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("managedidentity: the IMDS request cannot be retried because its body cannot be rewound")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}

// drainResponse reads and closes a response that is being thrown away.
func drainResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
}

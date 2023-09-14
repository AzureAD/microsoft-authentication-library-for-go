// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/broker"
	"golang.org/x/sys/windows"
)

// msalruntime API
var (
	msalruntime *windows.LazyDLL

	cancelAsyncOperation *windows.LazyProc
	getError             *windows.LazyProc
	releaseAsyncHandle   *windows.LazyProc
	releaseError         *windows.LazyProc
	// shutdown should be called before the process exits. It's idempotent.
	shutdown *windows.LazyProc
	// startup must be called exactly once before any other msalruntime function
	startup *windows.LazyProc

	// authentication methods
	signInInteractivelyAsync *windows.LazyProc
	signInSilentlyAsync      *windows.LazyProc

	// Account
	getClientInfo     *windows.LazyProc
	getContext        *windows.LazyProc
	getDisplayName    *windows.LazyProc
	getEnvironment    *windows.LazyProc
	getExpiresOn      *windows.LazyProc
	getFamilyName     *windows.LazyProc
	getGivenName      *windows.LazyProc
	getHomeAccountID  *windows.LazyProc
	getLocalAccountID *windows.LazyProc
	getMiddleName     *windows.LazyProc
	getRawIdToken     *windows.LazyProc
	getRealm          *windows.LazyProc
	getUserName       *windows.LazyProc
	releaseAccount    *windows.LazyProc

	// AuthParameters
	createAuthParameters  *windows.LazyProc
	releaseAuthParameters *windows.LazyProc
	setAddtionalParameter *windows.LazyProc
	setDecodedClaims      *windows.LazyProc
	setRedirectURI        *windows.LazyProc
	setRequestedScopes    *windows.LazyProc

	// AuthResult
	getAccessToken    *windows.LazyProc
	getAccount        *windows.LazyProc
	getGrantedScopes  *windows.LazyProc
	releaseAuthResult *windows.LazyProc

	// logging
	registerLogCallback      *windows.LazyProc
	releaseLogCallbackHandle *windows.LazyProc
	setIsPIIEnabled          *windows.LazyProc

	// TODO: get this from the application
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	getConsoleWindow = kernel32.NewProc("GetConsoleWindow")
)

// Initialize loads the msalruntime DLL from the given path.
func Initialize(path string) error {
	msalruntime = windows.NewLazyDLL(path)
	cancelAsyncOperation = msalruntime.NewProc("MSALRUNTIME_CancelAsyncOperation")
	createAuthParameters = msalruntime.NewProc("MSALRUNTIME_CreateAuthParameters")
	getAccessToken = msalruntime.NewProc("MSALRUNTIME_GetAccessToken")
	getAccount = msalruntime.NewProc("MSALRUNTIME_GetAccount")
	getClientInfo = msalruntime.NewProc("MSALRUNTIME_GetClientInfo")
	getContext = msalruntime.NewProc("MSALRUNTIME_GetContext")
	getDisplayName = msalruntime.NewProc("MSALRUNTIME_GetDisplayName")
	getError = msalruntime.NewProc("MSALRUNTIME_GetError")
	getEnvironment = msalruntime.NewProc("MSALRUNTIME_GetEnvironment")
	getExpiresOn = msalruntime.NewProc("MSALRUNTIME_GetExpiresOn")
	getFamilyName = msalruntime.NewProc("MSALRUNTIME_GetFamilyName")
	getGivenName = msalruntime.NewProc("MSALRUNTIME_GetGivenName")
	getGrantedScopes = msalruntime.NewProc("MSALRUNTIME_GetGrantedScopes")
	getHomeAccountID = msalruntime.NewProc("MSALRUNTIME_GetHomeAccountId")
	getLocalAccountID = msalruntime.NewProc("MSALRUNTIME_GetLocalAccountId")
	getMiddleName = msalruntime.NewProc("MSALRUNTIME_GetMiddleName")
	getRawIdToken = msalruntime.NewProc("MSALRUNTIME_GetRawIdToken")
	getRealm = msalruntime.NewProc("MSALRUNTIME_GetRealm")
	getUserName = msalruntime.NewProc("MSALRUNTIME_GetUserName")
	registerLogCallback = msalruntime.NewProc("MSALRUNTIME_RegisterLogCallback")
	releaseAccount = msalruntime.NewProc("MSALRUNTIME_ReleaseAccount")
	releaseAsyncHandle = msalruntime.NewProc("MSALRUNTIME_ReleaseAsyncHandle")
	releaseAuthParameters = msalruntime.NewProc("MSALRUNTIME_ReleaseAuthParameters")
	releaseAuthResult = msalruntime.NewProc("MSALRUNTIME_ReleaseAuthResult")
	releaseError = msalruntime.NewProc("MSALRUNTIME_ReleaseError")
	releaseLogCallbackHandle = msalruntime.NewProc("MSALRUNTIME_ReleaseLogCallbackHandle")
	setAddtionalParameter = msalruntime.NewProc("MSALRUNTIME_SetAdditionalParameter")
	setDecodedClaims = msalruntime.NewProc("MSALRUNTIME_SetDecodedClaims")
	setIsPIIEnabled = msalruntime.NewProc("MSALRUNTIME_SetIsPiiEnabled")
	setRedirectURI = msalruntime.NewProc("MSALRUNTIME_SetRedirectUri")
	setRequestedScopes = msalruntime.NewProc("MSALRUNTIME_SetRequestedScopes")
	shutdown = msalruntime.NewProc("MSALRUNTIME_Shutdown")
	signInInteractivelyAsync = msalruntime.NewProc("MSALRUNTIME_SignInInteractivelyAsync")
	signInSilentlyAsync = msalruntime.NewProc("MSALRUNTIME_SignInSilentlyAsync")
	startup = msalruntime.NewProc("MSALRUNTIME_Startup")

	errHandle, _, _ := startup.Call()
	err := convertError(errHandle)
	if err == nil {
		broker.SignInInteractively = signInInteractively
		broker.SignInSilently = signInSilently
	}
	return err
}

// bufPool is a pool of buffers allocated for msalruntime string returns
var bufPool = sync.Pool{
	New: func() any {
		b := make([]uint16, 4096)
		return &b
	},
}

// callStringMethod calls an msalruntime method that returns a string
func callStringMethod(proc *windows.LazyProc, handle uintptr) (string, error) {
	buf := *bufPool.Get().(*[]uint16)
	defer bufPool.Put(&buf)
	length := len(buf)
	for {
		errHandle, _, _ := proc.Call(
			handle,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&length)),
		)
		if errHandle != 0 {
			return "", convertError(errHandle)
		}
		if length <= len(buf) {
			break
		}
		buf = make([]uint16, length)
	}
	return windows.UTF16ToString(buf), nil
}

// callUintMethod calls an msalruntime method that returns a uint
func callUintMethod(proc *windows.LazyProc, handle uintptr) (uint, error) {
	var out uint
	errHandle, _, _ := proc.Call(handle, uintptr(unsafe.Pointer(&out)))
	err := convertError(errHandle)
	return out, err
}

// convertError converts an msalruntime error to a Go error
func convertError(handle uintptr) error {
	if handle == 0 {
		return nil
	}
	defer releaseError.Call(handle)
	s, err := callStringMethod(getContext, handle)
	if err != nil {
		return fmt.Errorf("couldn't get MSAL error: %v", err)
	}
	return errors.New(s)
}

// completionRoutine creates a callback function for use as an MSALRUNTIME_COMPLETION_ROUTINE i.e.,
// a function msalruntime can call with the result of an asynchronous operation. The function will
// send a result to the given channel.
func completionRoutine(c chan result) uintptr {
	// MSALRUNTIME_COMPLETION_ROUTINE is a void stdcall but windows.NewCallback creates a stdcall
	// returning uintptr (it's intended for use with Windows APIs). So, this callback will set
	// E/RAX with a value msalruntime doesn't want. This is harmless or at least blameless,
	// because the convention makes the caller responsible for saving E/RAX.
	return windows.NewCallback(func(arHandle, data uintptr) uintptr {
		if arHandle == 0 {
			c <- result{err: errors.New("msalruntime returned a null AuthResult")}
			return 0
		}
		runtimeResult := AuthResult{arHandle}
		defer runtimeResult.Release()
		r := result{err: runtimeResult.Error()}
		if r.err == nil {
			r.ar, r.err = runtimeResult.Convert()
		}
		c <- r
		return 0
	})
}

func signInInteractively(ctx context.Context, ap broker.AuthParams) (internal.AuthResult, error) {
	c := make(chan result)
	hwnd := ap.ParentWindow
	if hwnd == 0 {
		hwnd, _, _ = getConsoleWindow.Call()
	}
	params, err := newAuthParameters(ap)
	if err != nil {
		return internal.AuthResult{}, err
	}
	defer params.Release()
	var asyncHandle uintptr
	errHandle, _, _ := signInInteractivelyAsync.Call(
		hwnd,
		params.handle,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("TODO-correlation-id"))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(ap.Account.PreferredUsername))),
		completionRoutine(c),
		uintptr(unsafe.Pointer(&c)),
		uintptr(unsafe.Pointer(&asyncHandle)),
	)
	if errHandle != 0 {
		fmt.Println("silent auth failed")
		return internal.AuthResult{}, convertError(errHandle)
	}
	defer releaseAsyncHandle.Call(asyncHandle)
	var ar internal.AuthResult
	select {
	case <-ctx.Done():
		// TODO: should we cancel the msalruntime async operation? It's tricky because
		// we don't read the channel again after this, leaving no goroutine to receive
		// msalruntime's callback.
		err = ctx.Err()
	case r := <-c:
		ar = r.ar
		err = r.err
	}
	return ar, err
}

func signInSilently(ctx context.Context, ap broker.AuthParams) (internal.AuthResult, error) {
	p, err := newAuthParameters(ap)
	if err != nil {
		return internal.AuthResult{}, err
	}
	defer p.Release()
	if ap.Username != "" {
		err = p.SetAdditionalParameter("MSALRuntime_Username", ap.Username)
		if err != nil {
			return internal.AuthResult{}, err
		}
	}
	if ap.Password != "" {
		err = p.SetAdditionalParameter("MSALRuntime_Password", ap.Password)
		if err != nil {
			return internal.AuthResult{}, err
		}
	}

	c := make(chan result)
	asyncHandle := uintptr(0)
	errHandle, _, _ := signInSilentlyAsync.Call(
		p.handle,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("correlation-id"))),
		completionRoutine(c),
		uintptr(unsafe.Pointer(&c)),
		uintptr(unsafe.Pointer(&asyncHandle)),
	)
	if errHandle != 0 {
		return internal.AuthResult{}, convertError(errHandle)
	}
	var ar internal.AuthResult
	// wait for msalruntime to call the completion routine
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case r := <-c:
		ar = r.ar
		err = r.err
	}
	if asyncHandle != 0 {
		_, _, _ = cancelAsyncOperation.Call(asyncHandle)
		_, _, _ = releaseAsyncHandle.Call(asyncHandle)
	}
	return ar, err
}

// TODO: use something like this to pipe msalruntime logs to MSAL Go's logger once MSAL Go has a logger
func RegisterLogCallback() (uintptr, error) {
	printMessage := windows.NewCallback(func(message *uint16, level uint, data uintptr) uintptr {
		if level > 3 {
			s := windows.UTF16PtrToString(message)
			fmt.Println(s)
		}
		return 0
	})
	var cbHandle uintptr
	errHandle, _, _ := registerLogCallback.Call(printMessage, 0, uintptr(unsafe.Pointer(&cbHandle)))
	return cbHandle, convertError(errHandle)
}

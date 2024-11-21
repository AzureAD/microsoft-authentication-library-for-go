### Design Proposal: Managed Identity Authentication with Logging in Azure SDK

#### **Overview**
This proposal outlines a design to implement two types of Managed Identity (MI) authentication mechanisms: one using the old Azure SDK and another leveraging the new SDK, with logging and structured logging (`log/slog`) integration. The focus is on demonstrating both methods, highlighting the improvements and how they can be applied in real-world scenarios.

#### **Use Case**
We need to authenticate against Azure services using Managed Identity, particularly for `SystemAssigned` identity. The new SDK provides structured logging with the `log/slog` package, which helps with monitoring and debugging. We will implement both the old and new approaches, showing the differences and benefits of the new logging system.

#### **Azure SDK Go**

In the old Azure SDK approach, we utilize `ManagedIdentityCredential` to authenticate and acquire a token for Azure services. Here's an overview of how this works in practice:

1. **Authentication**:
   The `ManagedIdentityCredential` in the old SDK interacts with the IMDS (Instance Metadata Service) to authenticate the application and retrieve an access token for the Azure Resource Manager (ARM) API (`https://management.azure.com`).

2. **Code Snippet**:
   ```go
   azlog.SetListener(func(event azlog.Event, s string){
		fmt.Println(": ", s)
	})
   // Azure SDK Managed Identity Authentication
   cred, err := azidentity.NewManagedIdentityCredential(nil)
   if err != nil {
       log.Fatalf("Failed to get ManagedIdentityCredential: %v", err)
   }
   
   token, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
       Scopes: []string{"https://management.azure.com/.default"},
   })
   if err != nil {
       log.Fatalf("Failed to acquire token: %v", err)
   }
   fmt.Println("Token acquired:", token.Token)
   ```

   **Log Output**:
   ```bash
   : Managed Identity Credential will use IMDS managed identity
   : NewDefaultAzureCredential failed to initialize some credentials:
     EnvironmentCredential: missing environment variable AZURE_TENANT_ID
     WorkloadIdentityCredential: no client ID specified. Check pod configuration or set ClientID in the options
   : ManagedIdentityCredential.GetToken() acquired a token for scope "https://management.azure.com"
   : DefaultAzureCredential authenticated with ManagedIdentityCredential
   : ManagedIdentityCredential.GetToken() acquired a token for scope "https://management.azure.com"
   ```

3. **Key Observations**:
   - The old SDK uses a `NewDefaultAzureCredential` class for token acquisition.
   - The logs are basic and do not provide structured logging, making it harder to troubleshoot and interpret.

#### **New SDK Approach with Structured Logging**

The new SDK introduces enhanced features like structured logging with `log/slog`. This approach offers better tracking and diagnostic capabilities. We’ll implement the Managed Identity using `mi.New()` with `SystemAssigned` identity and utilize structured logging.

1. **Authentication with Structured Logging**:
   The new SDK, with `log/slog`, integrates seamlessly with the token acquisition process. In this design, we will use `mi.New()` to initialize a `SystemAssigned` managed identity, while the log/slog captures the process and logs relevant information.


2. How to Here’s the complete code for your project that supports both callback-based logging for Go 1.18 and later and full `slog`-based logging for Go 1.21 and later. This version takes advantage of structured logging, multiple log levels, and flexible handling of logs with the `slog` package.

---

### Project Structure
```plaintext
microsoft-authentication-library-for-go/apps/
├── logger/
│   ├── logger_118.go
│   ├── logger_121.go
│   ├── logger_wrapper.go
├── managedidentity/
│   ├── managedidentity.go
├── main.go
```

---

### **1. `logger/logger_118.go`** (Callback Logging for Go 1.18 to 1.20)

```go
//go:build go1.18 && !go1.21

package logger

import "fmt"

// CallbackFunc defines the signature for callback functions
// we can only have one string to support azure sdk
type CallbackFunc func(level, message string)

// Logger struct for Go versions <= 1.20.
type Logger struct {
	LogCallback CallbackFunc
}

// Log method for Go <= 1.20, calls the callback function with log data.
func (a *Logger) Log(level string, message string, fields ...any) {
	if a.LogCallback != nil {
		a.LogCallback(level, message, fields...)
	} else {
		fmt.Println("No callback function provided")
	}
}
```

---

### **2. `logger/logger_121.go`** (slog Logging for Go 1.21 and later)

```go
//go:build go1.21

package logger

type CallbackFunc func(level, message string)

import (
	"log/slog"
)

// Logger struct for Go 1.21+ with full `slog` logging support.
type Logger struct {
	loging *slog.Logger
	callBackLogger CallbackFunc
}

// Log method for Go 1.21+ with full support for structured logging and multiple log levels.
func (a *Logger) Log(level string, message string, fields ...any) {
	if a.loging == nil {
		return
	}

	// Use the appropriate log level
	var logEntry slog.Record
	switch level {
	case "info":
		logEntry = slog.NewRecord(slog.LevelInfo, message, fields...)
		a.loging.Log(logEntry)
	case "error":
		logEntry = slog.NewRecord(slog.LevelError, message, fields...)
		a.loging.Log(logEntry)
	case "warn":
		logEntry = slog.NewRecord(slog.LevelWarn, message, fields...)
		a.loging.Log(logEntry)
	default:
		logEntry = slog.NewRecord(slog.LevelInfo, "Default log level: "+message, fields...)
		a.loging.Log(logEntry)
	}
}
```

---

### **3. `logger/logger_wrapper.go`** (Factory Method for Creating Logger Instances)

```go
package logger

import (
	"fmt"
	"log/slog"
	"runtime"
)

// New created a new logger instance, determining the Go version and choosing the appropriate logging method.
func New(input interface{}) (*Logger, error) {
	if isGo121OrLater() {
		if callback, ok := input.(func(level, message string)); ok {
			return &Logger{callBackLogger: callback}, nil
		}
		if logger, ok := input.(*slog.Logger); ok {
			return &Logger{Logger: logger}, nil
		}
		return nil, fmt.Errorf("invalid input for Go 1.21+; expected *slog.Logger")
	}

	if callback, ok := input.(func(level, message string)); ok {
		return &Logger{LogCallback: callback}, nil
	}
	return nil, fmt.Errorf("invalid input for Go <=1.20; expected CallbackFunc")
}

// isGo121OrLater checks if the Go version is 1.21 or later.
func isGo121OrLater() bool {
	return runtime.Version() >= "go1.21"
}
```

---
This is an example and can be use with any client.
### **4. `managedidentity/managedidentity.go`** (Configures the Logging Mechanism form `Logger`)

```go
package managedidentity

import (
	"fmt"
	"microsoft-authentication-library-for-go/apps/logger"
)

type Managedidentity struct {
	logger *logger.Logger
}

// Configure sets up the logger instance with either a callback or slog logger.
func (x *Client) New(input interface{}) error {
	instance, err := logger.New(input)
	if err != nil {
		return fmt.Errorf("failed to configure logger: %w", err)
	}
	x.logger = instance
	return nil
}

// Log delegates the logging to the logger instance with specified level, message, and fields.
func (x *managedidentity) Log(level, message string, fields ...any) {
	if x.logger == nil {
		fmt.Println("logger instance is not configured")
		return
	}
	x.logger.Log(level, message, fields...)
}
```

---

### **5. `main.go`** (Demonstrates Usage)

```go
package main

import (
	"fmt"
	"log/slog"
	"microsoft-authentication-library-for-go/apps/managedidentity"
)

func main() {
	miClient := &mi.Client{}

	// Configure Mi with a callback for Go <= 1.20
	callback := func(level, message string, fields ...any) {
		// This callback simply prints the log level, message, and fields
		fmt.Printf("[%s] %s ", level, message)
		for _, field := range fields {
			fmt.Printf("%v ", field)
		}
		fmt.Println()
	}
	if err := miClient.New(SystemAssigned(), WithLogCallback(callback)); err != nil {
		fmt.Println("Error configuring Mi with callback:", err)
		return
	}
	miClient.Log("info", "This is an info message via callback.", "username", "john_doe", "age", 30)
	miClient.Log("error", "This is an error message via callback.", "module", "user-service")

	// Configure Mi with slog for Go 1.21+
	logger := slog.New(slog.NewTextHandler())
	if err := miClient.New(SystemAssigned(), WithLogger(logger); err != nil {
		fmt.Println("Error configuring Mi with slog:", err)
		return
	}
	if err := miClient.New(SystemAssigned(), WithLogCallback(callback); err != nil {
		fmt.Println("Error configuring Mi with slog:", err)
		return
	}
	miClient.Log("info", "This is an info message via slog.", slog.String("username", "john_doe"), slog.Int("age", 30))
	miClient.Log("error", "This is an error message via slog.", slog.String("module", "user-service"), slog.Int("retry", 3))
	miClient.Log("warn", "Disk space is low.", slog.Int("free_space_mb", 100))
	miClient.Log("info", "Default log message.", slog.String("module", "main"))
}
```

---

### **6. Expected Output**

#### For **Go <= 1.20** (Callback-based Logging):

```plaintext
[info] This is an info message via callback. username john_doe age 30 
[error] This is an error message via callback. module user-service 
```

#### For **Go 1.21 and later** (slog-based Logging):

```plaintext
INFO: This is an info message via slog. {"username": "john_doe", "age": 30}
ERROR: This is an error message via slog. {"module": "user-service", "retry": 3}
WARN: Disk space is low. {"free_space_mb": 100}
INFO: Default log message. {"module": "main"}
```

---

### Key Pointers:

1. **Callback-based Logging for Go <= 1.20**:
   - The `logger_118.go` file uses a callback function (`CallbackFunc`) to log messages.
   - The callback prints the log level, message, and fields.
   
2. **Full `slog` Support for Go 1.21+**:
   - The `logger_121.go` file leverages the `slog` package, supporting structured logs, multiple log levels (`info`, `error`, `warn`), and fields.
   
3. **Flexible Configuration**:
   - The `managedidentity` module can be configured with either a callback (for Go <= 1.20) or a `slog.Logger` (for Go 1.21+).
   
4. **Structured Logging**:
   - You can pass key-value pairs using `slog.String`, `slog.Int`, etc., for structured logging, which is handled by `slog` in Go 1.21 and later.

This solution provides backward compatibility for Go 1.18 to 1.20 while fully leveraging the features of `slog` in Go 1.21 and beyond.


#### **Comparison of Old vs New Approaches**

| Feature                        | Old SDK Approach                    | New SDK with Structured Logging |
|---------------------------------|-------------------------------------|---------------------------------|
| **Authentication Method**       | `ManagedIdentityCredential`         | `SystemAssigned` via `mi.New()` |
| **Logging**                     | Basic text logs                     | Structured logs using `log/slog` |
| **Log Output**                  | Simple log messages                 | Detailed, timestamped, structured logs |
| **Usability**                   | Standard approach                   | Enhanced debugging and monitoring |
| **Error Handling**              | Simple error logs                   | Detailed error handling with contextual info |

#### **Advantages of the New Approach**

1. **Improved Diagnostics**: Structured logging provides detailed insights that are helpful for debugging and performance monitoring.
2. **Enhanced Monitoring**: With `log/slog`, logs can be better parsed and integrated into monitoring systems like Azure Monitor or ELK Stack.
3. **Ease of Use**: The new approach simplifies the interaction with Managed Identity credentials while adding more flexible logging.

#### **Conclusion**

The new SDK, with its use of structured logging through `log/slog`, greatly enhances the debugging and monitoring capabilities compared to the old SDK. This is especially useful in production environments where accurate, traceable logs are crucial for maintaining application health and troubleshooting issues.

This design proposal suggests transitioning to the new SDK to leverage these benefits while maintaining compatibility with `SystemAssigned` Managed Identity authentication, also have support for the older call back functions that Azure sdk uses for 1.18 Go version.
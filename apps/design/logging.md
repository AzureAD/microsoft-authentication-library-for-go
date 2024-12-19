# Logging

GO 1.21 introduces enhanced features like structured logging with `log/slog`.
As part of MSAL GO, we have decided to only support logging using slog from version 1.21.
The reason for this is `log/slog` greatly enhances the debugging and monitoring capabilities compared to the old SDK. This is especially useful in production environments where accurate, traceable logs are crucial for maintaining application health and troubleshooting issues. For versions older than 1.21, the user can specify *nil* to the *New()* function and a no-op is returned

## **Expected Output**

```plaintext
time=2024-12-19T01:25:58.730Z level=INFO msg="This is an info message via slog." username=john_doe age=30
time=2024-12-19T01:25:58.730Z level=ERROR msg="This is an error message via slog." module=user-service retry=3
time=2024-12-19T01:25:58.730Z level=WARN msg="Disk space is low." free_space_mb=100
time=2024-12-19T01:25:58.730Z level=INFO msg="Default log message." module=main
```

## Key Pointers

1. **For Go <= 1.20**:
   - User should pass *nil* to `logger.New(nil)`
   - No-op is returned and can be handled by user

2. **Full `slog` Support for Go 1.21+**:
   - The `logger.go` file leverages the `slog` package, supporting structured logs, multiple log levels (`info`, `error`, `warn`), and fields.

3. **Structured Logging**:
   - You can pass key-value pairs using `slog.String`, `slog.Int`, etc., for structured logging, which is handled by `slog` in Go 1.21 and later.

### **Sample**

A sample of the logger can be found in the following location:

```plaintext
microsoft-authentication-library-for-go/apps/devapps
├── logger/
│   ├── logger_sample.go
```

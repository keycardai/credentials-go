package mcp

// ResourceAccessError is returned when a resource's token is unavailable.
type ResourceAccessError struct {
	Message string
}

func (e *ResourceAccessError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "resource access error"
}

// AuthProviderConfigurationError indicates invalid AuthProvider configuration.
type AuthProviderConfigurationError struct {
	Message string
}

func (e *AuthProviderConfigurationError) Error() string {
	return e.Message
}

// EKSWorkloadIdentityConfigurationError indicates invalid EKS workload identity configuration
// detected at construction (e.g. no token file path, or the file is missing or empty).
type EKSWorkloadIdentityConfigurationError struct {
	Message string
}

func (e *EKSWorkloadIdentityConfigurationError) Error() string {
	return e.Message
}

// EKSWorkloadIdentityRuntimeError indicates the EKS token could not be read at request
// time (e.g. the token file was rotated away or emptied after construction). It is
// distinct from EKSWorkloadIdentityConfigurationError, which is a construction-time fault.
type EKSWorkloadIdentityRuntimeError struct {
	Message string
}

func (e *EKSWorkloadIdentityRuntimeError) Error() string {
	return e.Message
}

// ClientSecretConfigurationError indicates a ClientSecretCredential was constructed with
// invalid configuration, such as an empty client_id or client_secret, or an empty
// multi-zone map.
type ClientSecretConfigurationError struct {
	Message string
}

func (e *ClientSecretConfigurationError) Error() string {
	return e.Message
}

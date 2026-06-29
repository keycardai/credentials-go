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

// EKSWorkloadIdentityConfigurationError indicates invalid EKS workload identity configuration.
type EKSWorkloadIdentityConfigurationError struct {
	Message string
}

func (e *EKSWorkloadIdentityConfigurationError) Error() string {
	return e.Message
}

// FlyWorkloadIdentityConfigurationError indicates invalid Fly.io workload identity configuration.
type FlyWorkloadIdentityConfigurationError struct {
	Message string
}

func (e *FlyWorkloadIdentityConfigurationError) Error() string {
	return e.Message
}

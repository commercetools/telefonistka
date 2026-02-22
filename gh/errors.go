package gh

// Error is a constant sentinel error type for the gh package.
type Error string

func (e Error) Error() string { return string(e) }

// Authentication errors.
const (
	ErrNoInstallation Error = "no app installation for owner"
	ErrNoCredentials  Error = "no credentials configured"
)

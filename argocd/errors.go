package argocd

// Error is a constant sentinel error type for the argocd package.
type Error string

func (e Error) Error() string { return string(e) }

// Discovery errors.
const (
	ErrAppNotFound    Error = "application not found"
	ErrAppSetNotFound Error = "application set not found"
)

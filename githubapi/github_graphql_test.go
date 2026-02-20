package githubapi

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/shurcooL/githubv4"
)

// RoundTripFunc is a helper for mocking http clients
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip is the implementation for http.RoundTripper
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}

func TestGetBotGhIdentity(t *testing.T) {
	t.Parallel()
	t.Run("should return bot identity", func(t *testing.T) {
		t.Parallel()
		mockClient := NewTestClient(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"data":{"viewer":{"login":"test-bot"}}}`)),
				Header:     make(http.Header),
			}
		})
		v4client := githubv4.NewClient(mockClient)

		identity, err := getBotIdentity(t.Context(), v4client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if identity != "test-bot" {
			t.Errorf("got %q, want %q", identity, "test-bot")
		}
	})
}

func TestMinimizeStalePRComments(t *testing.T) {
	t.Parallel()
	var identityCalled, commentsCalled, mutationCalled bool

	mockClient := NewTestClient(func(req *http.Request) *http.Response {
		bodyBytes, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		bodyString := string(bodyBytes)

		// MinimizeStalePRComments fires three requests:
		// 1. getBotIdentity (viewer query)
		// 2. getUnminimizedComments (repository/pullRequest query)
		// 3. minimizeComment mutation(s)
		if strings.Contains(bodyString, "viewer") && !strings.Contains(bodyString, "repository") {
			identityCalled = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"data":{"viewer":{"login":"test-bot"}}}`)),
				Header:     make(http.Header),
			}
		}

		if strings.Contains(bodyString, "repository") {
			commentsCalled = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewBufferString(`{
					"data": {
						"repository": {
							"pullRequest": {
								"comments": {
									"edges": [
										{
											"node": {
												"id": "comment1",
												"isMinimized": false,
												"body": "<!-- telefonistka_tag --> some comment",
												"author": {"login": "test-bot"}
											}
										},
										{
											"node": {
												"id": "comment2",
												"isMinimized": true,
												"body": "<!-- telefonistka_tag --> another comment",
												"author": {"login": "test-bot"}
											}
										},
										{
											"node": {
												"id": "comment3",
												"isMinimized": false,
												"body": "some other comment",
												"author": {"login": "test-bot"}
											}
										},
										{
											"node": {
												"id": "comment4",
												"isMinimized": false,
												"body": "<!-- telefonistka_tag --> comment from other user",
												"author": {"login": "other-user"}
											}
										}
									]
								}
							}
						}
					}
				}`)),
				Header: make(http.Header),
			}
		}

		if strings.Contains(bodyString, "minimizeComment") {
			mutationCalled = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"data":{"minimizeComment":{"minimizedComment":{"isMinimized":true}}}}`)),
				Header:     make(http.Header),
			}
		}

		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(bytes.NewBufferString(`{"message":"Unknown request"}`)),
			Header:     make(http.Header),
		}
	})
	v4client := githubv4.NewClient(mockClient)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	c := Context{
		Owner:    "owner",
		Repo:     "repo",
		PrNumber: 123,
		PrLogger: logger,
		GraphQL:  v4client,
	}

	err := minimizeStalePRComments(t.Context(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !identityCalled {
		t.Error("GraphQL query for bot identity was not called")
	}
	if !commentsCalled {
		t.Error("GraphQL query to fetch comments was not called")
	}
	if !mutationCalled {
		t.Error("GraphQL mutation to minimize comment was not called")
	}
}

func TestShouldMinimize(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		comment     prComment
		botIdentity string
		want        bool
	}{
		"should minimize": {
			comment: prComment{
				IsMinimized: false,
				Body:        "<!-- telefonistka_tag --> some diff",
				Author:      struct{ Login githubv4.String }{Login: "test-bot"},
			},
			botIdentity: "test-bot",
			want:        true,
		},
		"already minimized": {
			comment: prComment{
				IsMinimized: true,
				Body:        "<!-- telefonistka_tag --> some diff",
				Author:      struct{ Login githubv4.String }{Login: "test-bot"},
			},
			botIdentity: "test-bot",
			want:        false,
		},
		"wrong author": {
			comment: prComment{
				IsMinimized: false,
				Body:        "<!-- telefonistka_tag --> some diff",
				Author:      struct{ Login githubv4.String }{Login: "other-user"},
			},
			botIdentity: "test-bot",
			want:        false,
		},
		"no tag": {
			comment: prComment{
				IsMinimized: false,
				Body:        "just a regular comment",
				Author:      struct{ Login githubv4.String }{Login: "test-bot"},
			},
			botIdentity: "test-bot",
			want:        false,
		},
		"empty body": {
			comment: prComment{
				IsMinimized: false,
				Body:        "",
				Author:      struct{ Login githubv4.String }{Login: "test-bot"},
			},
			botIdentity: "test-bot",
			want:        false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := shouldMinimize(tc.comment, tc.botIdentity); got != tc.want {
				t.Errorf("shouldMinimize() = %v, want %v", got, tc.want)
			}
		})
	}
}

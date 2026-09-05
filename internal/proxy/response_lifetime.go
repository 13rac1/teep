package proxy

import (
	"context"
	"io"
	"net/http"
)

// responseLifetime bounds buffered response processing and downstream writes
// by the same context that authorizes the upstream attempt.
type responseLifetime struct {
	http.ResponseWriter
	controller *http.ResponseController
	contextErr func() error
	err        error
}

func newResponseLifetime(ctx context.Context, w http.ResponseWriter) (*responseLifetime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	controller := http.NewResponseController(w)
	if deadline, ok := ctx.Deadline(); ok {
		if err := controller.SetWriteDeadline(deadline); err != nil {
			return nil, err
		}
	}
	return &responseLifetime{ResponseWriter: w, controller: controller, contextErr: ctx.Err}, nil
}

func (w *responseLifetime) WriteHeader(status int) {
	if w.check() == nil {
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *responseLifetime) Write(body []byte) (int, error) {
	if err := w.check(); err != nil {
		return 0, err
	}
	n, err := w.ResponseWriter.Write(body)
	w.err = err
	return n, w.check()
}

func (w *responseLifetime) Flush() {
	if w.check() == nil {
		w.err = w.controller.Flush()
	}
}

func (w *responseLifetime) check() error {
	if err := w.contextErr(); err != nil {
		return err
	}
	return w.err
}

type responseLifetimeReader struct {
	io.Reader
	check func() error
}

func (r responseLifetimeReader) Read(p []byte) (int, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

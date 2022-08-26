package dnsserver

// Middleware is a general interface for dnsserver.Server middlewares.
type Middleware interface {
	// Wrap wraps the specified Handler and returns a new handler.  This
	// handler may call the underlying one and implement additional logic.
	Wrap(h Handler) (wrapped Handler)
}

// WithMiddlewares is a helper function that attaches the specified middlewares
// to the Handler.  Middlewares will be called in the same order in which they
// were specified.
func WithMiddlewares(h Handler, middlewares ...Middleware) (wrapped Handler) {
	wrapped = h

	// Go through middlewares in the reverse order.  This way the middleware
	// that was specified first will be called first.
	for i := len(middlewares) - 1; i >= 0; i-- {
		m := middlewares[i]
		wrapped = m.Wrap(wrapped)
	}

	return wrapped
}

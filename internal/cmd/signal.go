package cmd

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/log"
	"golang.org/x/sys/unix"
)

// signalHandler processes incoming signals and shuts services down.
type signalHandler struct {
	signal chan os.Signal

	// services are the services that are shut down before application
	// exiting.
	services []agd.Service
}

// newSignalHandler returns a new signalHandler that shuts down services.
func newSignalHandler() (h signalHandler) {
	h = signalHandler{
		signal: make(chan os.Signal, 1),
	}

	signal.Notify(h.signal, unix.SIGINT, unix.SIGQUIT, unix.SIGTERM)

	return h
}

// add adds a service to the signal handler.
func (h *signalHandler) add(s agd.Service) {
	h.services = append(h.services, s)
}

// Exit status constants.
const (
	statusSuccess = 0
	statusError   = 1
)

// handle processes OS signals.  status is statusSuccess on success and
// statusError on error.
func (h *signalHandler) handle() (status int) {
	defer log.OnPanic("signalHandler.handle")

	for sig := range h.signal {
		log.Info("sighdlr: received signal %q", sig)

		switch sig {
		case
			unix.SIGINT,
			unix.SIGQUIT,
			unix.SIGTERM:
			return h.shutdown()
		}
	}

	// Shouldn't happen, since h.signal is currently never closed.
	return statusError
}

// shutdown gracefully shuts down all services.  status is statusSuccess on
// success and statusError on error.
func (h *signalHandler) shutdown() (status int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Info("sighdlr: shutting down services")
	for i := len(h.services) - 1; i >= 0; i-- {
		s := h.services[i]
		err := s.Shutdown(ctx)
		if err != nil {
			log.Error("sighdlr: shutting down service at index %d: %s", i, err)
			status = statusError
		}
	}

	log.Info("sighdlr: shutting down adguard dns")

	return status
}

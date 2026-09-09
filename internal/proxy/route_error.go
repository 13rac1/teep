package proxy

import (
	"context"
	"errors"
	"net/http"

	"github.com/13rac1/teep/internal/provider/nearroute"
	"github.com/13rac1/teep/internal/tlsct"
)

// routeErrorResponse is shared by normal inference and Explore.
func routeErrorResponse(err error) (status int, classification string) {
	if failure, ok := errors.AsType[*nearroute.Error](err); ok {
		switch failure.Kind {
		case nearroute.Metadata:
		// Preserve cancellation and socket-capacity classification below.
		case nearroute.Input:
			return http.StatusBadRequest, "invalid_model"
		case nearroute.UnknownModel:
			return http.StatusBadRequest, "unknown_model"
		case nearroute.Capacity:
			return http.StatusServiceUnavailable, "route_capacity"
		case nearroute.Delay:
			return http.StatusServiceUnavailable, "metadata_delay"
		case nearroute.Expired:
			return http.StatusServiceUnavailable, "metadata_expired"
		case nearroute.Configuration:
			return http.StatusBadGateway, "route_configuration_mismatch"
		}
	}
	if errors.Is(err, tlsct.ErrConnectionCapacity) {
		return http.StatusServiceUnavailable, "metadata_socket_capacity"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, "route_deadline"
	}
	if errors.Is(err, context.Canceled) {
		return http.StatusRequestTimeout, "route_canceled"
	}
	return http.StatusBadGateway, "metadata_failed"
}

func writeRouteError(w http.ResponseWriter, err error) {
	status, classification := routeErrorResponse(err)
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	http.Error(w, classification, status)
}

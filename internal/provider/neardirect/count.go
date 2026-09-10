package neardirect

import (
	"errors"

	"github.com/13rac1/teep/internal/provider/nearparse"
)

type backendCount struct {
	Domain          string `json:"domain"`
	RequestedDomain string `json:"requested_domain"`
	Healthy         uint64 `json:"healthy"`
	Total           uint64 `json:"total"`
}

func parseBackendCount(body []byte, canonical string) (backendCount, []string, error) {
	var count backendCount
	if len(body) > 64<<10 {
		return count, nil, errors.New("backend-count response exceeds size limit")
	}
	unknown, err := nearparse.Object(body, &count, "backend_count")
	if err != nil {
		return count, unknown, err
	}
	if count.Domain != canonical || count.RequestedDomain != canonical {
		return count, unknown, errors.New("backend-count domain does not match canonical authority")
	}
	if count.Healthy == 0 || count.Healthy > count.Total {
		return count, unknown, errors.New("backend-count healthy must be positive and at most total")
	}
	return count, unknown, nil
}

package neardirect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearroute"
	"github.com/13rac1/teep/internal/tlsct"
)

type metadataSnapshot struct {
	mapping   map[string]string
	healthy   uint64
	fetchedAt time.Time
}
type mappingSnapshot struct {
	authority string
	fetchedAt time.Time
}
type metadataOperation struct {
	done     chan struct{}
	snapshot metadataSnapshot
	err      error
}
type metadataRecord struct {
	snapshot   metadataSnapshot
	operation  *metadataOperation
	failure    error
	retryAfter time.Time
	lastUsed   time.Time
}

// metadata shares one completion channel for each admitted fetch, regardless
// of how many callers wait or cancel. No waiter is retained by the resolver.
func (r *EndpointResolver) metadata(ctx context.Context, authority string) (metadataSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return metadataSnapshot{}, err
	}
	r.mu.Lock()
	r.initializeLocked()
	if r.closed {
		r.mu.Unlock()
		return metadataSnapshot{}, context.Canceled
	}
	record, err := r.metadataRecordLocked(authority)
	if err != nil {
		r.mu.Unlock()
		return metadataSnapshot{}, err
	}
	now := r.now()
	record.lastUsed = now
	if snapshotFresh(record.snapshot.fetchedAt, now) {
		snapshot := record.snapshot
		r.mu.Unlock()
		return snapshot, nil
	}
	if now.Before(record.retryAfter) {
		err := resolutionError(nearroute.Delay, "metadata retry delay", record.failure)
		r.mu.Unlock()
		return metadataSnapshot{}, err
	}
	op := record.operation
	if op == nil {
		if authority != "" && r.activeCounts >= maxCountFetches {
			r.mu.Unlock()
			return metadataSnapshot{}, resolutionError(nearroute.Capacity, "active backend-count fetch limit reached", nil)
		}
		op = &metadataOperation{done: make(chan struct{})}
		record.operation = op
		if authority != "" {
			r.activeCounts++
		}
		r.workers.Add(1)
		operationCtx, cancel := context.WithTimeout(r.owner, refreshTimeout)
		// Shared work belongs to the resolver; a waiter must not cancel other callers.
		go r.fetchMetadata(operationCtx, cancel, record, op, authority) //nolint:contextcheck // Use the bounded resolver lifecycle, independent of the waiter.
	}
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		return metadataSnapshot{}, ctx.Err()
	case <-op.done:
		if err := ctx.Err(); err != nil {
			return metadataSnapshot{}, err
		}
		return op.snapshot, op.err
	}
}

func (r *EndpointResolver) metadataRecordLocked(authority string) (*metadataRecord, error) {
	if authority == "" {
		return &r.endpoints, nil
	}
	if record := r.counts[authority]; record != nil {
		return record, nil
	}
	// Do not reserve records for work rejected by active-fetch admission.
	if r.activeCounts >= maxCountFetches {
		return nil, resolutionError(nearroute.Capacity, "active backend-count fetch limit reached", nil)
	}
	if len(r.counts) >= maxDiscoveryMappings && !r.evictCountLocked(r.now()) {
		return nil, resolutionError(nearroute.Capacity, "backend-count record limit reached", nil)
	}
	record := &metadataRecord{}
	r.counts[authority] = record
	return record, nil
}

func (r *EndpointResolver) evictCountLocked(now time.Time) bool {
	oldest := ""
	for authority, record := range r.counts {
		if record.operation != nil || now.Before(record.retryAfter) {
			continue
		}
		if oldest == "" || record.lastUsed.Before(r.counts[oldest].lastUsed) {
			oldest = authority
		}
	}
	if oldest == "" {
		return false
	}
	delete(r.counts, oldest)
	return true
}

func (r *EndpointResolver) fetchMetadata(ctx context.Context, cancel context.CancelFunc, record *metadataRecord, op *metadataOperation, authority string) {
	defer r.workers.Done()
	defer cancel()
	snapshot, err := r.retrieveMetadata(ctx, authority)
	if err != nil {
		err = resolutionError(nearroute.Metadata, "NEAR metadata retrieval or validation failed", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if authority != "" {
		r.activeCounts--
	}
	if r.closed {
		err = context.Canceled
	} else if ctx.Err() != nil {
		err = ctx.Err()
	}
	op.err = err
	if record.operation == op {
		record.operation = nil
		if err == nil {
			snapshot.fetchedAt = r.now()
			record.snapshot = snapshot
			record.failure = nil
			record.retryAfter = time.Time{}
			op.snapshot = snapshot
		} else if metadataFailureEligible(err) {
			record.failure = err
			record.retryAfter = r.now().Add(metadataFailureDelay)
		}
	}
	close(op.done)
}

func metadataFailureEligible(err error) bool {
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, tlsct.ErrConnectionCapacity)
}

func snapshotFresh(fetchedAt, now time.Time) bool {
	return !fetchedAt.IsZero() && now.Before(fetchedAt.Add(endpointsTTL))
}

func (r *EndpointResolver) retrieveMetadata(ctx context.Context, authority string) (metadataSnapshot, error) {
	endpoint, limit := r.endpointsURL, int64(maxDiscoveryBody)
	if authority != "" {
		parsed, err := url.Parse(r.countURL)
		if err != nil {
			return metadataSnapshot{}, err
		}
		query := parsed.Query()
		query.Set("domain", authority)
		parsed.RawQuery = query.Encode()
		endpoint, limit = parsed.String(), 64<<10
	}
	body, err := r.fetchMetadataBody(ctx, endpoint, limit)
	if err != nil {
		return metadataSnapshot{}, err
	}
	if authority == "" {
		mapping, err := parseEndpointMapping(body, r.restrictToNearAI)
		return metadataSnapshot{mapping: mapping}, err
	}
	count, unknown, err := parseBackendCount(body, authority)
	if err != nil {
		return metadataSnapshot{}, err
	}
	if len(unknown) != 0 {
		return metadataSnapshot{}, fmt.Errorf("unknown backend-count fields: %v", unknown)
	}
	return metadataSnapshot{healthy: count.Healthy}, nil
}

func (r *EndpointResolver) fetchMetadataBody(ctx context.Context, endpoint string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	provider.SetUserAgent(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("metadata response exceeds size limit")
	}
	return body, nil
}

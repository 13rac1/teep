package neardirect

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearroute"
)

// Selection contains routing metadata only, never evidence or authorization.
type Selection struct {
	Canonical string
	Index     uint64
	Authority string
	Mode      string
}

type selectionOperation struct {
	done      chan struct{}
	selection Selection
	route     provider.ResolvedRoute
	err       error
}

func randomIndex(ctx context.Context, healthy uint64) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if healthy == 0 {
		return 0, errors.New("cannot select a backend from an empty healthy set")
	}
	value, err := rand.Int(rand.Reader, new(big.Int).SetUint64(healthy))
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return value.Uint64(), nil
}

// ResolveConfigured establishes one route per model. The caller supplies the
// immutable origin validated by nearroute.ParseOrigin during construction.
func (r *EndpointResolver) ResolveConfigured(ctx context.Context, model string, configured nearroute.Origin) (provider.ResolvedRoute, error) {
	if err := nearroute.ValidateModel(model); err != nil {
		return provider.ResolvedRoute{}, err
	}
	if err := ctx.Err(); err != nil {
		return provider.ResolvedRoute{}, err
	}
	if configured.Static {
		return provider.NewResolvedRoute("https://"+configured.Authority, "")
	}
	op, err := r.selectionForModel(ctx, model, configured)
	if err != nil {
		return provider.ResolvedRoute{}, err
	}

	select {
	case <-ctx.Done():
		return provider.ResolvedRoute{}, ctx.Err()
	case <-op.done:
		if err := ctx.Err(); err != nil {
			return provider.ResolvedRoute{}, err
		}
		return op.route, op.err
	}
}

// selectionForModel checks shared endpoint metadata before reserving a route
// slot. Unknown callers can join discovery, but cannot consume selection slots.
func (r *EndpointResolver) selectionForModel(ctx context.Context, model string, configured nearroute.Origin) (*selectionOperation, error) {
	r.mu.Lock()
	r.initializeLocked()
	if r.closed {
		r.mu.Unlock()
		return nil, context.Canceled
	}
	if r.selectionOrigin != "" && r.selectionOrigin != configured.Authority {
		r.mu.Unlock()
		return nil, resolutionError(nearroute.Configuration, "resolver already belongs to a different configured origin", nil)
	}
	r.selectionOrigin = configured.Authority
	if op := r.selections[model]; op != nil {
		r.mu.Unlock()
		return op, nil
	}
	r.mu.Unlock()
	deadline := time.Now().Add(selectionTimeout)
	mapping, err := r.mappingForModel(ctx, model)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, context.Canceled
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Another caller may have selected this model while metadata was acquired.
	if op := r.selections[model]; op != nil {
		return op, nil
	}
	if err != nil {
		return nil, err
	}
	if len(r.selections) >= maxDiscoveryMappings {
		return nil, resolutionError(nearroute.Capacity, "retained route capacity reached; configuration change or restart may be required", nil)
	}
	op := &selectionOperation{done: make(chan struct{})}
	r.selections[model] = op
	r.workers.Add(1)
	operationCtx, cancel := context.WithDeadline(r.owner, deadline)
	// Shared work belongs to the resolver; a waiter must not cancel other callers.
	go r.selectRoute(operationCtx, cancel, model, configured, mapping, op) //nolint:contextcheck // Use the bounded resolver lifecycle, independent of the waiter.
	return op, nil
}

func (r *EndpointResolver) selectRoute(ctx context.Context, cancel context.CancelFunc, model string, configured nearroute.Origin, mapping mappingSnapshot, op *selectionOperation) {
	defer r.workers.Done()
	defer cancel()
	selected, countTime, err := r.initialSelection(ctx, mapping, configured)
	var route provider.ResolvedRoute
	if err == nil {
		route, err = provider.NewResolvedRoute("https://"+selected.Authority, "")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		err = context.Canceled
	} else if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil && (!snapshotFresh(mapping.fetchedAt, r.now()) || (!countTime.IsZero() && !snapshotFresh(countTime, r.now()))) {
		err = resolutionError(nearroute.Expired, "initial route metadata expired before publication", nil)
	}
	if r.selections[model] != op {
		err = resolutionError(nearroute.Configuration, "initial route operation lost ownership", nil)
	}
	op.err = err
	if err == nil {
		op.route = route
		op.selection = selected
	} else if r.selections[model] == op {
		delete(r.selections, model)
	}
	close(op.done)
}

func (r *EndpointResolver) initialSelection(ctx context.Context, mapping mappingSnapshot, configured nearroute.Origin) (Selection, time.Time, error) {
	if configured.Indexed && configured.Authority == mapping.authority {
		return Selection{}, time.Time{}, resolutionError(nearroute.Configuration, "ambiguous NEAR indexed authority", nil)
	}
	if configured.Canonical != "" && configured.Canonical != mapping.authority {
		return Selection{}, time.Time{}, resolutionError(nearroute.Configuration, "configured NEAR origin does not match discovered model authority", nil)
	}
	if configured.Indexed {
		return Selection{Canonical: mapping.authority, Index: configured.Index, Authority: configured.Authority, Mode: "explicit"}, time.Time{}, nil
	}
	count, err := r.metadata(ctx, mapping.authority)
	if err != nil {
		return Selection{}, time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return Selection{}, time.Time{}, err
	}
	index, err := r.selector(ctx, count.healthy)
	if err != nil {
		return Selection{}, time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return Selection{}, time.Time{}, err
	}
	if index >= count.healthy {
		return Selection{}, time.Time{}, resolutionError(nearroute.Configuration, "backend selector returned an out-of-range index", nil)
	}
	authority, err := nearroute.IndexedAuthority(mapping.authority, index)
	return Selection{Canonical: mapping.authority, Index: index, Authority: authority, Mode: "discovered"}, count.fetchedAt, err
}

// LookupSelection reads an established selection without fetching metadata or updating recency.
func (r *EndpointResolver) LookupSelection(model string) (Selection, bool) {
	if nearroute.ValidateModel(model) != nil {
		return Selection{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	op := r.selections[model]
	if op == nil {
		return Selection{}, false
	}
	select {
	case <-op.done:
		return op.selection, op.err == nil
	default:
		return Selection{}, false
	}
}

func resolutionError(kind nearroute.ErrorKind, detail string, cause error) error {
	return &nearroute.Error{Kind: kind, Detail: detail, Cause: cause}
}

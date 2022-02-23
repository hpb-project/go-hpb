// Code generated by the feature package; DO NOT EDIT.

package feature

import (
	"context"

	"github.com/influxdata/flux/internal/pkg/feature"
)

type (
	Flag       = feature.Flag
	Flagger    = feature.Flagger
	StringFlag = feature.StringFlag
	FloatFlag  = feature.FloatFlag
	IntFlag    = feature.IntFlag
	BoolFlag   = feature.BoolFlag
)

var narrowTransformationFilter = feature.MakeBoolFlag(
	"Narrow Transformation Filter",
	"narrowTransformationFilter",
	"Jonathan Sternberg",
	false,
)

// NarrowTransformationFilter - Enable the NarrowTransformation implementation of filter
func NarrowTransformationFilter() BoolFlag {
	return narrowTransformationFilter
}

var aggregateTransformationTransport = feature.MakeBoolFlag(
	"Aggregate Transformation Transport",
	"aggregateTransformationTransport",
	"Jonathan Sternberg",
	false,
)

// AggregateTransformationTransport - Enable Transport interface for AggregateTransformation
func AggregateTransformationTransport() BoolFlag {
	return aggregateTransformationTransport
}

var groupTransformationGroup = feature.MakeBoolFlag(
	"Group Transformation Group",
	"groupTransformationGroup",
	"Sean Brickley",
	false,
)

// GroupTransformationGroup - Enable GroupTransformation interface for the group function
func GroupTransformationGroup() BoolFlag {
	return groupTransformationGroup
}

var queryConcurrencyLimit = feature.MakeIntFlag(
	"Query Concurrency Limit",
	"queryConcurrencyLimit",
	"Jonathan Sternberg",
	0,
)

// QueryConcurrencyLimit - Sets the query concurrency limit for the planner
func QueryConcurrencyLimit() IntFlag {
	return queryConcurrencyLimit
}

var optimizeDerivative = feature.MakeBoolFlag(
	"Optimize Derivative",
	"optimizeDerivative",
	"Jonathan Sternberg",
	false,
)

// OptimizeDerivative - Enable derivative optimization
func OptimizeDerivative() BoolFlag {
	return optimizeDerivative
}

// Inject will inject the Flagger into the context.
func Inject(ctx context.Context, flagger Flagger) context.Context {
	return feature.Inject(ctx, flagger)
}

var all = []Flag{
	narrowTransformationFilter,
	aggregateTransformationTransport,
	groupTransformationGroup,
	queryConcurrencyLimit,
	optimizeDerivative,
}

var byKey = map[string]Flag{
	"narrowTransformationFilter":       narrowTransformationFilter,
	"aggregateTransformationTransport": aggregateTransformationTransport,
	"groupTransformationGroup":         groupTransformationGroup,
	"queryConcurrencyLimit":            queryConcurrencyLimit,
	"optimizeDerivative":               optimizeDerivative,
}

// Flags returns all feature flags.
func Flags() []Flag {
	return all
}

// ByKey returns the Flag corresponding to the given key.
func ByKey(k string) (Flag, bool) {
	v, found := byKey[k]
	return v, found
}

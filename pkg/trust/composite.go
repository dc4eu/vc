package trust

import (
	"context"
	"fmt"
	"strings"
)

// CompositeEvaluator combines multiple TrustEvaluators with configurable strategy.
type CompositeEvaluator struct {
	evaluators []TrustEvaluator
	strategy   CompositeStrategy
}

// CompositeStrategy determines how multiple evaluators are combined.
type CompositeStrategy int

const (
	// StrategyFirstSuccess returns success on the first positive decision.
	// This is useful for "any trust source" scenarios.
	StrategyFirstSuccess CompositeStrategy = iota

	// StrategyAllMustSucceed requires all evaluators to return a positive decision.
	// This is useful for "all trust sources must agree" scenarios.
	StrategyAllMustSucceed

	// StrategyFallback tries evaluators in order, returning the first non-error result.
	// This is useful for "try local first, then remote" scenarios.
	StrategyFallback
)

// NewCompositeEvaluator creates a composite evaluator with the given strategy.
func NewCompositeEvaluator(strategy CompositeStrategy, evaluators ...TrustEvaluator) *CompositeEvaluator {
	return &CompositeEvaluator{
		evaluators: evaluators,
		strategy:   strategy,
	}
}

// Evaluate implements TrustEvaluator.
func (c *CompositeEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	if len(c.evaluators) == 0 {
		return nil, fmt.Errorf("no evaluators configured")
	}

	switch c.strategy {
	case StrategyFirstSuccess:
		return c.evaluateFirstSuccess(ctx, req)
	case StrategyAllMustSucceed:
		return c.evaluateAllMustSucceed(ctx, req)
	case StrategyFallback:
		return c.evaluateFallback(ctx, req)
	default:
		return nil, fmt.Errorf("unknown strategy: %d", c.strategy)
	}
}

// evaluateFirstSuccess returns success on the first positive decision.
func (c *CompositeEvaluator) evaluateFirstSuccess(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	var lastError error
	var reasons []string

	for _, eval := range c.evaluators {
		if !eval.SupportsKeyType(req.KeyType) {
			continue
		}

		decision, err := eval.Evaluate(ctx, req)
		if err != nil {
			lastError = err
			continue
		}

		if decision.Trusted {
			return decision, nil
		}

		if decision.Reason != "" {
			reasons = append(reasons, decision.Reason)
		}
	}

	// No evaluator returned success
	return &TrustDecision{
		Trusted: false,
		Reason:  fmt.Sprintf("no trust evaluator accepted: %s", strings.Join(reasons, "; ")),
	}, lastError
}

// evaluateAllMustSucceed requires all evaluators to return positive decisions.
func (c *CompositeEvaluator) evaluateAllMustSucceed(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	var frameworks []string
	evaluatorCount := 0

	for _, eval := range c.evaluators {
		if !eval.SupportsKeyType(req.KeyType) {
			continue
		}

		evaluatorCount++
		decision, err := eval.Evaluate(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("evaluator failed: %w", err)
		}

		if !decision.Trusted {
			return decision, nil
		}

		if decision.TrustFramework != "" {
			frameworks = append(frameworks, decision.TrustFramework)
		}
	}

	if evaluatorCount == 0 {
		return nil, fmt.Errorf("no evaluator supports key type: %s", req.KeyType)
	}

	return &TrustDecision{
		Trusted:        true,
		Reason:         "all trust evaluators accepted",
		TrustFramework: strings.Join(frameworks, "+"),
	}, nil
}

// evaluateFallback tries evaluators in order, returning the first result.
func (c *CompositeEvaluator) evaluateFallback(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	var lastError error

	for _, eval := range c.evaluators {
		if !eval.SupportsKeyType(req.KeyType) {
			continue
		}

		decision, err := eval.Evaluate(ctx, req)
		if err != nil {
			lastError = err
			continue
		}

		return decision, nil
	}

	if lastError != nil {
		return nil, fmt.Errorf("all evaluators failed: %w", lastError)
	}

	return nil, fmt.Errorf("no evaluator supports key type: %s", req.KeyType)
}

// SupportsKeyType returns true if any evaluator supports the given key type.
func (c *CompositeEvaluator) SupportsKeyType(kt KeyType) bool {
	for _, eval := range c.evaluators {
		if eval.SupportsKeyType(kt) {
			return true
		}
	}
	return false
}

// AddEvaluator adds an evaluator to the composite.
func (c *CompositeEvaluator) AddEvaluator(eval TrustEvaluator) {
	c.evaluators = append(c.evaluators, eval)
}

// Verify interface compliance
var _ TrustEvaluator = (*CompositeEvaluator)(nil)

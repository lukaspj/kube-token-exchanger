// Package metrics exposes Prometheus metrics for the token exchanger.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// ExchangesTotal counts token exchanges by outcome.
	ExchangesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tokenexchange_exchanges_total",
		Help: "Total number of authentik token exchanges performed.",
	}, []string{"namespace", "name", "result"})

	// ExchangeDurationSeconds observes the duration of token exchanges.
	ExchangeDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tokenexchange_exchange_duration_seconds",
		Help:    "Duration of authentik token exchanges in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"namespace", "name"})

	// TokenTTLSeconds reports the remaining lifetime of the currently stored
	// token for each TokenExchangeRequest.
	TokenTTLSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tokenexchange_token_ttl_seconds",
		Help: "Remaining lifetime in seconds of the token stored in the target Secret.",
	}, []string{"namespace", "name"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		ExchangesTotal,
		ExchangeDurationSeconds,
		TokenTTLSeconds,
	)
}

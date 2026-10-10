package technitium

import "context"

// Metrics are what the server has counted since it started, where Stats is
// what it counted over a window.
type Metrics struct {
	// UpSince is when the server started, in UTC
	UpSince       string     `json:"uptimestamp"`
	UptimeSeconds int64      `json:"uptimeSeconds"`
	Lifetime      StatTotals `json:"lifetimeCounters"`
}

// Metrics reads what the server has counted since it started.
func (c *Client) Metrics(ctx context.Context) (*Metrics, error) {
	var out Metrics
	if err := c.read(ctx, "dashboard/metrics/json", nil, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// MetricsText is Metrics as Prometheus reads them: a text of counters, one
// a line.
func (c *Client) MetricsText(ctx context.Context) (string, error) {
	return c.readText(ctx, "dashboard/metrics/text", nil)
}

// DeleteAllStats deletes every statistic the server keeps, from its disk and
// from memory: the dashboard starts again from nothing.
func (c *Client) DeleteAllStats(ctx context.Context) error {
	return c.write(ctx, "dashboard/stats/deleteAll", nil, nil)
}

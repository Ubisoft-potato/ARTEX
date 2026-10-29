package server

import (
	"github.com/Autumn-27/artex/db"
	"net/http"
)

func (s *Server) triggerQueueStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := db.BoundedContext(r.Context())
	defer cancel()
	rows, err := s.m.pg.QueryContext(ctx, `SELECT state,count(*),COALESCE(EXTRACT(EPOCH FROM now()-min(created_at)),0)::bigint FROM trigger_jobs GROUP BY state`)
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	defer rows.Close()
	type summary struct {
		State         string `json:"state"`
		Count         int64  `json:"count"`
		OldestSeconds int64  `json:"oldest_seconds"`
	}
	items := []summary{}
	for rows.Next() {
		var item summary
		if err := rows.Scan(&item.State, &item.Count, &item.OldestSeconds); err != nil {
			writeErr(w, 503, err.Error())
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"states": items, "max_active": 8, "max_pending": 1000, "max_queue_age_seconds": 86400})
}

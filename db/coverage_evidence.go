package db

import "encoding/json"

// CoverageEvidence is a bounded, relation-checked read over one task and exactly
// its live direct sources. Node IDs are global; source data is never copied.
type CoverageEvidence struct {
	Intents   []*Node
	Results   map[int64][]*Node
	Truncated bool
}

func (s *ExplorationStore) CoverageEvidenceWithSources(taskID int64, intentLimit, resultLimit int) (*CoverageEvidence, error) {
	if intentLimit <= 0 {
		intentLimit = 5000
	}
	if resultLimit <= 0 {
		resultLimit = 20000
	}
	rows, err := s.db.Query(`WITH `+directTaskContextCTE+`,
 candidates AS (
 SELECT DISTINCT n.id, n.exploration_id, n.kind, n.state, n.payload, ctx.task_id
 FROM exploration_nodes n JOIN context_tasks ctx ON ctx.exploration_id=n.exploration_id
 WHERE n.kind='intent' ORDER BY n.id DESC LIMIT $2+1
 ), intents AS (SELECT * FROM candidates ORDER BY id DESC LIMIT $2),
 result_candidates AS (
 SELECT DISTINCT result.id, result.kind, result.state, result.payload, i.task_id, i.id AS parent_id
 FROM intents i
 JOIN exploration_edges e ON e.src_id=i.id AND e.exploration_id=i.exploration_id AND e.rel='yields'
 JOIN exploration_nodes result ON result.id=e.dst_id AND result.exploration_id=i.exploration_id
 WHERE result.kind IN ('fact','finding')
 ORDER BY result.id DESC, i.id DESC LIMIT $3+1
 ), nodes AS (
 SELECT id, kind, state, payload, task_id, 0::bigint AS parent_id FROM intents
 UNION ALL
 SELECT * FROM (SELECT * FROM result_candidates ORDER BY id DESC, parent_id DESC LIMIT $3) r
 )
 SELECT n.id,n.kind,n.state,n.payload,n.task_id,n.parent_id,
 to_json(ARRAY(SELECT asset_id FROM exploration_anchors WHERE node_id=n.id ORDER BY asset_id)),
 ((SELECT count(*) FROM candidates)>$2 OR (SELECT count(*) FROM result_candidates)>$3)
 FROM nodes n ORDER BY n.id DESC`, taskID, intentLimit, resultLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &CoverageEvidence{Intents: []*Node{}, Results: map[int64][]*Node{}}
	seen := map[int64]*Node{}
	for rows.Next() {
		n := &Node{}
		var source, parent int64
		var anchors []byte
		var truncated bool
		if err := rows.Scan(&n.ID, &n.Kind, &n.State, &n.Payload, &source, &parent, &anchors, &truncated); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(anchors, &n.Anchors); err != nil {
			return nil, err
		}
		out.Truncated = out.Truncated || truncated
		if source != taskID {
			n.SourceTaskID, n.Inherited = source, true
		}
		if previous := seen[n.ID]; previous != nil {
			n = previous
		} else {
			seen[n.ID] = n
		}
		if parent == 0 {
			out.Intents = append(out.Intents, n)
		} else {
			out.Results[parent] = append(out.Results[parent], n)
		}
	}
	return out, rows.Err()
}

package db

import (
	"context"
	"database/sql"
	"errors"
)

// CommitIntentOutcome is an idempotent completion CAS. A stale receipt cannot
// change an intent claimed by a subsequent execution or deleted by its owner.
func (s *ExplorationStore) CommitIntentOutcome(ctx context.Context, id int64, token, state, reason string) error {
	terminal := state == "done" || state == "blocked" || state == "exhausted" || state == "stopped"
	res, err := s.db.ExecContext(ctx, `UPDATE exploration_nodes SET state=$3,
 blocked_reason=NULLIF($4,''),content_version=content_version+1,
 completed_at=CASE WHEN $6 THEN now() ELSE NULL END
 WHERE exploration_id=$1 AND id=$2 AND kind='intent' AND state='running'
 AND ($5='' OR execution_token=$5)`, s.expID, id, state, reason, token, terminal)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n > 0 {
		return err
	}
	var current, currentToken string
	err = s.db.QueryRowContext(ctx, `SELECT state,execution_token FROM exploration_nodes WHERE exploration_id=$1 AND id=$2 AND kind='intent'`, s.expID, id).Scan(&current, &currentToken)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if current == state && (token == "" || currentToken == token) {
		return nil
	}
	return ErrIntentStateConflict
}

func (s *ExplorationStore) StartIntentExecution(ctx context.Context, id int64, expected, owner, token string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE exploration_nodes SET state='running',owner=$3,
 execution_token=$4,completed_at=NULL WHERE exploration_id=$1 AND id=$2 AND kind='intent' AND state=$5`, s.expID, id, owner, token, expected)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

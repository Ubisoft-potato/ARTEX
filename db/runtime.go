package db

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const QueryTimeout = 30 * time.Second

func BoundedContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, QueryTimeout)
}

func openPostgres(dsn string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if cfg.ConnectTimeout == 0 {
		// 本机建连包含 fork + SCRAM 认证，慢盘/高负载时可能接近秒级。
		// 5s 太紧会把短暂的调度抖动放大成连接超时，留出重试余量。
		cfg.ConnectTimeout = 15 * time.Second
	}
	for key, value := range map[string]string{"statement_timeout": "30000", "lock_timeout": "5000", "idle_in_transaction_session_timeout": "120000"} {
		if cfg.RuntimeParams[key] == "" {
			cfg.RuntimeParams[key] = value
		}
	}
	d := stdlib.OpenDB(*cfg)
	maxOpen := 32
	if n, err := strconv.Atoi(os.Getenv("ARTEX_DB_MAX_OPEN")); err == nil {
		maxOpen = max(4, min(n, 256))
	}
	d.SetMaxOpenConns(maxOpen)
	d.SetMaxIdleConns(min(8, maxOpen))
	// 连接池没有最小连接数，空闲/到期回收后的首次请求需要重新建连。
	// 拉长空闲存活与回收周期，避免低峰后再来一波任务时频繁冷启动。
	d.SetConnMaxIdleTime(30 * time.Minute)
	d.SetConnMaxLifetime(2 * time.Hour)
	return d, nil
}

// Bound both connection-pool acquisition and SQL execution for legacy writes.
func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	ctx, cancel := BoundedContext(context.Background())
	defer cancel()
	return d.DB.ExecContext(ctx, query, args...)
}

func (d *DB) ExecContext(parent context.Context, query string, args ...any) (sql.Result, error) {
	ctx, cancel := BoundedContext(parent)
	defer cancel()
	return d.DB.ExecContext(ctx, query, args...)
}

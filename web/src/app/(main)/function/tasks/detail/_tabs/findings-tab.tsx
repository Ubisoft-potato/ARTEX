"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowDownIcon, ArrowUpIcon, ArrowUpRightIcon, ChevronRightIcon } from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { api } from "@/lib/api";
import { useStoredSortPreference } from "@/lib/sort-preference";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

type FindingSortField = "time";

const FINDING_SORT_FIELDS: readonly FindingSortField[] = ["time"];
const FINDING_SORT_PREFERENCE_KEY = "artex_task_findings_sort";

function findingLabel(finding: Finding): string {
  if (finding.name?.trim()) return finding.name;
  if (finding.vulnclass?.trim()) return finding.vulnclass;
  return "未分类";
}

function findingDetailHref(finding: Finding, contextTaskId: string): string {
  const params = new URLSearchParams({ id: finding.finding_id ?? finding.id });
  // Preserve the task findings tab for the detail page's back link. context_task
  // is still only needed for inherited (read-only) findings.
  params.set("from_task", contextTaskId);
  params.set("from_tab", "findings");
  if (finding.inherited) params.set("context_task", contextTaskId);
  return `/function/findings/detail?${params.toString()}`;
}

const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function Row({
  f,
  contextTaskId,
  onStatus,
}: {
  f: Finding;
  contextTaskId: string;
  onStatus: (f: Finding, next: FindingStatus) => void;
}) {
  const [open, setOpen] = React.useState(false);
  return (
    <div className="min-w-0 border-b last:border-b-0">
      <div className="flex w-full min-w-0 flex-wrap items-center gap-x-3 gap-y-2 px-3 py-3 text-sm hover:bg-accent/40 sm:px-4">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex min-w-0 flex-1 basis-full items-center gap-2 text-left sm:basis-0 sm:gap-3"
        >
          <ChevronRightIcon
            className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
          />
          <StatusBadge domain="severity" value={f.severity} dot />
          <div className="flex min-w-0 flex-1 flex-col gap-1">
            <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <span className="min-w-0 font-medium [overflow-wrap:anywhere]">{findingLabel(f)}</span>
              {f.inherited && f.source_task_id && (
                <Badge variant="outline" className="shrink-0">
                  来源 #{f.source_task_id} · 只读
                </Badge>
              )}
            </div>
            <span className="truncate text-xs text-muted-foreground">{f.summary}</span>
          </div>
        </button>
        <Badge variant="outline" className="shrink-0">
          流量证据 {f.traffic_count ?? 0} 条
        </Badge>
        {f.assets && f.assets.length > 0 && (
          <div className="hidden shrink-0 flex-wrap justify-end gap-1 sm:flex">
            {f.assets.slice(0, 2).map((a) => (
              <code
                key={a.id}
                className="max-w-[10rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                title={`${a.type} · ${a.label}`}
              >
                {a.label}
              </code>
            ))}
            {f.assets.length > 2 && <span className="text-xs text-muted-foreground">+{f.assets.length - 2}</span>}
          </div>
        )}
        {f.finding_id && !f.inherited ? (
          <Select value={f.status} onValueChange={(v) => onStatus(f, v as FindingStatus)}>
            <SelectTrigger size="sm" className="h-7 w-28 shrink-0 border-none px-1 shadow-none focus-visible:ring-0">
              <StatusBadge domain="finding" value={f.status} dot />
            </SelectTrigger>
            <SelectContent position="popper" align="end">
              <SelectGroup>
                {FINDING_STATUSES.map((st) => (
                  <SelectItem key={st} value={st}>
                    {statusMeta("finding", st).label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        ) : (
          <StatusBadge domain="finding" value={f.status} dot />
        )}
        <span className="hidden shrink-0 text-xs text-muted-foreground md:block">
          {new Date(f.ts).toLocaleString("zh-CN")}
        </span>
        {f.finding_id && (
          <Link
            href={findingDetailHref(f, contextTaskId)}
            className="text-muted-foreground hover:text-primary ml-auto inline-flex min-h-8 shrink-0 items-center gap-0.5 text-xs sm:ml-0"
            title="查看漏洞详情"
          >
            详情
            <ArrowUpRightIcon className="size-3" />
          </Link>
        )}
      </div>
      {open && (
        <div className="min-w-0 bg-muted/30 px-3 pb-4 sm:pl-11 sm:pr-4">
          <div className="mb-1 text-xs font-medium text-muted-foreground">证据 / PoC</div>
          <pre className="max-w-full overflow-auto rounded-md border bg-background p-3 font-mono text-xs whitespace-pre-wrap [overflow-wrap:anywhere]">
            {f.evidence}
          </pre>
        </div>
      )}
    </div>
  );
}

export function FindingsTab({ taskId }: { taskId: string }) {
  return <TaskFindings key={taskId} taskId={taskId} />;
}

function TaskFindings({ taskId }: { taskId: string }) {
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState("");
  const [sortPreference, setSortPreference] = useStoredSortPreference(
    FINDING_SORT_PREFERENCE_KEY,
    FINDING_SORT_FIELDS,
    "time",
    "desc",
  );

  React.useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const load = () => {
      api
        .findings(taskId)
        .then((fs) => {
          if (!active) return;
          setFindings(fs);
          setError("");
        })
        .catch((e: Error) => {
          if (active) setError(e.message);
        })
        .finally(() => {
          if (!active) return;
          setLoaded(true);
          timer = setTimeout(load, 3000);
        });
    };
    load();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [taskId]);

  const onStatus = React.useCallback(async (f: Finding, next: FindingStatus) => {
    if (f.inherited || !f.finding_id || next === f.status) return;
    const prev = f.status;
    setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: next } : x)));
    try {
      await api.setFindingStatus(f.finding_id, next);
      toast.success(`已标记为「${statusMeta("finding", next).label}」`);
    } catch (e) {
      setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: prev } : x)));
      toast.error("更新失败：" + (e as Error).message);
    }
  }, []);

  const items = findings
    .filter((f) => f.task_id === taskId || f.inherited)
    .sort((a, b) => {
      const compared = Date.parse(a.ts) - Date.parse(b.ts);
      if (compared !== 0) return sortPreference.direction === "asc" ? compared : -compared;
      return b.id.localeCompare(a.id, undefined, { numeric: true });
    });

  return (
    <Card className="min-w-0 overflow-hidden py-0">
      <CardContent className="min-w-0 px-0">
        <div className="flex items-center border-b px-4 py-2 text-xs text-muted-foreground">
          <span className="min-w-0 flex-1">漏洞</span>
          <button
            type="button"
            className="inline-flex items-center gap-1 outline-none focus-visible:underline"
            aria-label={`发现时间当前${sortPreference.direction === "asc" ? "正序" : "倒序"}，点击切换排序方向`}
            onClick={() =>
              setSortPreference((current) => ({
                field: "time",
                direction: current.direction === "asc" ? "desc" : "asc",
              }))
            }
          >
            <span>发现时间</span>
            {sortPreference.direction === "asc" ? (
              <ArrowUpIcon className="size-3.5" />
            ) : (
              <ArrowDownIcon className="size-3.5" />
            )}
          </button>
        </div>
        {items.map((f) => (
          <Row key={f.id} f={f} contextTaskId={taskId} onStatus={onStatus} />
        ))}
        {!loaded && (
          <p role="status" className="px-4 py-8 text-center text-sm text-muted-foreground">
            加载发现中…
          </p>
        )}
        {error && (
          <p role="alert" className="px-4 py-4 text-sm text-destructive [overflow-wrap:anywhere]">
            加载发现失败：{error}，稍后自动重试。
          </p>
        )}
        {loaded && !error && items.length === 0 && (
          <p className="px-4 py-8 text-center text-sm text-muted-foreground">本任务及直接关联任务暂无确认发现。</p>
        )}
      </CardContent>
    </Card>
  );
}

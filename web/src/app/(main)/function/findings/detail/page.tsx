"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { ArrowLeftIcon, ArrowUpRightIcon, ShieldAlertIcon } from "lucide-react";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { FindingRetestPanel } from "@/components/finding-retest-panel";
import { FindingTrafficPanel } from "@/components/finding-traffic-panel";
import { Markdown } from "@/components/markdown";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingStatus, Severity } from "@/lib/types";

import { FindingLineageView } from "./lineage";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
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

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString("zh-CN");
}

// FieldRow is one label/value line in the right-hand status panel.
function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 items-start justify-between gap-3 py-2.5">
      <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">{label}</span>
      <div className="flex min-w-0 flex-1 flex-col items-end gap-1 text-right text-sm [overflow-wrap:anywhere]">
        {children}
      </div>
    </div>
  );
}

function FindingDetailInner({ id, contextTaskId }: { id: string; contextTaskId: string }) {
  const searchParams = useSearchParams();
  const fromTaskId = searchParams.get("from_task") ?? contextTaskId;
  const fromTab = searchParams.get("from_tab") === "retests" ? "retests" : "findings";
  const backHref = fromTaskId
    ? `/function/tasks/detail?id=${encodeURIComponent(fromTaskId)}&tab=${fromTab}`
    : "/function/findings";
  let backLabel = "返回发现列表";
  if (fromTaskId) backLabel = fromTab === "retests" ? "返回任务复测" : "返回任务发现";
  const [finding, setFinding] = React.useState<Finding | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [tab, setTab] = React.useState("overview");
  const loadRequest = React.useRef<symbol | null>(null);

  const load = React.useCallback(() => {
    if (!id) {
      setLoaded(true);
      return;
    }
    const request = Symbol();
    loadRequest.current = request;
    api
      .getFinding(id, contextTaskId || undefined)
      .then((f) => {
        if (loadRequest.current === request) setFinding(f);
      })
      .catch(() => {
        if (loadRequest.current === request) setFinding(null);
      })
      .finally(() => {
        if (loadRequest.current === request) setLoaded(true);
      });
  }, [contextTaskId, id]);
  React.useEffect(() => {
    load();
    return () => {
      loadRequest.current = null;
    };
  }, [load]);

  const changeSeverity = React.useCallback(
    async (next: Severity) => {
      if (!finding || finding.inherited || next === finding.severity) return;
      const prev = finding.severity;
      setFinding({ ...finding, severity: next });
      try {
        const updated = await api.setFindingSeverity(id, next);
        setFinding(updated);
        toast.success(`严重等级已改为「${statusMeta("severity", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, severity: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  const changeStatus = React.useCallback(
    async (next: FindingStatus) => {
      if (!finding || finding.inherited || next === finding.status) return;
      const prev = finding.status;
      setFinding({ ...finding, status: next });
      try {
        const updated = await api.setFindingStatus(id, next);
        setFinding(updated);
        toast.success(`处理状态已改为「${statusMeta("finding", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, status: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  if (!finding) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        <p className="text-muted-foreground">{loaded ? `未找到发现 ${id}` : "加载中…"}</p>
        {loaded && (
          <Button asChild variant="outline">
            <Link href={backHref}>
              <ArrowLeftIcon /> {backLabel}
            </Link>
          </Button>
        )}
      </div>
    );
  }

  const title = finding.name || finding.vulnclass || "未分类";

  return (
    <Tabs value={tab} onValueChange={setTab} className="flex w-full min-w-0 flex-1 flex-col gap-0">
      {/* Sticky header */}
      <header className="sticky top-0 z-10 flex flex-col gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur lg:px-6">
        <div className="flex min-w-0 items-start gap-2">
          <SidebarTrigger className="-ml-1 shrink-0" />
          <Button asChild variant="ghost" size="icon" className="size-7 shrink-0">
            <Link href={backHref} title={backLabel} aria-label={backLabel}>
              <ArrowLeftIcon />
            </Link>
          </Button>
          <ShieldAlertIcon className="mt-1.5 hidden size-4 shrink-0 text-muted-foreground sm:block" />
          <h1 className="min-w-0 flex-1 pt-1 text-sm font-semibold [overflow-wrap:anywhere]" title={title}>
            {title}
          </h1>
          <code className="mt-1 shrink-0 rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
            #{finding.id}
          </code>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge domain="severity" value={finding.severity} dot />
          <StatusBadge domain="finding" value={finding.status} dot />
          {finding.inherited && finding.source_task_id && (
            <Badge variant="outline">来源任务 #{finding.source_task_id} · 只读</Badge>
          )}
        </div>
        <TabsList>
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="lineage">链路图</TabsTrigger>
        </TabsList>
      </header>

      {/* Tab content */}
      <div className="min-w-0 flex-1 p-3 sm:p-4 lg:p-6">
        {/* 概览：左（摘要 + 证据）/ 右（状态区） */}
        <TabsContent value="overview" className="mt-0 min-w-0">
          <div className="grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-3">
            {/* 左栏 */}
            <div className="flex min-w-0 flex-col gap-4 lg:col-span-2">
              <Card className="min-w-0">
                <CardHeader>
                  <CardTitle className="text-sm">摘要</CardTitle>
                </CardHeader>
                <CardContent className="min-w-0">
                  <p className="text-sm leading-relaxed whitespace-pre-wrap [overflow-wrap:anywhere]">
                    {finding.summary || "（无摘要）"}
                  </p>
                </CardContent>
              </Card>
              <FindingRetestPanel key={id} findingId={id} readOnly={finding.inherited} onCompleted={load} />
              <Card className="min-w-0">
                <CardHeader>
                  <CardTitle className="text-sm">证据 / PoC</CardTitle>
                </CardHeader>
                <CardContent className="min-w-0">
                  {finding.evidence ? (
                    <pre className="max-h-[46dvh] max-w-full overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap [overflow-wrap:anywhere]">
                      {finding.evidence}
                    </pre>
                  ) : (
                    <p className="text-sm text-muted-foreground">（无证据）</p>
                  )}
                </CardContent>
              </Card>
              <FindingTrafficPanel
                key={id}
                findingId={id}
                contextTask={contextTaskId || undefined}
                readOnly={finding.inherited}
                onChanged={load}
              />
              {/* 证据下方：详细报告(Markdown 渲染) */}
              <Card className="min-w-0">
                <CardHeader className="flex flex-row items-center justify-between gap-2">
                  <CardTitle className="text-sm">详细报告</CardTitle>
                  {finding.report && <CopyButton text={finding.report} successMessage="已复制详细报告" />}
                </CardHeader>
                <CardContent className="min-w-0">
                  {finding.report_stale ? (
                    <Alert>
                      <AlertDescription>流量证据已变更，详细报告待更新。</AlertDescription>
                    </Alert>
                  ) : null}
                  {finding.report ? (
                    <Markdown text={finding.report} />
                  ) : (
                    <p className="text-sm text-muted-foreground">暂无详细报告。</p>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* 右栏：状态区 */}
            <Card className="h-fit min-w-0 lg:sticky lg:top-24">
              <CardHeader>
                <CardTitle className="text-sm">状态</CardTitle>
              </CardHeader>
              <CardContent className="min-w-0 divide-y">
                {/* 漏洞 ID */}
                <FieldRow label="漏洞 ID">
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                    #{finding.id}
                  </code>
                </FieldRow>

                {/* 严重等级 */}
                <FieldRow label="严重等级">
                  {finding.inherited ? (
                    <StatusBadge domain="severity" value={finding.severity} dot />
                  ) : (
                    <Select value={finding.severity} onValueChange={(v) => changeSeverity(v as Severity)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="severity" value={finding.severity} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {SEVERITIES.map((sv) => (
                            <SelectItem key={sv} value={sv}>
                              {statusMeta("severity", sv).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </FieldRow>

                {/* 处理状态 */}
                <FieldRow label="处理状态">
                  {finding.inherited ? (
                    <StatusBadge domain="finding" value={finding.status} dot />
                  ) : (
                    <Select value={finding.status} onValueChange={(v) => changeStatus(v as FindingStatus)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="finding" value={finding.status} dot />
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
                  )}
                </FieldRow>

                {/* 漏洞类型 */}
                <FieldRow label="漏洞类型">
                  {finding.vulnclass ? (
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{finding.vulnclass}</code>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 涉及资产 */}
                <FieldRow label="涉及资产">
                  {finding.assets && finding.assets.length > 0 ? (
                    <div className="flex min-w-0 max-w-full flex-wrap justify-end gap-1">
                      {finding.assets.map((a) => (
                        <code
                          key={a.id}
                          className="max-w-full rounded bg-muted px-1.5 py-0.5 font-mono text-xs [overflow-wrap:anywhere]"
                          title={`${a.type} · ${a.label}`}
                        >
                          {a.label}
                        </code>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 所属任务 */}
                <FieldRow label="所属任务">
                  {finding.task_id ? (
                    <Link
                      href={`/function/tasks/detail?id=${encodeURIComponent(finding.task_id)}&tab=findings`}
                      className="inline-flex min-w-0 max-w-full items-start justify-end gap-1 text-primary hover:underline"
                      title={finding.task_description}
                    >
                      <span className="min-w-0 [overflow-wrap:anywhere]">
                        {finding.task_description || `#${finding.task_id}`}
                      </span>
                      <ArrowUpRightIcon className="mt-1 size-3 shrink-0" />
                    </Link>
                  ) : (
                    <span className="text-muted-foreground">—（任务已删除）</span>
                  )}
                </FieldRow>

                {/* 发现时间 */}
                <FieldRow label="发现时间">
                  <span className="tabular-nums">{fmtTime(finding.ts)}</span>
                </FieldRow>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 链路图：从任务初始节点回溯到本漏洞节点的攻击链路 */}
        <TabsContent value="lineage" className="mt-0 min-w-0">
          <FindingLineageView findingId={finding.id} />
        </TabsContent>
      </div>
    </Tabs>
  );
}

function FindingDetailRoute() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const contextTaskId = searchParams.get("context_task") ?? "";
  return <FindingDetailInner key={`${id}:${contextTaskId}`} id={id} contextTaskId={contextTaskId} />;
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <FindingDetailRoute />
    </React.Suspense>
  );
}

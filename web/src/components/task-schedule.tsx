"use client";

import * as React from "react";

import { toast } from "sonner";
import { Temporal } from "temporal-polyfill";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";

export interface ScheduleEvent {
  at: string;
  state: string;
  result?: string;
}
export interface TaskSchedule {
  revision: number;
  timezone: string;
  start?: ScheduleEvent;
  stop?: ScheduleEvent;
}
export interface ScheduleDraft {
  timezone: string;
  start: string;
  stop: string;
  disambiguation: "reject" | "earlier" | "later";
}
export const emptyScheduleDraft = (): ScheduleDraft => ({
  timezone: "Asia/Shanghai",
  start: "",
  stop: "",
  disambiguation: "reject",
});
export function encodeSchedule(draft: ScheduleDraft, revision = 0): TaskSchedule {
  const event = (local: string): ScheduleEvent | undefined => {
    if (!local) return undefined;
    const plain = Temporal.PlainDateTime.from(local);
    const zoned = plain.toZonedDateTime(draft.timezone, { disambiguation: draft.disambiguation });
    if (!plain.equals(zoned.toPlainDateTime())) throw new Error("所选时间因夏令时切换而不存在，请重新选择");
    return { at: zoned.toInstant().toString(), state: "pending" };
  };
  try {
    return { revision, timezone: draft.timezone, start: event(draft.start), stop: event(draft.stop) };
  } catch (error) {
    throw new Error(error instanceof Error ? `时间无效或存在夏令时歧义：${error.message}` : "时间无效");
  }
}
export function ScheduleFields({ value, onChange }: { value: ScheduleDraft; onChange: (v: ScheduleDraft) => void }) {
  const fieldID = React.useId();
  const zones = React.useMemo(
    () => Array.from(new Set(["Asia/Shanghai", "UTC", ...Intl.supportedValuesOf("timeZone")])),
    [],
  );
  const update = (key: keyof ScheduleDraft, next: string) => onChange({ ...value, [key]: next });
  function changeZone(zone: string) {
    try {
      const encoded = encodeSchedule(value);
      const local = (e?: ScheduleEvent) =>
        e
          ? Temporal.Instant.from(e.at).toZonedDateTimeISO(zone).toPlainDateTime().toString({ smallestUnit: "minute" })
          : "";
      onChange({ ...value, timezone: zone, start: local(encoded.start), stop: local(encoded.stop) });
    } catch {
      toast.error("请先解决当前时间的夏令时歧义，再切换时区");
    }
  }
  let preview = "";
  try {
    const v = encodeSchedule(value);
    preview = [
      v.start ? `启动：${Temporal.Instant.from(v.start.at).toZonedDateTimeISO(value.timezone).toString()}` : "",
      v.stop ? `停止：${Temporal.Instant.from(v.stop.at).toZonedDateTimeISO(value.timezone).toString()}` : "",
    ]
      .filter(Boolean)
      .join("；");
  } catch {
    preview = "时间无效或存在夏令时歧义，请调整时间或选择偏移。";
  }
  return (
    <div className="grid gap-3 rounded border p-3 text-sm">
      <p className="font-medium">单次定时启停（可分别设置）</p>
      <label className="grid gap-1">
        时区
        <select
          className="h-9 rounded border bg-background px-2"
          value={value.timezone}
          onChange={(e) => changeZone(e.target.value)}
        >
          {zones.map((zone) => (
            <option key={zone}>{zone}</option>
          ))}
        </select>
      </label>
      <label htmlFor={`${fieldID}-start`} className="grid gap-1">
        启动时间
        <Input
          id={`${fieldID}-start`}
          type="datetime-local"
          value={value.start}
          onChange={(e) => update("start", e.target.value)}
        />
      </label>
      <label htmlFor={`${fieldID}-stop`} className="grid gap-1">
        停止时间（暂停并保留进度）
        <Input
          id={`${fieldID}-stop`}
          type="datetime-local"
          value={value.stop}
          onChange={(e) => update("stop", e.target.value)}
        />
      </label>
      <label className="grid gap-1">
        夏令时重复时间
        <select
          className="h-9 rounded border bg-background px-2"
          value={value.disambiguation}
          onChange={(e) => update("disambiguation", e.target.value)}
        >
          <option value="reject">需要明确选择</option>
          <option value="earlier">使用较早的 UTC 偏移</option>
          <option value="later">使用较晚的 UTC 偏移</option>
        </select>
      </label>
      {preview && <p className="break-all text-xs text-muted-foreground">{preview}</p>}
      <p className="text-xs text-muted-foreground">
        手动启停会取消待执行预约。启动遵循并发限制，可能排队；暂停期间仍计入任务超时。错过的启动不补跑，停止补执行。
      </p>
    </div>
  );
}
const labels: Record<string, string> = {
  pending: "待执行",
  executed: "已执行",
  expired: "已过期",
  cancelled: "已取消",
  skipped: "已跳过",
};
export function TaskScheduleControl({ id, onUpdated }: { id: string; onUpdated: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [draft, setDraft] = React.useState(emptyScheduleDraft);
  const [saved, setSaved] = React.useState<TaskSchedule>();
  const [busy, setBusy] = React.useState(false);
  async function load() {
    setSaved(undefined);
    setBusy(true);
    try {
      const v = await api.taskSchedule(id);
      setSaved(v);
      const local = (e?: ScheduleEvent) =>
        e?.state === "pending"
          ? Temporal.Instant.from(e.at)
              .toZonedDateTimeISO(v.timezone)
              .toPlainDateTime()
              .toString({ smallestUnit: "minute" })
          : "";
      setDraft({ timezone: v.timezone, start: local(v.start), stop: local(v.stop), disambiguation: "reject" });
    } catch (e) {
      toast.error(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function save(cancel: boolean) {
    if (!saved) return;
    setBusy(true);
    try {
      await (cancel
        ? api.cancelTaskSchedule(id, saved.revision)
        : api.saveTaskSchedule(id, encodeSchedule(draft, saved.revision)));
      toast.success(cancel ? "预约已取消" : "预约已保存");
      setOpen(false);
      onUpdated();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (next) void load();
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          定时启停
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>任务定时启停</DialogTitle>
        </DialogHeader>
        <ScheduleFields value={draft} onChange={setDraft} />
        {saved &&
          [saved.start, saved.stop].map(
            (e, i) =>
              e && (
                <p key={i === 0 ? "start" : "stop"} className="text-xs">
                  {i === 0 ? "启动" : "停止"}：
                  {Temporal.Instant.from(e.at).toZonedDateTimeISO(saved.timezone).toString()} ·{" "}
                  {labels[e.state] ?? e.state} {e.result}
                </p>
              ),
          )}
        <div className="flex justify-end gap-2">
          <Button variant="outline" disabled={busy || !saved} onClick={() => void save(true)}>
            取消预约
          </Button>
          <Button disabled={busy || !saved} onClick={() => void save(false)}>
            保存预约
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

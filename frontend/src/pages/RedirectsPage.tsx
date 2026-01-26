import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { groupRedirectSchedulesApi, printerGroupsApi, printerRedirectSchedulesApi, redirectsApi, printersApi } from '@/lib/api';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  ArrowRight,
  Loader2,
  Trash2,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/use-document-title';
import type { ActiveRedirect, PrinterStatus } from '@/types/api';

export function RedirectsPage() {
  useDocumentTitle('Redirects');
  const queryClient = useQueryClient();
  const [showAddForm, setShowAddForm] = useState(false);
  const [showScheduleForm, setShowScheduleForm] = useState(false);
  const [sourceId, setSourceId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [sourceGroupFilter, setSourceGroupFilter] = useState('all');
  const [targetGroupFilter, setTargetGroupFilter] = useState('all');
  const [error, setError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [scheduleScope, setScheduleScope] = useState<'printer' | 'group'>('printer');
  const [scheduleSourceId, setScheduleSourceId] = useState('');
  const [scheduleGroupId, setScheduleGroupId] = useState('');
  const [scheduleTargetId, setScheduleTargetId] = useState('');
  const [scheduleStartAt, setScheduleStartAt] = useState('');
  const [scheduleEndAt, setScheduleEndAt] = useState('');
  const [scheduleError, setScheduleError] = useState('');

  const { data: redirects, isLoading } = useQuery<ActiveRedirect[]>({
    queryKey: ['redirects'],
    queryFn: redirectsApi.getAll,
  });

  const { data: printers } = useQuery<PrinterStatus[]>({
    queryKey: ['printers'],
    queryFn: printersApi.getAll,
  });

  const { data: groupsData } = useQuery({
    queryKey: ['printer-groups'],
    queryFn: printerGroupsApi.getAll,
  });

  const { data: groupSchedulesData } = useQuery<{ schedules: any[] }>({
    queryKey: ['group-redirect-schedules'],
    queryFn: () => groupRedirectSchedulesApi.getAll(),
  });

  const { data: printerSchedulesData } = useQuery<{ schedules: any[] }>({
    queryKey: ['printer-redirect-schedules'],
    queryFn: () => printerRedirectSchedulesApi.getAll(),
  });

  const createMutation = useMutation({
    mutationFn: () => redirectsApi.create({ source_printer_id: sourceId, target_printer_id: targetId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['redirects'] });
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setShowAddForm(false);
      setSourceId('');
      setTargetId('');
      setError('');
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setError(axiosError.response?.data?.error || 'Failed to create redirect');
      }
    },
  });

  const createScheduleMutation = useMutation({
    mutationFn: () => {
      if (scheduleScope === 'group') {
        return groupRedirectSchedulesApi.create({
          group_id: Number(scheduleGroupId),
          target_printer_id: scheduleTargetId,
          start_at: new Date(scheduleStartAt).toISOString(),
          end_at: scheduleEndAt ? new Date(scheduleEndAt).toISOString() : null,
        });
      }
      return printerRedirectSchedulesApi.create({
        source_printer_id: scheduleSourceId,
        target_printer_id: scheduleTargetId,
        start_at: new Date(scheduleStartAt).toISOString(),
        end_at: scheduleEndAt ? new Date(scheduleEndAt).toISOString() : null,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['group-redirect-schedules'] });
      queryClient.invalidateQueries({ queryKey: ['printer-redirect-schedules'] });
      setShowScheduleForm(false);
      setScheduleSourceId('');
      setScheduleGroupId('');
      setScheduleTargetId('');
      setScheduleStartAt('');
      setScheduleEndAt('');
      setScheduleError('');
    },
    onError: () => {
      setScheduleError('Failed to create schedule');
    },
  });

  const deleteScheduleMutation = useMutation({
    mutationFn: ({ id, type }: { id: number; type: 'group' | 'printer' }) => {
      if (type === 'group') {
        return groupRedirectSchedulesApi.delete(id);
      }
      return printerRedirectSchedulesApi.delete(id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['group-redirect-schedules'] });
      queryClient.invalidateQueries({ queryKey: ['printer-redirect-schedules'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: redirectsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['redirects'] });
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setDeleteError('');
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setDeleteError(axiosError.response?.data?.error || 'Failed to remove redirect');
      } else {
        setDeleteError('Failed to remove redirect');
      }
    },
  });

  const handleDelete = (id: number) => {
    if (confirm('Are you sure you want to remove this redirect?')) {
      deleteMutation.mutate(id);
    }
  };

  const getPrinterName = (printerId: string) => {
    const printer = printers?.find((p) => p.printer.id === printerId);
    return printer?.printer.name || printerId;
  };

  const getPrinterGroupName = (printerId: string) => {
    const printer = printers?.find((p) => p.printer.id === printerId);
    return printer?.group?.name || '';
  };

  const getPrinterLabel = (printer: PrinterStatus) => {
    const groupName = printer.group?.name ? ` • ${printer.group.name}` : '';
    return `${printer.printer.name} (${printer.printer.ip})${groupName}`;
  };

  const groupOptions = (groupsData?.groups && groupsData.groups.length > 0)
    ? groupsData.groups.map((group: { id: number; name: string }) => ({ id: group.id, name: group.name }))
    : Array.from(
      (printers ?? []).reduce((acc, printer) => {
        if (printer.group?.id && printer.group?.name) {
          acc.set(printer.group.id, printer.group.name);
        }
        return acc;
      }, new Map<number, string>())
    ).map(([id, name]) => ({ id, name }));

  const passesGroupFilter = (printer: PrinterStatus, filter: string) => {
    if (filter === 'all') return true;
    if (filter === 'ungrouped') return !printer.group?.id;
    return printer.group?.id?.toString() === filter;
  };

  // Available sources: printers that don't already have a redirect
  const availableSources = printers?.filter(
    (p) => !p.has_redirect && !p.is_target
  );

  // Available targets: online printers that aren't already sources or targets
  const availableTargets = printers?.filter(
    (p) => p.is_online && !p.has_redirect && !p.is_target && p.printer.id !== sourceId
  );

  const filteredSources = availableSources?.filter((printer) => passesGroupFilter(printer, sourceGroupFilter));
  const filteredTargets = availableTargets?.filter((printer) => passesGroupFilter(printer, targetGroupFilter));

  const groupSchedules = groupSchedulesData?.schedules ?? [];
  const printerSchedules = printerSchedulesData?.schedules ?? [];
  const scheduledRedirects = [
    ...groupSchedules.map((schedule) => ({
      id: `group-${schedule.id}`,
      type: 'Group',
      scheduleType: 'group' as const,
      scheduleId: schedule.id as number,
      sourceLabel: schedule.group_name || `Group #${schedule.group_id}`,
      sourceId: schedule.group_id,
      targetLabel: schedule.target_printer_name || schedule.target_printer_id,
      startAt: schedule.start_at,
      endAt: schedule.end_at,
      enabled: schedule.enabled,
      isActive: schedule.is_active,
    })),
    ...printerSchedules.map((schedule) => ({
      id: `printer-${schedule.id}`,
      type: 'Printer',
      scheduleType: 'printer' as const,
      scheduleId: schedule.id as number,
      sourceLabel: schedule.source_printer_name || schedule.source_printer_id,
      sourceId: schedule.source_printer_id,
      targetLabel: schedule.target_printer_name || schedule.target_printer_id,
      startAt: schedule.start_at,
      endAt: schedule.end_at,
      enabled: schedule.enabled,
      isActive: schedule.is_active,
    })),
  ];

  useEffect(() => {
    if (!sourceId || !filteredSources) return;
    if (!filteredSources.some((printer) => printer.printer.id === sourceId)) {
      setSourceId('');
    }
  }, [sourceId, filteredSources]);

  useEffect(() => {
    if (!targetId || !filteredTargets) return;
    if (!filteredTargets.some((printer) => printer.printer.id === targetId)) {
      setTargetId('');
    }
  }, [targetId, filteredTargets]);

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">Redirects</h1>
          <p className="text-muted-foreground">Manage print traffic redirects</p>
        </div>
        {(redirects && redirects.length > 0) || scheduledRedirects.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => setShowScheduleForm(true)}>
              Schedule Redirect
            </Button>
            <Button onClick={() => setShowAddForm(true)}>
              New Redirect
            </Button>
          </div>
        ) : null}
      </div>

      {deleteError && (
        <div className="rounded-lg bg-error-bg p-3 text-sm text-error">
          {deleteError}
        </div>
      )}

      <Dialog open={showAddForm} onOpenChange={setShowAddForm}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>Create Redirect</DialogTitle>
            <DialogDescription>Route print traffic from one printer to another.</DialogDescription>
          </DialogHeader>
          <div className="space-y-6">
            {error && (
              <div className="rounded-lg bg-error-bg p-3 text-sm text-error">{error}</div>
            )}
            <div className="grid gap-6 lg:grid-cols-2">
              <div className="space-y-4 rounded-lg border border-border bg-background px-4 py-4">
                <div>
                  <p className="text-sm font-semibold">Source</p>
                  <p className="text-xs text-muted-foreground">Select the printer to redirect from.</p>
                </div>
                <div className="space-y-2">
                  <Label>Filter by group</Label>
                  <select
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                    value={sourceGroupFilter}
                    onChange={(e) => setSourceGroupFilter(e.target.value)}
                  >
                    <option value="all">All groups</option>
                    <option value="ungrouped">Ungrouped</option>
                    {groupOptions.map((group) => (
                      <option key={group.id} value={group.id.toString()}>
                        {group.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="space-y-2">
                  <Label>Source printer</Label>
                  <select
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                    value={sourceId}
                    onChange={(e) => setSourceId(e.target.value)}
                  >
                    <option value="">Select source printer...</option>
                    {filteredSources?.map((p) => (
                      <option key={p.printer.id} value={p.printer.id}>
                        {getPrinterLabel(p)}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="space-y-4 rounded-lg border border-border bg-background px-4 py-4">
                <div>
                  <p className="text-sm font-semibold">Target</p>
                  <p className="text-xs text-muted-foreground">Select the printer to route traffic to.</p>
                </div>
                <div className="space-y-2">
                  <Label>Filter by group</Label>
                  <select
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                    value={targetGroupFilter}
                    onChange={(e) => setTargetGroupFilter(e.target.value)}
                  >
                    <option value="all">All groups</option>
                    <option value="ungrouped">Ungrouped</option>
                    {groupOptions.map((group) => (
                      <option key={group.id} value={group.id.toString()}>
                        {group.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="space-y-2">
                  <Label>Target printer</Label>
                  <select
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                    value={targetId}
                    onChange={(e) => setTargetId(e.target.value)}
                    disabled={!sourceId}
                  >
                    <option value="">Select target printer...</option>
                    {filteredTargets?.map((p) => (
                      <option key={p.printer.id} value={p.printer.id}>
                        {getPrinterLabel(p)}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
            <div className="rounded-lg border border-border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
              Redirect will forward traffic from the source printer to the target printer until removed.
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowAddForm(false); setError(''); }}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate()}
              disabled={!sourceId || !targetId || createMutation.isPending}
            >
              {createMutation.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              )}
              Create Redirect
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showScheduleForm} onOpenChange={setShowScheduleForm}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>Schedule Redirect</DialogTitle>
            <DialogDescription>Plan redirects for a specific printer or an entire group.</DialogDescription>
          </DialogHeader>
          <div className="space-y-6">
            {scheduleError && (
              <div className="rounded-lg bg-error-bg p-3 text-sm text-error">{scheduleError}</div>
            )}
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant={scheduleScope === 'printer' ? 'default' : 'outline'}
                onClick={() => setScheduleScope('printer')}
              >
                Schedule for Printer
              </Button>
              <Button
                type="button"
                variant={scheduleScope === 'group' ? 'default' : 'outline'}
                onClick={() => setScheduleScope('group')}
              >
                Schedule for Group
              </Button>
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <div className="space-y-4 rounded-lg border border-border bg-background px-4 py-4">
                <div>
                  <p className="text-sm font-semibold">Source</p>
                  <p className="text-xs text-muted-foreground">
                    {scheduleScope === 'group'
                      ? 'Choose which group should redirect.'
                      : 'Choose the source printer to redirect.'}
                  </p>
                </div>
                {scheduleScope === 'group' ? (
                  <div className="space-y-2">
                    <Label>Printer group</Label>
                    <select
                      className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                      value={scheduleGroupId}
                      onChange={(e) => setScheduleGroupId(e.target.value)}
                    >
                      <option value="">Select group...</option>
                      {groupOptions.map((group) => (
                        <option key={group.id} value={group.id.toString()}>
                          {group.name}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Label>Source printer</Label>
                    <select
                      className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                      value={scheduleSourceId}
                      onChange={(e) => setScheduleSourceId(e.target.value)}
                    >
                      <option value="">Select source printer...</option>
                      {(printers || []).map((printerStatus) => (
                        <option key={printerStatus.printer.id} value={printerStatus.printer.id}>
                          {printerStatus.printer.name} ({printerStatus.printer.ip})
                        </option>
                      ))}
                    </select>
                  </div>
                )}
              </div>
              <div className="space-y-4 rounded-lg border border-border bg-background px-4 py-4">
                <div>
                  <p className="text-sm font-semibold">Target</p>
                  <p className="text-xs text-muted-foreground">Choose where traffic should go.</p>
                </div>
                <div className="space-y-2">
                  <Label>Target printer</Label>
                  <select
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                    value={scheduleTargetId}
                    onChange={(e) => setScheduleTargetId(e.target.value)}
                  >
                    <option value="">Select target printer...</option>
                    {(printers || []).map((printerStatus) => (
                      <option key={printerStatus.printer.id} value={printerStatus.printer.id}>
                        {printerStatus.printer.name} ({printerStatus.printer.ip})
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>Start time</Label>
                <Input type="datetime-local" value={scheduleStartAt} onChange={(e) => setScheduleStartAt(e.target.value)} />
              </div>
              <div className="space-y-2">
                <Label>End time (optional)</Label>
                <Input type="datetime-local" value={scheduleEndAt} onChange={(e) => setScheduleEndAt(e.target.value)} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowScheduleForm(false);
                setScheduleSourceId('');
                setScheduleGroupId('');
                setScheduleTargetId('');
                setScheduleStartAt('');
                setScheduleEndAt('');
                setScheduleError('');
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={() => createScheduleMutation.mutate()}
              disabled={
                !scheduleTargetId ||
                !scheduleStartAt ||
                (scheduleScope === 'group' ? !scheduleGroupId : !scheduleSourceId) ||
                createScheduleMutation.isPending
              }
            >
              {createScheduleMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create Schedule
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Redirects list */}
      {redirects && redirects.length > 0 ? (
        <Card className="gap-0 py-0">
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="px-4">Source</TableHead>
                  <TableHead className="px-4">Target</TableHead>
                  <TableHead className="px-4">Path</TableHead>
                  <TableHead className="px-4">Enabled By</TableHead>
                  <TableHead className="px-4">Date</TableHead>
                  <TableHead className="px-4 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {redirects.map((redirect) => (
                  <TableRow key={redirect.id}>
                    <TableCell className="px-4">
                      <div className="font-medium">{getPrinterName(redirect.source_printer_id)}</div>
                      {getPrinterGroupName(redirect.source_printer_id) && (
                        <div className="text-xs text-muted-foreground">
                          {getPrinterGroupName(redirect.source_printer_id)}
                        </div>
                      )}
                      <div className="text-xs text-muted-foreground font-mono">{redirect.source_ip}</div>
                    </TableCell>
                    <TableCell className="px-4">
                      <div className="font-medium">{getPrinterName(redirect.target_printer_id)}</div>
                      {getPrinterGroupName(redirect.target_printer_id) && (
                        <div className="text-xs text-muted-foreground">
                          {getPrinterGroupName(redirect.target_printer_id)}
                        </div>
                      )}
                      <div className="text-xs text-muted-foreground font-mono">{redirect.target_ip}</div>
                    </TableCell>
                    <TableCell className="px-4">
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <ArrowRight className="h-4 w-4" />
                        <span>{redirect.protocol.toUpperCase()}:{redirect.port}</span>
                      </div>
                    </TableCell>
                    <TableCell className="px-4 text-sm text-muted-foreground">
                      {redirect.enabled_by}
                    </TableCell>
                    <TableCell className="px-4 text-sm text-muted-foreground">
                      {new Date(redirect.enabled_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="px-4 text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleDelete(redirect.id)}
                        disabled={deleteMutation.isPending}
                        aria-label="Remove redirect"
                        className="delete-action"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : scheduledRedirects.length > 0 ? (
        <Card className="gap-0 py-0">
          <CardContent className="p-0">
            <div className="border-b border-border px-4 py-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-semibold">Scheduled Redirects</h3>
                  <p className="text-sm text-muted-foreground">Overview of group and printer schedules.</p>
                </div>
              </div>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="px-4">Type</TableHead>
                  <TableHead className="px-4">Source</TableHead>
                  <TableHead className="px-4">Target</TableHead>
                  <TableHead className="px-4">Window</TableHead>
                  <TableHead className="px-4">Status</TableHead>
                  <TableHead className="px-4 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scheduledRedirects.map((schedule) => (
                  <TableRow key={schedule.id}>
                    <TableCell className="px-4 text-sm font-medium">{schedule.type}</TableCell>
                    <TableCell className="px-4 text-sm">
                      {schedule.type === 'Printer' ? (
                        <Link to={`/printers/${schedule.sourceId}`} className="text-primary hover:underline">
                          {schedule.sourceLabel}
                        </Link>
                      ) : (
                        <span>{schedule.sourceLabel}</span>
                      )}
                    </TableCell>
                    <TableCell className="px-4 text-sm">
                      {schedule.targetLabel}
                    </TableCell>
                    <TableCell className="px-4 text-sm text-muted-foreground">
                      {new Date(schedule.startAt).toLocaleString()}
                      {schedule.endAt ? ` → ${new Date(schedule.endAt).toLocaleString()}` : ''}
                    </TableCell>
                    <TableCell className="px-4 text-sm text-muted-foreground">
                      {schedule.enabled ? (schedule.isActive ? 'Active' : 'Scheduled') : 'Paused'}
                    </TableCell>
                    <TableCell className="px-4 text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => {
                          if (confirm('Delete this schedule?')) {
                            deleteScheduleMutation.mutate({ id: schedule.scheduleId, type: schedule.scheduleType });
                          }
                        }}
                        disabled={deleteScheduleMutation.isPending}
                        aria-label="Delete schedule"
                        className="delete-action"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : (
        <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
          <div className="relative">
            <div className="absolute inset-0 -z-10 h-48 w-48 rounded-full bg-primary/5 blur-2xl" />
            <svg
              className="h-40 w-40 text-primary"
              viewBox="0 0 200 200"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <circle cx="60" cy="100" r="28" className="fill-primary/15" />
              <circle cx="140" cy="100" r="28" className="fill-primary/15" />
              <path d="M75 100h50" className="stroke-primary/30" strokeWidth="8" strokeLinecap="round" />
              <path d="M108 90l12 10-12 10" className="stroke-primary/40" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <h3 className="mt-6 text-2xl font-semibold">Redirects are standing by</h3>
          <p className="mt-3 max-w-xl text-sm text-muted-foreground">
            Create a redirect to keep printing online when a printer goes down.
          </p>
          <div className="mt-6">
            <div className="flex flex-wrap items-center justify-center gap-3">
              <Button variant="outline" onClick={() => setShowScheduleForm(true)}>
                Schedule Redirect
              </Button>
              <Button onClick={() => setShowAddForm(true)}>
                New Redirect
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

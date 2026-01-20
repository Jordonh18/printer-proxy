import { useMemo, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { printersApi } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { StatusBadge } from '@/components/printers/StatusBadge';
import { Loader2, Pencil, Trash2, RefreshCw, ExternalLink } from 'lucide-react';
import type { PrinterStatus } from '@/types/api';

export function PrinterDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canEdit = user?.role === 'admin' || user?.role === 'operator';

  const [showAudit, setShowAudit] = useState(false);
  const [showTimeline, setShowTimeline] = useState(false);

  const { data: printerStatus, isLoading } = useQuery<PrinterStatus>({
    queryKey: ['printer', id],
    queryFn: () => printersApi.getById(id!),
    refetchInterval: 10000,
  });

  const { data: statsData } = useQuery({
    queryKey: ['printer', id, 'stats'],
    queryFn: () => printersApi.getStats(id!),
  });

  const { data: healthData } = useQuery({
    queryKey: ['printer', id, 'health'],
    queryFn: () => printersApi.getHealth(id!),
  });

  const { data: auditData } = useQuery({
    queryKey: ['printer', id, 'audit'],
    queryFn: () => printersApi.getAudit(id!),
  });

  const refreshMutation = useMutation({
    mutationFn: () => printersApi.refresh(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printer', id] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => printersApi.delete(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      navigate('/printers');
    },
  });

  const handleDelete = () => {
    if (confirm(`Are you sure you want to delete "${printerStatus?.printer.name}"?`)) {
      deleteMutation.mutate();
    }
  };

  const tonerLevels = useMemo(() => {
    const toner = statsData?.toner || {};
    return [
      { label: 'Black', value: toner.black },
      { label: 'Cyan', value: toner.cyan },
      { label: 'Magenta', value: toner.magenta },
      { label: 'Yellow', value: toner.yellow },
    ].filter((item) => typeof item.value === 'number');
  }, [statsData]);

  if (isLoading || !printerStatus) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  const { printer } = printerStatus;
  const status = printerStatus.status ?? {
    icmp_reachable: false,
    tcp_reachable: false,
    is_online: false,
    is_redirected: false,
    is_redirect_target: false,
    redirect_info: null,
  };
  const isOnline = status.is_online ?? (printerStatus as unknown as { is_online?: boolean }).is_online ?? false;

  const hasRedirect = status.is_redirected ?? false;
  const isTarget = status.is_redirect_target ?? false;

  const getStatus = () => {
    if (hasRedirect) return 'redirected';
    if (isTarget) return 'target';
    if (isOnline) return 'online';
    return 'offline';
  };

  return (
    <div className="space-y-4">
      <div>
        <Link to="/printers">
          <Button variant="ghost" size="sm" className="text-muted-foreground">
            Back to Printers
          </Button>
        </Link>
      </div>
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">{printer.name}</h1>
            <a
              href={`http://${printer.ip}`}
              target="_blank"
              rel="noreferrer"
              className="text-muted-foreground hover:text-foreground"
              aria-label="Open printer web interface"
            >
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>
        </div>
        {canEdit && (
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => refreshMutation.mutate()} disabled={refreshMutation.isPending}>
              <RefreshCw className={`h-4 w-4 ${refreshMutation.isPending ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button variant="outline" onClick={() => navigate(`/printers?edit=${id}`)}>
              <Pencil className="h-4 w-4" />
              Edit
            </Button>
            <Button
              variant="outline"
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
              className="delete-action"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Printer Information</CardTitle>
              <CardDescription>Device identity and network status</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-3">
                  <p className="text-xs font-semibold text-muted-foreground">Printer Information</p>
                  <div className="grid grid-cols-[140px_1fr] gap-2 text-sm">
                    <span className="text-muted-foreground">ID</span>
                    <span className="font-mono">{printer.id}</span>
                    <span className="text-muted-foreground">IP Address</span>
                    <span className="font-mono">{printer.ip}</span>
                    <span className="text-muted-foreground">Model</span>
                    <span>{printer.model || '—'}</span>
                    <span className="text-muted-foreground">Location</span>
                    <span>{printer.location || '—'}</span>
                    <span className="text-muted-foreground">Department</span>
                    <span>{printer.department || '—'}</span>
                    <span className="text-muted-foreground">Protocols</span>
                    <span>{printer.protocols?.join(', ').toUpperCase() || '—'}</span>
                  </div>
                </div>
                <div className="space-y-3">
                  <p className="text-xs font-semibold text-muted-foreground">Network Status</p>
                  <div className="grid grid-cols-[140px_1fr] gap-2 text-sm">
                    <span className="text-muted-foreground">ICMP</span>
                    <span className={status.icmp_reachable ? 'text-emerald-600' : 'text-error'}>
                      {status.icmp_reachable ? 'Reachable' : 'Unreachable'}
                    </span>
                    <span className="text-muted-foreground">TCP 9100</span>
                    <span className={status.tcp_reachable ? 'text-emerald-600' : 'text-error'}>
                      {status.tcp_reachable ? 'Open' : 'Closed'}
                    </span>
                    <span className="text-muted-foreground">Health</span>
                    <span className={isOnline ? 'text-emerald-600' : 'text-error'}>
                      {isOnline ? 'Healthy' : 'Critical'}
                    </span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Printer Statistics</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-6 md:grid-cols-3">
                <div>
                  <p className="text-xs text-muted-foreground">Total Pages</p>
                  <p className="text-2xl font-semibold">{statsData?.stats?.total_pages ?? '—'}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Status</p>
                  <p className="text-2xl font-semibold">{statsData?.stats?.status ?? '—'}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Uptime</p>
                  <p className="text-2xl font-semibold">{statsData?.stats?.uptime ?? '—'}</p>
                </div>
              </div>
              {tonerLevels.length > 0 && (
                <div className="space-y-3">
                  <p className="text-xs font-semibold text-muted-foreground">Toner / Supply Levels</p>
                  <div className="grid gap-4 md:grid-cols-2">
                    {tonerLevels.map((level) => (
                      <div key={level.label} className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                          <span>{level.label}</span>
                          <span className="text-muted-foreground">{level.value}%</span>
                        </div>
                        <div className="h-2 w-full rounded-full bg-muted">
                          <div
                            className="h-2 rounded-full bg-emerald-500"
                            style={{ width: `${Math.max(0, Math.min(100, level.value ?? 0))}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Audit History</CardTitle>
                <Button variant="ghost" size="sm" onClick={() => setShowAudit((prev) => !prev)}>
                  {showAudit ? 'Hide' : 'Show'}
                </Button>
              </div>
            </CardHeader>
            {showAudit && (
              <CardContent className="space-y-3">
                {auditData?.logs?.length ? (
                  auditData.logs.map((log: any) => (
                    <div key={log.id} className="text-sm">
                      <p className="font-medium">{log.action}</p>
                      <p className="text-xs text-muted-foreground">
                        {new Date(log.timestamp).toLocaleString()} · {log.username}
                      </p>
                    </div>
                  ))
                ) : (
                  <p className="text-sm text-muted-foreground">No audit activity yet.</p>
                )}
              </CardContent>
            )}
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Status Timeline</CardTitle>
                <Button variant="ghost" size="sm" onClick={() => setShowTimeline((prev) => !prev)}>
                  {showTimeline ? 'Hide' : 'Show'}
                </Button>
              </div>
            </CardHeader>
            {showTimeline && (
              <CardContent className="space-y-2">
                {healthData?.history?.length ? (
                  healthData.history.map((entry: any) => (
                    <div key={entry.id || entry.checked_at} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className={`h-2 w-2 rounded-full ${entry.is_online ? 'bg-emerald-500' : 'bg-red-500'}`} />
                        <span className="font-medium">
                          {entry.is_online ? 'Online' : 'Offline'}
                        </span>
                      </div>
                      <span className="text-muted-foreground">
                        {new Date(entry.checked_at).toLocaleString()}
                      </span>
                    </div>
                  ))
                ) : (
                  <p className="text-sm text-muted-foreground">No recent checks.</p>
                )}
              </CardContent>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

import { useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { printersApi, redirectsApi } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { StatusBadge } from '@/components/printers/StatusBadge';
import {
  ArrowLeft,
  Loader2,
  Pencil,
  Trash2,
  RefreshCw,
  ArrowRight,
  XCircle,
  MapPin,
  Wifi,
  Activity,
} from 'lucide-react';
import type { PrinterStatus, ActiveRedirect } from '@/types/api';

export function PrinterDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canEdit = user?.role === 'admin' || user?.role === 'operator';

  const [selectedTargetId, setSelectedTargetId] = useState<string>('');

  const { data: printerStatus, isLoading } = useQuery<PrinterStatus>({
    queryKey: ['printer', id],
    queryFn: () => printersApi.getById(id!),
    refetchInterval: 10000,
  });

  const { data: allPrinters } = useQuery<PrinterStatus[]>({
    queryKey: ['printers'],
    queryFn: printersApi.getAll,
  });

  const { data: redirects } = useQuery<ActiveRedirect[]>({
    queryKey: ['redirects'],
    queryFn: redirectsApi.getAll,
    enabled: canEdit,
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

  const createRedirectMutation = useMutation({
    mutationFn: () => redirectsApi.create({ source_printer_id: id!, target_printer_id: selectedTargetId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printer', id] });
      queryClient.invalidateQueries({ queryKey: ['redirects'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setSelectedTargetId('');
    },
  });

  const removeRedirectMutation = useMutation({
    mutationFn: (redirectId: number) => redirectsApi.delete(redirectId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printer', id] });
      queryClient.invalidateQueries({ queryKey: ['redirects'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });

  const handleDelete = () => {
    if (confirm(`Are you sure you want to delete "${printerStatus?.printer.name}"?`)) {
      deleteMutation.mutate();
    }
  };

  if (isLoading || !printerStatus) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  const { printer, is_online, has_redirect, is_target, redirect_target, redirect_source } = printerStatus;
  const getStatus = () => {
    if (has_redirect) return 'redirected';
    if (is_target) return 'target';
    if (is_online) return 'online';
    return 'offline';
  };

  const currentRedirect = redirects?.find((r) => r.source_printer_id === id);
  const availableTargets = allPrinters?.filter(
    (p) => p.printer.id !== id && p.is_online && !p.has_redirect && !p.is_target
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-center gap-4">
          <Link to="/printers">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-5 w-5" />
            </Button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold">{printer.name}</h1>
              <StatusBadge status={getStatus()} />
            </div>
            <p className="text-muted-foreground">{printer.ip}</p>
          </div>
        </div>
        {canEdit && (
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => refreshMutation.mutate()} disabled={refreshMutation.isPending}>
              <RefreshCw className={`h-4 w-4 ${refreshMutation.isPending ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Link to={`/printers/${id}/edit`}>
              <Button variant="outline">
                <Pencil className="h-4 w-4" />
                Edit
              </Button>
            </Link>
            <Button variant="outline" onClick={handleDelete} disabled={deleteMutation.isPending}>
              <Trash2 className="h-4 w-4 text-error" />
            </Button>
          </div>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Details card */}
        <Card>
          <CardHeader>
            <CardTitle>Printer Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                <Wifi className="h-5 w-5 text-muted-foreground" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">IP Address</p>
                <p className="font-medium font-mono">{printer.ip}</p>
              </div>
            </div>

            {printer.location && (
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                  <MapPin className="h-5 w-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Location</p>
                  <p className="font-medium">{printer.location}</p>
                </div>
              </div>
            )}

            {printer.model && (
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                  <Activity className="h-5 w-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Model</p>
                  <p className="font-medium">{printer.model}</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Redirect card */}
        {canEdit && (
          <Card>
            <CardHeader>
              <CardTitle>Traffic Redirect</CardTitle>
              <CardDescription>
                Redirect print traffic from this printer to another
              </CardDescription>
            </CardHeader>
            <CardContent>
              {has_redirect && redirect_target && currentRedirect ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 rounded-lg bg-warning-bg p-4">
                    <ArrowRight className="h-5 w-5 text-warning" />
                    <div className="flex-1">
                      <p className="font-medium">Redirecting to {redirect_target.name}</p>
                      <p className="text-sm text-muted-foreground">{redirect_target.ip}</p>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    className="w-full"
                    onClick={() => removeRedirectMutation.mutate(currentRedirect.id)}
                    disabled={removeRedirectMutation.isPending}
                  >
                    {removeRedirectMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <XCircle className="h-4 w-4" />
                    )}
                    Remove Redirect
                  </Button>
                </div>
              ) : is_target && redirect_source ? (
                <div className="flex items-center gap-3 rounded-lg bg-info-bg p-4">
                  <ArrowRight className="h-5 w-5 text-info rotate-180" />
                  <div>
                    <p className="font-medium">Receiving from {redirect_source.name}</p>
                    <p className="text-sm text-muted-foreground">{redirect_source.ip}</p>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <p className="text-sm text-muted-foreground">
                    Select a target printer to redirect traffic to:
                  </p>
                  <select
                    className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                    value={selectedTargetId}
                    onChange={(e) => setSelectedTargetId(e.target.value)}
                  >
                    <option value="">Select a printer...</option>
                    {availableTargets?.map((p) => (
                      <option key={p.printer.id} value={p.printer.id}>
                        {p.printer.name} ({p.printer.ip})
                      </option>
                    ))}
                  </select>
                  <Button
                    className="w-full"
                    disabled={!selectedTargetId || createRedirectMutation.isPending}
                    onClick={() => createRedirectMutation.mutate()}
                  >
                    {createRedirectMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <ArrowRight className="h-4 w-4" />
                    )}
                    Enable Redirect
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

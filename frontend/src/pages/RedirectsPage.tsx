import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { redirectsApi, printersApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  ArrowRightLeft,
  ArrowRight,
  Loader2,
  Trash2,
  Plus,
} from 'lucide-react';
import { useState } from 'react';
import type { ActiveRedirect, PrinterStatus } from '@/types/api';

export function RedirectsPage() {
  const queryClient = useQueryClient();
  const [showAddForm, setShowAddForm] = useState(false);
  const [sourceId, setSourceId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [error, setError] = useState('');

  const { data: redirects, isLoading } = useQuery<ActiveRedirect[]>({
    queryKey: ['redirects'],
    queryFn: redirectsApi.getAll,
  });

  const { data: printers } = useQuery<PrinterStatus[]>({
    queryKey: ['printers'],
    queryFn: printersApi.getAll,
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

  const deleteMutation = useMutation({
    mutationFn: redirectsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['redirects'] });
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
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

  // Available sources: printers that don't already have a redirect
  const availableSources = printers?.filter(
    (p) => !p.has_redirect && !p.is_target
  );

  // Available targets: online printers that aren't already sources or targets
  const availableTargets = printers?.filter(
    (p) => p.is_online && !p.has_redirect && !p.is_target && p.printer.id !== sourceId
  );

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
        <Button onClick={() => setShowAddForm(true)}>
          <Plus className="h-4 w-4" />
          New Redirect
        </Button>
      </div>

      {/* Add redirect form */}
      {showAddForm && (
        <Card>
          <CardHeader>
            <CardTitle>Create Redirect</CardTitle>
            <CardDescription>
              Redirect print traffic from a failed printer to a working one
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {error && (
              <div className="rounded-lg bg-error-bg p-3 text-sm text-error">{error}</div>
            )}
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <label className="text-sm font-medium">Source Printer</label>
                <select
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                  value={sourceId}
                  onChange={(e) => setSourceId(e.target.value)}
                >
                  <option value="">Select source printer...</option>
                  {availableSources?.map((p) => (
                    <option key={p.printer.id} value={p.printer.id}>
                      {p.printer.name} ({p.printer.ip})
                    </option>
                  ))}
                </select>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Target Printer</label>
                <select
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                  value={targetId}
                  onChange={(e) => setTargetId(e.target.value)}
                  disabled={!sourceId}
                >
                  <option value="">Select target printer...</option>
                  {availableTargets?.map((p) => (
                    <option key={p.printer.id} value={p.printer.id}>
                      {p.printer.name} ({p.printer.ip})
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex gap-2">
              <Button
                onClick={() => createMutation.mutate()}
                disabled={!sourceId || !targetId || createMutation.isPending}
              >
                {createMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <ArrowRightLeft className="h-4 w-4" />
                )}
                Create Redirect
              </Button>
              <Button variant="outline" onClick={() => { setShowAddForm(false); setError(''); }}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Redirects list */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Active Redirects</CardTitle>
        </CardHeader>
        <CardContent>
          {redirects && redirects.length > 0 ? (
            <div className="space-y-4">
              {redirects.map((redirect) => (
                <div
                  key={redirect.id}
                  className="flex items-center justify-between rounded-lg bg-muted p-4"
                >
                  <div className="flex items-center gap-4">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-warning-bg">
                      <ArrowRightLeft className="h-5 w-5 text-warning" />
                    </div>
                    <div className="flex items-center gap-3">
                      <div>
                        <p className="font-medium">{getPrinterName(redirect.source_printer_id)}</p>
                        <p className="text-xs text-muted-foreground font-mono">{redirect.source_ip}</p>
                      </div>
                      <ArrowRight className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="font-medium">{getPrinterName(redirect.target_printer_id)}</p>
                        <p className="text-xs text-muted-foreground font-mono">{redirect.target_ip}</p>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-right text-sm">
                      <p className="text-muted-foreground">Enabled by {redirect.enabled_by}</p>
                      <p className="text-xs text-muted-foreground">
                        {new Date(redirect.enabled_at).toLocaleDateString()}
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleDelete(redirect.id)}
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 className="h-4 w-4 text-error" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted">
                <ArrowRightLeft className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="mt-4 text-lg font-medium">No active redirects</h3>
              <p className="mt-2 text-center text-muted-foreground">
                Create a redirect to forward print traffic from a failed printer to a working one.
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

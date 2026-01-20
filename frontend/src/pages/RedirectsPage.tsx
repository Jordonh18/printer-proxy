import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { redirectsApi, printersApi } from '@/lib/api';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  ArrowRightLeft,
  ArrowRight,
  Loader2,
  Trash2,
  Plus,
} from 'lucide-react';
import { useState } from 'react';
import { useDocumentTitle } from '@/hooks/use-document-title';
import type { ActiveRedirect, PrinterStatus } from '@/types/api';

export function RedirectsPage() {
  useDocumentTitle('Redirects');
  const queryClient = useQueryClient();
  const [showAddForm, setShowAddForm] = useState(false);
  const [sourceId, setSourceId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [error, setError] = useState('');
  const [deleteError, setDeleteError] = useState('');

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
        {redirects && redirects.length > 0 && (
          <Button onClick={() => setShowAddForm(true)}>
            <Plus className="h-4 w-4" />
            New Redirect
          </Button>
        )}
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
          <div className="space-y-4">
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
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowAddForm(false); setError(''); }}>
              Cancel
            </Button>
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
                      <div className="text-xs text-muted-foreground font-mono">{redirect.source_ip}</div>
                    </TableCell>
                    <TableCell className="px-4">
                      <div className="font-medium">{getPrinterName(redirect.target_printer_id)}</div>
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
            <Button onClick={() => setShowAddForm(true)}>
              <Plus className="h-4 w-4" />
              New Redirect
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

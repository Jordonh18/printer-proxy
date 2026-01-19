import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { printersApi, discoveryApi } from '@/lib/api';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { StatusBadge } from '@/components/printers/StatusBadge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Eye,
  Loader2,
  Pencil,
  Printer,
  Trash2,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import type { PrinterStatus } from '@/types/api';

export function PrintersPage() {
  const queryClient = useQueryClient();
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [showDiscover, setShowDiscover] = useState(false);
  const [subnet, setSubnet] = useState('');
  const [singleIp, setSingleIp] = useState('');
  const [discoverError, setDiscoverError] = useState('');
  const [discoverResults, setDiscoverResults] = useState<Array<{
    ip: string;
    name?: string;
    model?: string;
    location?: string;
    discovery_method?: string;
    hostname?: string;
    tcp_9100_open?: boolean;
    snmp_available?: boolean;
  }>>([]);
  const [importedIps, setImportedIps] = useState<Set<string>>(new Set());
  const [importingIp, setImportingIp] = useState<string | null>(null);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [addError, setAddError] = useState('');
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [editError, setEditError] = useState('');
  const [editPrinterId, setEditPrinterId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({
    name: '',
    ip: '',
    location: '',
    model: '',
  });
  const [printerForm, setPrinterForm] = useState({
    name: '',
    ip: '',
    location: '',
    model: '',
    department: '',
    notes: '',
    protocols: ['raw'] as string[],
  });
  const [searchParams, setSearchParams] = useSearchParams();

  const { data: printers, isLoading } = useQuery<PrinterStatus[]>({
    queryKey: ['printers'],
    queryFn: printersApi.getAll,
  });

  const deleteMutation = useMutation({
    mutationFn: printersApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setDeletingId(null);
    },
    onError: () => {
      setDeletingId(null);
    },
  });

  const discoverMutation = useMutation({
    mutationFn: () => discoveryApi.scan(singleIp || subnet || undefined),
    onSuccess: (data) => {
      setDiscoverError('');
      setDiscoverResults(data.printers || []);
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setDiscoverError(axiosError.response?.data?.error || 'Discovery failed');
      } else {
        setDiscoverError('Discovery failed');
      }
    },
  });

  const addDiscoveredMutation = useMutation({
    mutationFn: printersApi.create,
    onMutate: (variables) => {
      setImportingIp(variables.ip);
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setImportedIps((current) => new Set(current).add(variables.ip));
      setImportingIp(null);
    },
    onError: () => {
      setImportingIp(null);
    },
  });

  const updatePrinterMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { name: string; ip: string; location?: string; model?: string } }) =>
      printersApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setIsEditModalOpen(false);
      setEditError('');
      setEditPrinterId(null);
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setEditError(axiosError.response?.data?.error || 'Failed to update printer');
      } else {
        setEditError('Failed to update printer');
      }
    },
  });

  const createPrinterMutation = useMutation({
    mutationFn: printersApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      setIsAddModalOpen(false);
      setPrinterForm({
        name: '',
        ip: '',
        location: '',
        model: '',
        department: '',
        notes: '',
        protocols: ['raw'],
      });
      setAddError('');
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setAddError(axiosError.response?.data?.error || 'Failed to add printer');
      } else {
        setAddError('Failed to add printer');
      }
    },
  });

  const handleDelete = (id: string, name: string) => {
    if (confirm(`Are you sure you want to delete "${name}"?`)) {
      setDeletingId(id);
      deleteMutation.mutate(id);
    }
  };

  const startEdit = (printer: PrinterStatus['printer']) => {
    setEditPrinterId(printer.id);
    setEditForm({
      name: printer.name,
      ip: printer.ip,
      location: printer.location || '',
      model: printer.model || '',
    });
    setEditError('');
    setIsEditModalOpen(true);
  };

  useEffect(() => {
    if (searchParams.get('add') === '1') {
      setIsAddModalOpen(true);
      setSearchParams((params) => {
        params.delete('add');
        return params;
      }, { replace: true });
    }
  }, [searchParams, setSearchParams]);

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
          <h1 className="text-2xl font-bold">Printers</h1>
          <p className="text-muted-foreground">Manage your network printers</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setShowDiscover(true)}>
            Discover Printers
          </Button>
          <Button onClick={() => setIsAddModalOpen(true)}>Add Printer</Button>
        </div>
      </div>

      <Dialog open={isAddModalOpen} onOpenChange={setIsAddModalOpen}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>Add Printer</DialogTitle>
            <DialogDescription>Enter printer details to add it to the registry.</DialogDescription>
          </DialogHeader>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              setAddError('');
              createPrinterMutation.mutate({
                name: printerForm.name,
                ip: printerForm.ip,
                location: printerForm.location || undefined,
                model: printerForm.model || undefined,
                department: printerForm.department || undefined,
                notes: printerForm.notes || undefined,
                protocols: printerForm.protocols,
              });
            }}
            className="space-y-4"
          >
            {addError && (
              <div className="rounded-lg bg-error-bg p-3 text-sm text-error">{addError}</div>
            )}
            <div className="space-y-1">
              <h4 className="text-sm font-semibold">Printer details</h4>
              <p className="text-xs text-muted-foreground">Required information for registration.</p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="printer-name">Name</Label>
                <Input
                  id="printer-name"
                  value={printerForm.name}
                  onChange={(e) => setPrinterForm({ ...printerForm, name: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="printer-ip">IP Address</Label>
                <Input
                  id="printer-ip"
                  value={printerForm.ip}
                  onChange={(e) => setPrinterForm({ ...printerForm, ip: e.target.value })}
                  required
                />
              </div>
            </div>

            <div className="space-y-1">
              <h4 className="text-sm font-semibold">Metadata</h4>
              <p className="text-xs text-muted-foreground">Optional context for reporting and filters.</p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="printer-location">Location</Label>
                <Input
                  id="printer-location"
                  value={printerForm.location}
                  onChange={(e) => setPrinterForm({ ...printerForm, location: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="printer-department">Department</Label>
                <Input
                  id="printer-department"
                  value={printerForm.department}
                  onChange={(e) => setPrinterForm({ ...printerForm, department: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="printer-model">Model</Label>
                <Input
                  id="printer-model"
                  value={printerForm.model}
                  onChange={(e) => setPrinterForm({ ...printerForm, model: e.target.value })}
                />
              </div>
            </div>

            <div className="space-y-1">
              <h4 className="text-sm font-semibold">Protocols</h4>
              <p className="text-xs text-muted-foreground">Select supported print protocols.</p>
            </div>
            <div className="flex flex-wrap gap-4">
              {['raw', 'ipp', 'lpr'].map((protocol) => (
                <label key={protocol} className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={printerForm.protocols.includes(protocol)}
                    onCheckedChange={(value) => {
                      setPrinterForm((current) => {
                        const next = new Set(current.protocols)
                        if (value === true) {
                          next.add(protocol)
                        } else {
                          next.delete(protocol)
                        }
                        return { ...current, protocols: Array.from(next) }
                      })
                    }}
                  />
                  {protocol.toUpperCase()}
                </label>
              ))}
            </div>

            <div className="space-y-2">
              <Label htmlFor="printer-notes">Notes</Label>
              <Textarea
                id="printer-notes"
                value={printerForm.notes}
                onChange={(e) => setPrinterForm({ ...printerForm, notes: e.target.value })}
                placeholder="Add any special instructions or maintenance notes..."
              />
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setIsAddModalOpen(false);
                  setAddError('');
                  setPrinterForm({
                    name: '',
                    ip: '',
                    location: '',
                    model: '',
                    department: '',
                    notes: '',
                    protocols: ['raw'],
                  });
                }}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createPrinterMutation.isPending}>
                {createPrinterMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={isEditModalOpen} onOpenChange={setIsEditModalOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>Edit Printer</DialogTitle>
            <DialogDescription>Update printer details and save changes.</DialogDescription>
          </DialogHeader>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              if (!editPrinterId) return;
              setEditError('');
              updatePrinterMutation.mutate({
                id: editPrinterId,
                data: {
                  name: editForm.name,
                  ip: editForm.ip,
                  location: editForm.location || undefined,
                  model: editForm.model || undefined,
                },
              });
            }}
            className="space-y-4"
          >
            {editError && (
              <div className="rounded-lg bg-error-bg p-3 text-sm text-error">{editError}</div>
            )}
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="edit-printer-name">Name</Label>
                <Input
                  id="edit-printer-name"
                  value={editForm.name}
                  onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-printer-ip">IP Address</Label>
                <Input
                  id="edit-printer-ip"
                  value={editForm.ip}
                  onChange={(e) => setEditForm({ ...editForm, ip: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-printer-location">Location</Label>
                <Input
                  id="edit-printer-location"
                  value={editForm.location}
                  onChange={(e) => setEditForm({ ...editForm, location: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-printer-model">Model</Label>
                <Input
                  id="edit-printer-model"
                  value={editForm.model}
                  onChange={(e) => setEditForm({ ...editForm, model: e.target.value })}
                />
              </div>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setIsEditModalOpen(false);
                  setEditError('');
                }}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updatePrinterMutation.isPending}>
                {updatePrinterMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={showDiscover} onOpenChange={setShowDiscover}>
        <DialogContent className="!max-w-[95vw] !w-[95vw] !max-h-[90vh] !h-[90vh] p-0 overflow-hidden">
          <div className="flex h-full flex-col">
            <div className="border-b border-border px-6 py-5">
              <DialogHeader className="space-y-2">
                <DialogTitle>Discover Printers</DialogTitle>
                <DialogDescription>
                  Scan your network and import printers into the registry.
                </DialogDescription>
              </DialogHeader>
            </div>
            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
              {discoverError && (
                <div className="rounded-lg bg-error-bg p-3 text-sm text-error">
                  {discoverError}
                </div>
              )}
              <section className="space-y-4 rounded-lg border border-border px-4 py-4">
                <div>
                  <h3 className="text-sm font-semibold">Network Scan</h3>
                  <p className="text-xs text-muted-foreground">Choose a CIDR or single IP to scan.</p>
                </div>
                <div className="grid gap-4 lg:grid-cols-[1fr_auto_1fr_auto] lg:items-end">
                  <div className="space-y-2">
                    <Label htmlFor="discover-subnet">Network to scan (CIDR)</Label>
                    <Input
                      id="discover-subnet"
                      placeholder="e.g. 192.168.1.0/24"
                      value={subnet}
                      onChange={(e) => setSubnet(e.target.value)}
                    />
                  </div>
                  <div className="text-xs font-medium text-muted-foreground text-center">OR</div>
                  <div className="space-y-2">
                    <Label htmlFor="discover-single">Scan single IP</Label>
                    <Input
                      id="discover-single"
                      placeholder="e.g. 10.0.0.23"
                      value={singleIp}
                      onChange={(e) => setSingleIp(e.target.value)}
                    />
                  </div>
                  <Button onClick={() => discoverMutation.mutate()} disabled={discoverMutation.isPending}>
                    {discoverMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Scan'}
                  </Button>
                </div>
              </section>

              {discoverResults.length > 0 && (
                <section className="space-y-4 rounded-lg border border-border">
                  <div className="flex items-center justify-between border-b border-border px-4 py-3">
                    <div>
                      <h3 className="text-sm font-semibold">Discovered Printers</h3>
                      <p className="text-xs text-muted-foreground">Edit values before importing.</p>
                    </div>
                    <div className="text-xs text-muted-foreground">{discoverResults.length} found</div>
                  </div>
                  <div className="max-h-[45vh] overflow-y-auto">
                    <div className="w-full overflow-x-auto">
                      <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="px-4">IP Address</TableHead>
                          <TableHead className="px-4">Name</TableHead>
                          <TableHead className="px-4">Model</TableHead>
                          <TableHead className="px-4">Location</TableHead>
                          <TableHead className="px-4">Host</TableHead>
                          <TableHead className="px-4">Method</TableHead>
                          <TableHead className="px-4">Caps</TableHead>
                          <TableHead className="px-4 text-right">Action</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {discoverResults.map((printer) => (
                          <TableRow
                            key={printer.ip}
                            className={importedIps.has(printer.ip) ? 'bg-emerald-50' : undefined}
                          >
                            <TableCell className="px-4 text-sm font-mono">{printer.ip}</TableCell>
                            <TableCell className="px-4">
                              <Input
                                value={printer.name || ''}
                                onChange={(e) =>
                                  setDiscoverResults((current) =>
                                    current.map((item) =>
                                      item.ip === printer.ip
                                        ? { ...item, name: e.target.value }
                                        : item
                                    )
                                  )
                                }
                              />
                            </TableCell>
                            <TableCell className="px-4">
                              <Input
                                value={printer.model || ''}
                                onChange={(e) =>
                                  setDiscoverResults((current) =>
                                    current.map((item) =>
                                      item.ip === printer.ip
                                        ? { ...item, model: e.target.value }
                                        : item
                                    )
                                  )
                                }
                              />
                            </TableCell>
                            <TableCell className="px-4">
                              <Input
                                value={printer.location || ''}
                                onChange={(e) =>
                                  setDiscoverResults((current) =>
                                    current.map((item) =>
                                      item.ip === printer.ip
                                        ? { ...item, location: e.target.value }
                                        : item
                                    )
                                  )
                                }
                              />
                            </TableCell>
                            <TableCell className="px-4 text-sm text-muted-foreground">
                              {printer.hostname || '—'}
                            </TableCell>
                            <TableCell className="px-4">
                              <Badge variant="secondary">
                                {(printer.discovery_method || 'Unknown').toUpperCase()}
                              </Badge>
                            </TableCell>
                            <TableCell className="px-4">
                              <div className="flex flex-wrap gap-2">
                                {printer.tcp_9100_open && (
                                  <Badge variant="outline">9100</Badge>
                                )}
                                {printer.snmp_available && (
                                  <Badge variant="outline">SNMP</Badge>
                                )}
                              </div>
                            </TableCell>
                            <TableCell className="px-4 text-right">
                              <Button
                                variant="outline"
                                onClick={() =>
                                  addDiscoveredMutation.mutate({
                                    name: printer.name || printer.ip,
                                    ip: printer.ip,
                                    model: printer.model || undefined,
                                    location: printer.location || undefined,
                                    protocols: printer.tcp_9100_open ? ['raw'] : undefined,
                                  })
                                }
                                disabled={
                                  addDiscoveredMutation.isPending || importedIps.has(printer.ip)
                                }
                              >
                                {importedIps.has(printer.ip)
                                  ? 'Imported'
                                  : importingIp === printer.ip
                                    ? 'Importing…'
                                    : 'Import'}
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                      </Table>
                    </div>
                  </div>
                </section>
              )}
            </div>
            <div className="border-t border-border px-6 py-4 flex justify-end bg-background sticky bottom-0">
              <Button variant="outline" onClick={() => setShowDiscover(false)}>Close</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Printers table */}
      <Card>
        <CardContent className="p-0">
          {printers && printers.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="px-4">Printer</TableHead>
                  <TableHead className="px-4">IP Address</TableHead>
                  <TableHead className="px-4">Location</TableHead>
                  <TableHead className="px-4">Status</TableHead>
                  <TableHead className="px-4 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {printers.map((printerStatus) => {
                  const { printer, is_online, has_redirect, is_target } = printerStatus;
                  const getStatus = () => {
                    if (has_redirect) return 'redirected';
                    if (is_target) return 'target';
                    if (is_online) return 'online';
                    return 'offline';
                  };

                  return (
                    <TableRow key={printer.id}>
                      <TableCell className="px-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                            <Printer className="h-5 w-5 text-primary" />
                          </div>
                          <div>
                            <Link
                              to={`/printers/${printer.id}`}
                              className="font-medium hover:text-primary"
                            >
                              {printer.name}
                            </Link>
                            {printer.model && (
                              <p className="text-xs text-muted-foreground">{printer.model}</p>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="px-4">
                        <Badge variant="outline" className="font-mono">
                          {printer.ip}
                        </Badge>
                      </TableCell>
                      <TableCell className="px-4 text-muted-foreground">
                        {printer.location || '—'}
                      </TableCell>
                      <TableCell className="px-4">
                        <StatusBadge status={getStatus()} />
                      </TableCell>
                      <TableCell className="px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <Link to={`/printers/${printer.id}`} aria-label={`View ${printer.name}`}>
                            <Button variant="ghost" size="icon">
                              <Eye className="h-4 w-4" />
                            </Button>
                          </Link>
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={`Edit ${printer.name}`}
                            onClick={() => startEdit(printer)}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={`Delete ${printer.name}`}
                            onClick={() => handleDelete(printer.id, printer.name)}
                            disabled={deleteMutation.isPending}
                          >
                            {deletingId === printer.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center justify-center py-16">
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted">
                <Printer className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="mt-4 text-lg font-medium">No printers configured</h3>
              <p className="mt-2 text-center text-muted-foreground">
                Get started by adding your first printer.
              </p>
              <Button className="mt-6" onClick={() => setIsAddModalOpen(true)}>
                Add Printer
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

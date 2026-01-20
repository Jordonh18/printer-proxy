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
import { useDocumentTitle } from '@/hooks/use-document-title';
import type { PrinterStatus } from '@/types/api';

export function PrintersPage() {
  useDocumentTitle('Printers');
  const queryClient = useQueryClient();
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState('');
  const [showDiscover, setShowDiscover] = useState(false);
  const [subnet, setSubnet] = useState('');
  const [singleIp, setSingleIp] = useState('');
  const [discoverError, setDiscoverError] = useState('');
  const [discoverStep, setDiscoverStep] = useState<'input' | 'scanning' | 'results'>('input');
  const [tipIndex, setTipIndex] = useState(0);
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
      setDeleteError('');
    },
    onError: (err: unknown) => {
      setDeletingId(null);
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setDeleteError(axiosError.response?.data?.error || 'Failed to delete printer');
      } else {
        setDeleteError('Failed to delete printer');
      }
    },
  });

  const discoverMutation = useMutation({
    mutationFn: () => discoveryApi.scan(singleIp || subnet || undefined),
    onMutate: () => {
      setDiscoverError('');
      setDiscoverStep('scanning');
    },
    onSuccess: (data) => {
      setDiscoverError('');
      setDiscoverResults(data.printers || []);
      setDiscoverStep('results');
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setDiscoverError(axiosError.response?.data?.error || 'Discovery failed');
      } else {
        setDiscoverError('Discovery failed');
      }
      setDiscoverStep('input');
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

  useEffect(() => {
    const editId = searchParams.get('edit');
    if (!editId || !printers) return;
    const printerStatus = printers.find((item) => item.printer.id === editId);
    if (printerStatus) {
      startEdit(printerStatus.printer);
    }
    setSearchParams((params) => {
      params.delete('edit');
      return params;
    }, { replace: true });
  }, [searchParams, setSearchParams, printers]);

  useEffect(() => {
    if (discoverStep !== 'scanning') return;
    const timer = window.setInterval(() => {
      setTipIndex((current) => {
        if (DISCOVERY_TIPS.length <= 1) return 0;
        let next = Math.floor(Math.random() * DISCOVERY_TIPS.length);
        if (next === current) {
          next = (next + 1) % DISCOVERY_TIPS.length;
        }
        return next;
      });
    }, 3200);
    return () => window.clearInterval(timer);
  }, [discoverStep]);

  const DISCOVERY_TIPS = [
    '1969: Xerox debuts the 9700, one of the first commercial laser printers.',
    '1976: IBM ships the 3800, a high‑speed laser printer for mainframes.',
    '1984: HP launches the original LaserJet, changing office printing.',
    '1985: Apple’s LaserWriter helps ignite the desktop publishing boom.',
    '1999: IPP is standardized, enabling network printing over HTTP.',
    'Many printers still expose PJL commands for deep status inspection.',
    'Some devices store a lifetime page count in non‑volatile memory.',
    'RAW port 9100 originated with HP JetDirect cards in early networks.',
    'SNMP can surface model, serial, uptime, and consumables in seconds.',
    'Bonjour/mDNS can discover printers without DHCP reservations.',
    'IPP Everywhere allows driverless printing on modern networks.',
    'The first dot‑matrix printers were inspired by teletype mechanisms.',
  ];

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  const hasPrinters = !!(printers && printers.length > 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">Printers</h1>
          <p className="text-muted-foreground">Manage your network printers</p>
        </div>
        {hasPrinters && (
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setShowDiscover(true)}>
              Discover Printers
            </Button>
            <Button onClick={() => setIsAddModalOpen(true)}>Add Printer</Button>
          </div>
        )}
      </div>

      {deleteError && (
        <div className="rounded-lg bg-error-bg p-3 text-sm text-error">
          {deleteError}
        </div>
      )}

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
        <DialogContent className="!max-w-[80vw] !w-[80vw] !max-h-[70vh] !h-[70vh] p-0 overflow-hidden">
          <div className="flex h-full flex-col">
            {discoverStep === 'results' && (
              <div className="border-b border-border px-6 py-5">
                <DialogHeader>
                  <DialogTitle>Discovered Printers</DialogTitle>
                </DialogHeader>
              </div>
            )}
            <div className="flex-1 overflow-y-auto px-6 py-6">
              {discoverStep === 'input' && (
                <div className="mx-auto flex min-h-[70vh] w-full max-w-3xl flex-col justify-center">
                  {discoverError && (
                    <div className="rounded-lg bg-error-bg p-3 text-sm text-error">
                      {discoverError}
                    </div>
                  )}
                  <div className="grid gap-6 lg:grid-cols-[1fr_auto_1fr] lg:items-end">
                    <div className="space-y-3">
                      <Label htmlFor="discover-subnet" className="text-sm">Network (CIDR)</Label>
                      <Input
                        id="discover-subnet"
                        placeholder="192.168.1.0/24"
                        value={subnet}
                        onChange={(e) => setSubnet(e.target.value)}
                        className="h-12 text-base"
                      />
                    </div>
                    <div className="text-xs font-medium text-muted-foreground text-center">OR</div>
                    <div className="space-y-3">
                      <Label htmlFor="discover-single" className="text-sm">Single IP</Label>
                      <Input
                        id="discover-single"
                        placeholder="10.0.0.23"
                        value={singleIp}
                        onChange={(e) => setSingleIp(e.target.value)}
                        className="h-12 text-base"
                      />
                    </div>
                  </div>
                  <div className="mt-6 flex justify-center">
                    <Button
                      size="lg"
                      className="h-12 px-14 text-base"
                      onClick={() => discoverMutation.mutate()}
                      disabled={discoverMutation.isPending}
                    >
                      {discoverMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Scan'}
                    </Button>
                  </div>
                </div>
              )}

              {discoverStep === 'scanning' && (
                <div className="flex min-h-[70vh] flex-col items-center justify-center text-center">
                  <div className="flex h-48 w-48 items-center justify-center rounded-2xl bg-primary/5">
                    <svg
                      className="h-32 w-32 text-primary"
                      viewBox="0 0 200 200"
                      fill="none"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <rect x="40" y="55" width="120" height="70" rx="12" className="fill-primary/15" />
                      <rect x="60" y="40" width="80" height="25" rx="6" className="fill-primary/25" />
                      <rect x="70" y="120" width="60" height="35" rx="6" className="fill-primary/20" />
                      <circle cx="150" cy="90" r="4" className="fill-primary" />
                      <path d="M30 150h140" className="stroke-primary/30" strokeWidth="6" strokeLinecap="round" />
                      <circle cx="30" cy="150" r="6" className="fill-primary/40">
                        <animate attributeName="cx" values="30;170;30" dur="2.8s" repeatCount="indefinite" />
                      </circle>
                    </svg>
                  </div>
                  <h3 className="mt-6 text-xl font-semibold">Scanning for printers…</h3>
                  <p className="mt-2 max-w-lg text-sm text-muted-foreground">{DISCOVERY_TIPS[tipIndex]}</p>
                </div>
              )}

              {discoverStep === 'results' && (
                <div className="space-y-4">
                  {discoverError && (
                    <div className="rounded-lg bg-error-bg p-3 text-sm text-error">
                      {discoverError}
                    </div>
                  )}
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">{discoverResults.length} found</p>
                  </div>
                  <div className="rounded-lg border border-border">
                    <div className="max-h-[55vh] overflow-y-auto">
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
                  </div>
                </div>
              )}
            </div>
            {discoverStep === 'results' && (
              <div className="border-t border-border px-6 py-4 flex justify-end bg-background sticky bottom-0">
                <Button variant="outline" onClick={() => {
                  setShowDiscover(false);
                  setDiscoverStep('input');
                }}>
                  Close
                </Button>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Printers table */}
      {hasPrinters ? (
        <Card className="gap-0 py-0">
          <CardContent className="p-0">
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
                  const { printer, status } = printerStatus;
                  const isOnline = status?.is_online ?? (printerStatus as unknown as { is_online?: boolean }).is_online ?? false;
                  const hasRedirect = status?.is_redirected ?? (printerStatus as unknown as { has_redirect?: boolean }).has_redirect ?? false;
                  const isTarget = status?.is_redirect_target ?? (printerStatus as unknown as { is_target?: boolean }).is_target ?? false;
                  const getStatus = () => {
                    if (hasRedirect) return 'redirected';
                    if (isTarget) return 'target';
                    if (isOnline) return 'online';
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
                            className="delete-action"
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
            <rect x="42" y="60" width="116" height="62" rx="12" className="fill-primary/15" />
            <rect x="62" y="45" width="76" height="22" rx="6" className="fill-primary/25" />
            <rect x="70" y="120" width="60" height="32" rx="6" className="fill-primary/20" />
            <circle cx="148" cy="90" r="4" className="fill-primary" />
            <path d="M35 155h130" className="stroke-primary/30" strokeWidth="6" strokeLinecap="round" />
            </svg>
          </div>
          <h3 className="mt-6 text-2xl font-semibold">Your printer fleet starts here</h3>
          <p className="mt-3 max-w-xl text-sm text-muted-foreground">
            Add a printer or scan the network to build your registry in minutes.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Button onClick={() => setIsAddModalOpen(true)}>Add Printer</Button>
            <Button variant="outline" onClick={() => setShowDiscover(true)}>
              Discover Printers
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

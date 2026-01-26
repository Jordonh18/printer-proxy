import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { printerGroupsApi, printersApi } from '@/lib/api';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Checkbox } from '@/components/ui/checkbox';
import { Loader2, Pencil, Trash2, Users } from 'lucide-react';
import { useDocumentTitle } from '@/hooks/use-document-title';
import { useAuth } from '@/contexts/AuthContext';
import type { PrinterGroup, PrinterGroupDetail, PrinterStatus } from '@/types/api';

export function GroupsPage() {
  useDocumentTitle('Printer Groups');
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const [showGroupModal, setShowGroupModal] = useState(false);
  const [showMembersModal, setShowMembersModal] = useState(false);
  const [editingGroup, setEditingGroup] = useState<PrinterGroup | null>(null);
  const [managingGroup, setManagingGroup] = useState<PrinterGroup | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [selectedPrinters, setSelectedPrinters] = useState<string[]>([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [error, setError] = useState('');
  const [groupSearch, setGroupSearch] = useState('');
  const [healthFilter, setHealthFilter] = useState('all');

  const { data: groupsData, isLoading } = useQuery<{ groups: PrinterGroup[] }>({
    queryKey: ['printer-groups'],
    queryFn: printerGroupsApi.getAll,
  });

  const { data: printers } = useQuery<PrinterStatus[]>({
    queryKey: ['printers'],
    queryFn: printersApi.getAll,
  });

  const groups = groupsData?.groups || [];
  const filteredGroups = groups.filter((group) => {
    if (!groupSearch.trim()) return true;
    const needle = groupSearch.toLowerCase();
    return group.name.toLowerCase().includes(needle) || (group.description || '').toLowerCase().includes(needle);
  }).filter((group) => {
    if (healthFilter === 'all') return true;
    const health = groupHealth[group.id] || { total: 0, online: 0 };
    if (health.total === 0) return healthFilter === 'empty';
    if (healthFilter === 'healthy') return health.online === health.total;
    if (healthFilter === 'degraded') return health.online < health.total && health.online > 0;
    if (healthFilter === 'offline') return health.online === 0;
    return true;
  });

  const groupHealth = (printers || []).reduce<Record<number, { total: number; online: number }>>(
    (acc, printerStatus) => {
      const groupId = printerStatus.group?.id;
      if (!groupId) return acc;
      if (!acc[groupId]) acc[groupId] = { total: 0, online: 0 };
      acc[groupId].total += 1;
      if (printerStatus.is_online || printerStatus.status?.is_online) acc[groupId].online += 1;
      return acc;
    },
    {}
  );

  const createMutation = useMutation({
    mutationFn: () => printerGroupsApi.create({ name, description }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printer-groups'] });
      setShowGroupModal(false);
      setName('');
      setDescription('');
      setEditingGroup(null);
      setError('');
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setError(axiosError.response?.data?.error || 'Failed to create group');
      } else {
        setError('Failed to create group');
      }
    },
  });

  const updateMutation = useMutation({
    mutationFn: () => printerGroupsApi.update(editingGroup!.id, { name, description }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printer-groups'] });
      setShowGroupModal(false);
      setEditingGroup(null);
      setName('');
      setDescription('');
      setError('');
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setError(axiosError.response?.data?.error || 'Failed to update group');
      } else {
        setError('Failed to update group');
      }
    },
  });

  const deleteMutation = useMutation({
    mutationFn: printerGroupsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printer-groups'] });
      queryClient.invalidateQueries({ queryKey: ['printers'] });
    },
  });

  const membersMutation = useMutation({
    mutationFn: (payload: { groupId: number; printerIds: string[] }) =>
      printerGroupsApi.setPrinters(payload.groupId, payload.printerIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printer-groups'] });
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      setShowMembersModal(false);
      setManagingGroup(null);
      setSelectedPrinters([]);
    },
  });

  const openCreate = () => {
    setEditingGroup(null);
    setName('');
    setDescription('');
    setError('');
    setShowGroupModal(true);
  };

  const openEdit = (group: PrinterGroup) => {
    setEditingGroup(group);
    setName(group.name);
    setDescription(group.description || '');
    setError('');
    setShowGroupModal(true);
  };

  const openManagePrinters = async (group: PrinterGroup) => {
    setManagingGroup(group);
    setSelectedPrinters([]);
    setMembersLoading(true);
    setShowMembersModal(true);
    try {
      const detail: PrinterGroupDetail = await printerGroupsApi.getById(group.id);
      setSelectedPrinters(detail.printer_ids || []);
    } finally {
      setMembersLoading(false);
    }
  };

  const togglePrinter = (printerId: string) => {
    setSelectedPrinters((prev) =>
      prev.includes(printerId) ? prev.filter((id) => id !== printerId) : [...prev, printerId]
    );
  };

  const handleSaveGroup = () => {
    if (!name.trim()) {
      setError('Group name is required');
      return;
    }
    if (editingGroup) {
      updateMutation.mutate();
    } else {
      createMutation.mutate();
    }
  };

  const handleDeleteGroup = (groupId: number) => {
    if (confirm('Delete this group? Printers will be unassigned.')) {
      deleteMutation.mutate(groupId);
    }
  };

  const handleSaveMembers = () => {
    if (!managingGroup) return;
    membersMutation.mutate({ groupId: managingGroup.id, printerIds: selectedPrinters });
  };

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">Groups</h1>
          <p className="text-muted-foreground">Organize printers into fleet groups for faster redirects.</p>
        </div>
        <Button onClick={openCreate}>New Group</Button>
      </div>
      {groups.length === 0 ? (
        <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
          <div className="relative">
            <div className="absolute inset-0 -z-10 h-48 w-48 rounded-full bg-primary/5 blur-2xl" />
            <svg
              className="h-40 w-40 text-primary"
              viewBox="0 0 200 200"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <circle cx="70" cy="85" r="24" className="fill-primary/15" />
              <circle cx="130" cy="85" r="24" className="fill-primary/20" />
              <rect x="55" y="115" width="90" height="36" rx="12" className="fill-primary/10" />
            </svg>
          </div>
          <h3 className="mt-6 text-2xl font-semibold">Create your first group</h3>
          <p className="mt-3 max-w-xl text-sm text-muted-foreground">
            Group printers together so redirects and notifications stay organized.
          </p>
          <div className="mt-6">
            <Button onClick={openCreate}>New Group</Button>
          </div>
        </div>
      ) : (
        <>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div className="w-full sm:max-w-sm">
              <Input
                id="group-search"
                value={groupSearch}
                onChange={(event) => setGroupSearch(event.target.value)}
                placeholder="Search by group name or description"
              />
            </div>
            <div className="flex flex-wrap items-end gap-3">
              <p className="text-sm text-muted-foreground">
                {filteredGroups.length} of {groups.length}
              </p>
              <div className="min-w-[180px]">
                <select
                  id="health-filter"
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                  value={healthFilter}
                  onChange={(event) => setHealthFilter(event.target.value)}
                >
                  <option value="all">All health</option>
                  <option value="healthy">Healthy</option>
                  <option value="degraded">Degraded</option>
                  <option value="offline">Offline</option>
                  <option value="empty">No printers</option>
                </select>
              </div>
            </div>
          </div>

          <Card className="gap-0 py-0">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="px-4">Group</TableHead>
                    <TableHead className="px-4">Description</TableHead>
                    <TableHead className="px-4">Health</TableHead>
                    <TableHead className="px-4">Printers</TableHead>
                    <TableHead className="px-4 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredGroups.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="px-4 py-10 text-center text-sm text-muted-foreground">
                        No groups match your search.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredGroups.map((group) => {
                      const health = groupHealth[group.id] || { total: 0, online: 0 };
                      const offline = health.total - health.online;
                      const isOwner = group.owner_user_id ? group.owner_user_id === user?.id : true;
                      return (
                      <TableRow key={group.id}>
                        <TableCell className="px-4">
                          <div className="flex items-center gap-3">
                            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                              <Users className="h-5 w-5" />
                            </div>
                            <div>
                              <div className="font-medium">{group.name}</div>
                              <div className="text-xs text-muted-foreground">Owner: {group.owner_username || 'Unknown'}</div>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="px-4 text-sm text-muted-foreground">
                          {group.description || '—'}
                        </TableCell>
                        <TableCell className="px-4">
                          <div className="flex flex-col text-xs text-muted-foreground">
                            <span>{health.online} online</span>
                            <span>{offline} offline</span>
                          </div>
                        </TableCell>
                        <TableCell className="px-4">
                          <Badge variant="secondary">{group.printer_count} printers</Badge>
                        </TableCell>
                        <TableCell className="px-4 text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => openManagePrinters(group)}
                              disabled={!isOwner}
                            >
                              Manage printers
                            </Button>
                            <Button variant="ghost" size="icon" onClick={() => openEdit(group)} disabled={!isOwner}>
                              <Pencil className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleDeleteGroup(group.id)}
                              disabled={!isOwner}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </>
      )}

      <Dialog open={showGroupModal} onOpenChange={setShowGroupModal}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>{editingGroup ? 'Edit Group' : 'Create Group'}</DialogTitle>
            <DialogDescription>
              Group printers so fleet redirects stay organized and easy to manage.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            {error && <div className="rounded-lg bg-error-bg p-3 text-sm text-error">{error}</div>}
            <div className="space-y-2">
              <label className="text-sm font-medium">Group name</label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="North Wing" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Description</label>
              <Textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Printers serving the north wing floor"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowGroupModal(false)}>
              Cancel
            </Button>
            <Button onClick={handleSaveGroup} disabled={createMutation.isPending || updateMutation.isPending}>
              {(createMutation.isPending || updateMutation.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              )}
              {editingGroup ? 'Save changes' : 'Create group'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showMembersModal} onOpenChange={setShowMembersModal}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>Manage printers</DialogTitle>
            <DialogDescription>
              {managingGroup ? `Assign printers to ${managingGroup.name}.` : 'Assign printers to this group.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            {membersLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
              </div>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2">
                {(printers || []).map((printerStatus) => {
                  const assignedGroup = printerStatus.group;
                  const isSelected = selectedPrinters.includes(printerStatus.printer.id);
                  return (
                    <label
                      key={printerStatus.printer.id}
                      className="flex items-start gap-3 rounded-lg border border-border p-3 text-sm"
                    >
                      <Checkbox
                        checked={isSelected}
                        onCheckedChange={() => togglePrinter(printerStatus.printer.id)}
                      />
                      <div className="flex-1">
                        <div className="font-medium">{printerStatus.printer.name}</div>
                        <div className="text-xs text-muted-foreground font-mono">
                          {printerStatus.printer.ip}
                        </div>
                        {assignedGroup && assignedGroup.id !== managingGroup?.id && (
                          <Badge variant="secondary" className="mt-2">
                            In {assignedGroup.name}
                          </Badge>
                        )}
                      </div>
                    </label>
                  );
                })}
                {(printers || []).length === 0 && (
                  <div className="text-sm text-muted-foreground">No printers available.</div>
                )}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowMembersModal(false)}>
              Cancel
            </Button>
            <Button onClick={handleSaveMembers} disabled={membersMutation.isPending || !managingGroup}>
              {membersMutation.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              )}
              Save assignments
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

    </div>
  );
}

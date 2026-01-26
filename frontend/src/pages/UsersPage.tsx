import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { usersApi } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Loader2, Pencil, Trash2 } from 'lucide-react';
import { useDocumentTitle } from '@/hooks/use-document-title';
import type { User } from '@/types/api';

export function UsersPage() {
  useDocumentTitle('Users');
  const queryClient = useQueryClient();
  const { user: currentUser } = useAuth();
  const [isUserModalOpen, setIsUserModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'add' | 'edit'>('add');
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    role: 'viewer' as 'admin' | 'operator' | 'viewer',
    is_active: true,
  });
  const [error, setError] = useState('');

  const { data: users, isLoading } = useQuery<User[]>({
    queryKey: ['users'],
    queryFn: usersApi.getAll,
  });

  const createMutation = useMutation({
    mutationFn: usersApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setIsUserModalOpen(false);
      setEditingUser(null);
      resetForm();
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setError(axiosError.response?.data?.error || 'Failed to create user');
      }
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<User & { password?: string }> }) =>
      usersApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setIsUserModalOpen(false);
      setEditingUser(null);
      resetForm();
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setError(axiosError.response?.data?.error || 'Failed to update user');
      }
    },
  });

  const deleteMutation = useMutation({
    mutationFn: usersApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });

  const resetForm = () => {
    setFormData({ username: '', password: '', role: 'viewer', is_active: true });
    setError('');
  };

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    createMutation.mutate(formData);
  };

  const handleUpdate = (id: number) => {
    setError('');
    const data: Partial<User & { password?: string }> = {
      role: formData.role,
      is_active: formData.is_active,
    };
    if (formData.password) {
      data.password = formData.password;
    }
    updateMutation.mutate({ id, data });
  };

  const handleDelete = (id: number, username: string) => {
    if (confirm(`Are you sure you want to delete "${username}"?`)) {
      deleteMutation.mutate(id);
    }
  };

  const openAddModal = () => {
    setModalMode('add');
    setEditingUser(null);
    resetForm();
    setIsUserModalOpen(true);
  };

  const openEditModal = (user: User) => {
    setModalMode('edit');
    setEditingUser(user);
    setFormData({
      username: user.username,
      password: '',
      role: user.role,
      is_active: user.is_active,
    });
    setError('');
    setIsUserModalOpen(true);
  };

  const getRoleBadgeVariant = (role: string) => {
    switch (role) {
      case 'admin':
        return 'default';
      case 'operator':
        return 'info';
      default:
        return 'secondary';
    }
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
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">Users</h1>
          <p className="text-muted-foreground">Manage user accounts and permissions</p>
        </div>
        <Button onClick={openAddModal}>Add User</Button>
      </div>

      <Dialog open={isUserModalOpen} onOpenChange={setIsUserModalOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{modalMode === 'add' ? 'Add User' : 'Edit User'}</DialogTitle>
            <DialogDescription>
              {modalMode === 'add'
                ? 'Create a new user account with the appropriate role.'
                : 'Update role and access settings for this user.'}
            </DialogDescription>
          </DialogHeader>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              if (modalMode === 'add') {
                handleAdd(event);
              } else if (editingUser) {
                handleUpdate(editingUser.id);
              }
            }}
            className="space-y-4"
          >
            {error && (
              <div className="rounded-lg bg-error-bg p-3 text-sm text-error">{error}</div>
            )}

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  disabled={modalMode === 'edit'}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  required={modalMode === 'add'}
                />
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="role">Role</Label>
                <select
                  id="role"
                  className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
                  value={formData.role}
                  onChange={(e) =>
                    setFormData({ ...formData, role: e.target.value as 'admin' | 'operator' | 'viewer' })
                  }
                >
                  <option value="viewer">Viewer</option>
                  <option value="operator">Operator</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  checked={formData.is_active}
                  onCheckedChange={(value) =>
                    setFormData({ ...formData, is_active: value === true })
                  }
                />
                <Label>Active</Label>
              </div>
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setIsUserModalOpen(false);
                  setEditingUser(null);
                  resetForm();
                }}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending || updateMutation.isPending}>
                {createMutation.isPending || updateMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  'Save'
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Users table */}
      <Card className="gap-0 py-0">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="px-4">User</TableHead>
                <TableHead className="px-4">Role</TableHead>
                <TableHead className="px-4">Status</TableHead>
                <TableHead className="px-4">Last Login</TableHead>
                <TableHead className="px-4 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users?.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="px-4">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary">
                        {user.username.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <p className="font-medium">{user.username}</p>
                        {user.id === currentUser?.id && (
                          <p className="text-xs text-muted-foreground">You</p>
                        )}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="px-4">
                    <Badge variant={getRoleBadgeVariant(user.role)} className="capitalize">
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell className="px-4">
                    <Badge variant={user.is_active ? 'success' : 'secondary'}>
                      {user.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </TableCell>
                  <TableCell className="px-4 text-muted-foreground">
                    {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
                  </TableCell>
                  <TableCell className="px-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Edit ${user.username}`}
                        onClick={() => openEditModal(user)}
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      {user.id !== currentUser?.id && (
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Delete ${user.username}`}
                          onClick={() => handleDelete(user.id, user.username)}
                          disabled={deleteMutation.isPending}
                          className="delete-action"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

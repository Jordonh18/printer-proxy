import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { workflowApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { toast } from '@/lib/toast';
import { useAuth } from '@/contexts/AuthContext';
import type { Workflow } from '@/types/api';

export function WorkflowsPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canEdit = user?.role !== 'viewer';
  const { data: workflows = [], isLoading } = useQuery({
    queryKey: ['workflows'],
    queryFn: workflowApi.getAll,
  });

  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [isCreating, setIsCreating] = useState(false);

  const sorted = useMemo(() => {
    return [...workflows].sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''));
  }, [workflows]);

  const handleCreate = async () => {
    if (!name.trim()) {
      toast.error('Workflow name is required');
      return;
    }
    try {
      setIsCreating(true);
      const workflow = await workflowApi.create({ name: name.trim(), description: description.trim() });
      toast.success('Workflow created');
      setIsDialogOpen(false);
      setName('');
      setDescription('');
      navigate(`/workflows/${workflow.id}`);
    } catch (error) {
      toast.error('Failed to create workflow', error instanceof Error ? error.message : undefined);
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Workflows</h1>
          <p className="text-sm text-muted-foreground">
            Build automation flows for printers, queues, and integrations.
          </p>
        </div>
        {canEdit && (
          <Button onClick={() => setIsDialogOpen(true)}>New Workflow</Button>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {isLoading && (
          <Card>
            <CardContent className="py-8 text-sm text-muted-foreground">Loading workflows...</CardContent>
          </Card>
        )}
        {!isLoading && sorted.length === 0 && (
          <Card>
            <CardContent className="py-8 text-sm text-muted-foreground">
              No workflows yet. Create one to start building automated printer flows.
            </CardContent>
          </Card>
        )}
        {sorted.map((workflow: Workflow) => (
          <Card key={workflow.id} className="cursor-pointer transition hover:border-primary/40" onClick={() => navigate(`/workflows/${workflow.id}`)}>
            <CardHeader className="space-y-2">
              <div className="flex items-center justify-between">
                <CardTitle>{workflow.name}</CardTitle>
                <Badge variant={workflow.is_active ? 'default' : 'secondary'}>
                  {workflow.is_active ? 'Active' : 'Paused'}
                </Badge>
              </div>
              <p className="text-sm text-muted-foreground">
                {workflow.description || 'No description provided.'}
              </p>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              Updated {workflow.updated_at ? new Date(workflow.updated_at).toLocaleString() : '—'}
            </CardContent>
          </Card>
        ))}
      </div>

      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>New Workflow</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Name</label>
              <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Printer fallback flow" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Description</label>
              <Textarea value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Describe what this workflow does" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={isCreating}>
              {isCreating ? 'Creating...' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

import { useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { workflowApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { toast } from '@/lib/toast';
import { useAuth } from '@/contexts/AuthContext';
import type { Workflow } from '@/types/api';
import { Trash2 } from 'lucide-react';

export function WorkflowsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
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
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [workflowToDelete, setWorkflowToDelete] = useState<Workflow | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);

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

  const handleToggleActive = async (workflow: Workflow, checked: boolean) => {
    if (!canEdit) return;
    
    console.log(`Toggling workflow ${workflow.id} (${workflow.name}) to ${checked ? 'active' : 'inactive'}`);
    
    try {
      setTogglingId(workflow.id);
      // Update backend first
      const updatedWorkflow = await workflowApi.update(workflow.id, { is_active: checked });
      
      console.log(`Backend returned is_active: ${updatedWorkflow.is_active}`);
      
      // Verify the update succeeded
      if (updatedWorkflow.is_active !== checked) {
        throw new Error('Backend did not apply the change');
      }
      
      toast.success(checked ? 'Workflow activated' : 'Workflow deactivated');
      
      // Refresh the list to ensure UI matches backend state
      queryClient.invalidateQueries({ queryKey: ['workflows'] });
    } catch (error) {
      console.error('Failed to toggle workflow:', error);
      toast.error('Failed to update workflow', error instanceof Error ? error.message : undefined);
      // Refresh to revert the optimistic update
      queryClient.invalidateQueries({ queryKey: ['workflows'] });
    } finally {
      setTogglingId(null);
    }
  };

  const handleDeleteClick = (workflow: Workflow, event: React.MouseEvent) => {
    event.stopPropagation();
    setWorkflowToDelete(workflow);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    if (!workflowToDelete) return;
    
    try {
      setIsDeleting(true);
      await workflowApi.delete(workflowToDelete.id);
      toast.success('Workflow deleted');
      queryClient.invalidateQueries({ queryKey: ['workflows'] });
      setDeleteDialogOpen(false);
      setWorkflowToDelete(null);
    } catch (error) {
      toast.error('Failed to delete workflow', error instanceof Error ? error.message : undefined);
    } finally {
      setIsDeleting(false);
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

      {isLoading ? (
        <div className="flex h-64 items-center justify-center">
          <div className="text-sm text-muted-foreground">Loading workflows...</div>
        </div>
      ) : sorted.length === 0 ? (
        <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
          <div className="relative">
            <div className="absolute inset-0 -z-10 h-48 w-48 rounded-full bg-primary/5 blur-2xl" />
            <svg
              className="h-40 w-40 text-primary"
              viewBox="0 0 200 200"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <circle cx="50" cy="50" r="12" className="fill-primary/20" />
              <circle cx="100" cy="50" r="12" className="fill-primary/20" />
              <circle cx="150" cy="50" r="12" className="fill-primary/20" />
              <circle cx="100" cy="120" r="12" className="fill-primary/20" />
              <path d="M50 50 L100 120" className="stroke-primary/30" strokeWidth="3" />
              <path d="M150 50 L100 120" className="stroke-primary/30" strokeWidth="3" />
              <path d="M100 50 L100 120" className="stroke-primary/30" strokeWidth="3" />
              <circle cx="100" cy="180" r="8" className="fill-primary/15" />
              <path d="M100 132 L100 180" className="stroke-primary/25" strokeWidth="3" strokeDasharray="4 4" />
            </svg>
          </div>
          <h3 className="mt-6 text-2xl font-semibold">Workflows are standing by</h3>
          <p className="mt-3 max-w-xl text-sm text-muted-foreground">
            Create a workflow to automate printer operations, send notifications, and integrate with external systems.
          </p>
          {canEdit && (
            <div className="mt-6">
              <Button onClick={() => setIsDialogOpen(true)}>New Workflow</Button>
            </div>
          )}
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {sorted.map((workflow: Workflow) => (
          <Card key={workflow.id} className="cursor-pointer transition hover:border-primary/40" onClick={() => navigate(`/workflows/${workflow.id}`)}>
            <CardHeader className="space-y-2">
              <div className="flex items-center justify-between gap-3">
                <CardTitle className="flex-1">{workflow.name}</CardTitle>
                {canEdit && (
                  <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                    <Switch
                      checked={workflow.is_active}
                      onCheckedChange={(checked) => handleToggleActive(workflow, checked)}
                      disabled={togglingId === workflow.id}
                      title={workflow.is_active ? 'Deactivate workflow' : 'Activate workflow'}
                    />
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7 text-destructive hover:text-destructive"
                      onClick={(e) => handleDeleteClick(workflow, e)}
                      title="Delete workflow"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                )}
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
      )}

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

      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Workflow</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{workflowToDelete?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDeleteConfirm} disabled={isDeleting} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
              {isDeleting ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

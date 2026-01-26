import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { printersApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ArrowLeft, Loader2, Save } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { PrinterStatus } from '@/types/api';

export function PrinterFormPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const isEdit = !!id;

  const [formData, setFormData] = useState({
    name: '',
    ip: '',
    location: '',
    model: '',
  });
  const [error, setError] = useState('');

  // Fetch existing printer data for edit mode
  const { isLoading: isLoadingPrinter } = useQuery<PrinterStatus>({
    queryKey: ['printer', id],
    queryFn: () => printersApi.getById(id!),
    enabled: isEdit,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onSuccess: (data: any) => {
      setFormData({
        name: data.printer.name,
        ip: data.printer.ip,
        location: data.printer.location || '',
        model: data.printer.model || '',
      });
    },
  } as never);

  const createMutation = useMutation({
    mutationFn: printersApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      navigate('/printers');
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setError(axiosError.response?.data?.error || 'Failed to create printer');
      }
    },
  });

  const updateMutation = useMutation({
    mutationFn: (data: typeof formData) => printersApi.update(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['printers'] });
      queryClient.invalidateQueries({ queryKey: ['printer', id] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      navigate(`/printers/${id}`);
    },
    onError: (err: unknown) => {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setError(axiosError.response?.data?.error || 'Failed to update printer');
      }
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!formData.name.trim() || !formData.ip.trim()) {
      setError('Name and IP address are required');
      return;
    }

    if (isEdit) {
      updateMutation.mutate(formData);
    } else {
      createMutation.mutate(formData);
    }
  };

  const isLoading = createMutation.isPending || updateMutation.isPending;

  if (isEdit && isLoadingPrinter) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link to={isEdit ? `/printers/${id}` : '/printers'}>
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-5 w-5" />
          </Button>
        </Link>
        <div>
          <h1 className="text-2xl font-bold">{isEdit ? 'Edit Printer' : 'Add Printer'}</h1>
          <p className="text-muted-foreground">
            {isEdit ? 'Update printer details' : 'Configure a new printer to monitor'}
          </p>
        </div>
      </div>

      {/* Form */}
      <Card>
        <CardHeader>
          <CardTitle>Printer Details</CardTitle>
          <CardDescription>
            Enter the network details for your printer
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="rounded-lg bg-error-bg p-3 text-sm text-error">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="name">Name *</Label>
              <Input
                id="name"
                placeholder="e.g., Office Printer 1"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="ip">IP Address *</Label>
              <Input
                id="ip"
                placeholder="e.g., 192.168.1.100"
                value={formData.ip}
                onChange={(e) => setFormData({ ...formData, ip: e.target.value })}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="location">Location</Label>
              <Input
                id="location"
                placeholder="e.g., Building A, Floor 2"
                value={formData.location}
                onChange={(e) => setFormData({ ...formData, location: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="model">Model</Label>
              <Input
                id="model"
                placeholder="e.g., HP LaserJet Pro M404"
                value={formData.model}
                onChange={(e) => setFormData({ ...formData, model: e.target.value })}
              />
            </div>

            <div className="flex gap-3 pt-4">
              <Button type="submit" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {isEdit ? 'Updating...' : 'Creating...'}
                  </>
                ) : (
                  <>
                    <Save className="h-4 w-4" />
                    {isEdit ? 'Update Printer' : 'Add Printer'}
                  </>
                )}
              </Button>
              <Link to={isEdit ? `/printers/${id}` : '/printers'}>
                <Button type="button" variant="outline">
                  Cancel
                </Button>
              </Link>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

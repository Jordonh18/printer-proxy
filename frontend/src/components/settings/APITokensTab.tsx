import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiTokensApi } from '@/lib/api';
import type { APIToken, TokenPermissions } from '@/types/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Loader2, Key, Trash2, Copy, Check } from 'lucide-react';
import { useState } from 'react';

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);
  
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} ${hours === 1 ? 'hour' : 'hours'} ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} ${days === 1 ? 'day' : 'days'} ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months} ${months === 1 ? 'month' : 'months'} ago`;
  const years = Math.floor(months / 12);
  return `${years} ${years === 1 ? 'year' : 'years'} ago`;
}

export function APITokensTab() {
  const queryClient = useQueryClient();
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showTokenDialog, setShowTokenDialog] = useState(false);
  const [deleteTokenId, setDeleteTokenId] = useState<number | null>(null);
  const [newToken, setNewToken] = useState<string>('');
  const [copied, setCopied] = useState(false);
  
  const [tokenForm, setTokenForm] = useState({
    name: '',
    permissions: [] as string[],
    expires_in_days: 'never',
  });

  const { data: tokensData, isLoading } = useQuery({
    queryKey: ['api-tokens'],
    queryFn: apiTokensApi.list,
  });

  const { data: permissionsData } = useQuery<TokenPermissions>({
    queryKey: ['api-token-permissions'],
    queryFn: apiTokensApi.getPermissions,
  });

  const createMutation = useMutation({
    mutationFn: apiTokensApi.create,
    onSuccess: (data) => {
      setNewToken(data.token.token);
      setShowCreateDialog(false);
      setShowTokenDialog(true);
      setTokenForm({ name: '', permissions: [], expires_in_days: 'never' });
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: apiTokensApi.delete,
    onSuccess: () => {
      setDeleteTokenId(null);
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
    },
  });

  const handleCopyToken = () => {
    if (newToken) {
      navigator.clipboard.writeText(newToken);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleCreateToken = () => {
    if (!tokenForm.name || tokenForm.permissions.length === 0) return;
    
    createMutation.mutate({
      name: tokenForm.name,
      permissions: tokenForm.permissions,
      expires_in_days: tokenForm.expires_in_days && tokenForm.expires_in_days !== 'never' 
        ? parseInt(tokenForm.expires_in_days) 
        : undefined,
    });
  };

  const togglePermission = (perm: string) => {
    setTokenForm(prev => ({
      ...prev,
      permissions: prev.permissions.includes(perm)
        ? prev.permissions.filter(p => p !== perm)
        : [...prev.permissions, perm],
    }));
  };

  const tokens = tokensData?.tokens || [];
  const grouped = permissionsData?.grouped || {};

  return (
    <>
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <div className="flex items-start justify-between">
              <div>
                <CardTitle>API Tokens</CardTitle>
                <CardDescription>
                  Create tokens for programmatic access to the API. Each token can have granular permissions based on your role.
                </CardDescription>
              </div>
              <Button onClick={() => setShowCreateDialog(true)}>
                <Key className="h-4 w-4" />
                Create Token
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : tokens.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Key className="h-12 w-12 mx-auto mb-4 opacity-20" />
                <p>No API tokens yet</p>
                <p className="text-sm">Create a token to get started with API access</p>
              </div>
            ) : (
              <div className="space-y-3">
                {tokens.map((token: APIToken) => (
                  <div
                    key={token.id}
                    className="flex items-center justify-between rounded-lg border border-border px-4 py-3"
                  >
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium">{token.name}</p>
                        {token.expires_at && new Date(token.expires_at) < new Date() && (
                          <Badge variant="destructive" className="text-xs">Expired</Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                        {token.last_used_at ? (
                          <span>Last used {formatTimeAgo(token.last_used_at)}</span>
                        ) : (
                          <span>Never used</span>
                        )}
                        {token.expires_at && (
                          <span>Expires {formatTimeAgo(token.expires_at)}</span>
                        )}
                        <span>{token.permissions.length} {token.permissions.length === 1 ? 'permission' : 'permissions'}</span>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setDeleteTokenId(token.id)}
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Create Token Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create API Token</DialogTitle>
            <DialogDescription>
              Choose a name and select the permissions for this token. Permissions are limited to those available to your role.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="token-name">Token Name</Label>
              <Input
                id="token-name"
                placeholder="e.g., CI/CD Pipeline, Monitoring Script"
                value={tokenForm.name}
                onChange={(e) => setTokenForm({ ...tokenForm, name: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="expires">Expiration (optional)</Label>
              <Select
                value={tokenForm.expires_in_days}
                onValueChange={(value) => setTokenForm({ ...tokenForm, expires_in_days: value })}
              >
                <SelectTrigger id="expires">
                  <SelectValue placeholder="No expiration" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="never">No expiration</SelectItem>
                  <SelectItem value="7">7 days</SelectItem>
                  <SelectItem value="30">30 days</SelectItem>
                  <SelectItem value="90">90 days</SelectItem>
                  <SelectItem value="365">1 year</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-3">
              <Label>Permissions</Label>
              <div className="rounded-lg border p-4 space-y-4 max-h-[300px] overflow-y-auto">
                {Object.entries(grouped).map(([resource, actions]) => (
                  <div key={resource} className="space-y-2">
                    <p className="text-sm font-medium capitalize">{resource}</p>
                    <div className="space-y-2 pl-4">
                      {(actions as string[]).map((action) => {
                        const perm = `${resource}:${action}`;
                        return (
                          <div key={perm} className="flex items-center gap-2">
                            <Checkbox
                              id={perm}
                              checked={tokenForm.permissions.includes(perm)}
                              onCheckedChange={() => togglePermission(perm)}
                            />
                            <Label htmlFor={perm} className="text-sm font-normal cursor-pointer">
                              {action}
                            </Label>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
              {tokenForm.permissions.length === 0 && (
                <p className="text-sm text-destructive">At least one permission is required</p>
              )}
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreateToken}
              disabled={!tokenForm.name || tokenForm.permissions.length === 0 || createMutation.isPending}
            >
              {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Create Token
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Show Token Dialog */}
      <Dialog open={showTokenDialog} onOpenChange={(open) => {
        if (!open) {
          setShowTokenDialog(false);
          setNewToken('');
          setCopied(false);
        }
      }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Token Created Successfully</DialogTitle>
            <DialogDescription>
              Save this token now - you won't be able to see it again!
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="rounded-lg bg-muted p-4 font-mono text-sm break-all">
              {newToken}
            </div>
            <Button onClick={handleCopyToken} className="w-full">
              {copied ? (
                <>
                  <Check className="h-4 w-4" />
                  Copied!
                </>
              ) : (
                <>
                  <Copy className="h-4 w-4" />
                  Copy Token
                </>
              )}
            </Button>
          </div>

          <DialogFooter>
            <Button onClick={() => {
              setShowTokenDialog(false);
              setNewToken('');
              setCopied(false);
            }}>
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={deleteTokenId !== null} onOpenChange={() => setDeleteTokenId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete API Token?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. Applications using this token will lose access immediately.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (deleteTokenId) {
                  deleteMutation.mutate(deleteTokenId);
                }
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

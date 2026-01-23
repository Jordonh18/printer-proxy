import { useQuery } from '@tanstack/react-query';
import { appApi, updateApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useTranslation } from 'react-i18next';
import {
  Download,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { useState } from 'react';
import { useDocumentTitle } from '@/hooks/use-document-title';
import type { AppInfo } from '@/types/api';
import { toast } from '@/lib/toast';

export function AdminGeneralPage() {
  useDocumentTitle('General Settings');
  const { t } = useTranslation();
  const [isCheckingUpdate, setIsCheckingUpdate] = useState(false);

  const { data: appInfo } = useQuery<AppInfo>({
    queryKey: ['app', 'info'],
    queryFn: appApi.getInfo,
  });

  const { data: updateStatus, refetch: refetchUpdate } = useQuery({
    queryKey: ['update', 'status'],
    queryFn: updateApi.getStatus,
    refetchInterval: 10000,
  });

  const handleCheckUpdate = async () => {
    setIsCheckingUpdate(true);
    try {
      const result = await updateApi.check();
      if (result.update_available) {
        toast.info('Update Available', `Version ${result.available_version} is available`);
      } else {
        toast.success('Up to Date', 'You are running the latest version');
      }
      refetchUpdate();
    } catch {
      toast.error('Update Check Failed', 'Failed to check for updates');
    } finally {
      setIsCheckingUpdate(false);
    }
  };

  const handleStartUpdate = async () => {
    if (confirm('Are you sure you want to start the update? The application will restart.')) {
      try {
        await updateApi.start();
        toast.info('Update Started', 'Application will restart shortly');
        refetchUpdate();
      } catch {
        toast.error('Update Failed', 'Failed to start update');
      }
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">General Settings</h1>
        <p className="text-muted-foreground">
          Manage application information and updates
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>{t('application')}</CardTitle>
            <CardDescription>{t('applicationDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Application</span>
              <span className="font-medium">{appInfo?.app_name || 'Printer Proxy'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Version</span>
              <Badge variant="outline">{appInfo?.version_string || 'Loading...'}</Badge>
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>{t('updates')}</CardTitle>
            <CardDescription>{t('updatesDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">{t('currentVersion')}</span>
              <span className="font-medium">{appInfo?.version || '—'}</span>
            </div>

            {updateStatus?.update_available && (
              <div className="flex items-center gap-2 rounded-lg bg-warning-bg p-3 text-sm">
                <AlertCircle className="h-4 w-4 text-warning" />
                <span>{t('updateAvailable')}: {updateStatus.available_version}</span>
              </div>
            )}

            {updateStatus?.is_updating && (
              <div className="flex items-center gap-2 rounded-lg bg-info-bg p-3 text-sm">
                <Loader2 className="h-4 w-4 animate-spin text-info" />
                <span>{t('updateInProgress')}</span>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                onClick={handleCheckUpdate}
                disabled={isCheckingUpdate || updateStatus?.is_updating}
              >
                {isCheckingUpdate ? <Loader2 className="h-4 w-4 animate-spin" /> : t('checkUpdates')}
              </Button>

              {updateStatus?.update_available && !updateStatus?.is_updating && (
                <Button onClick={handleStartUpdate}>
                  <Download className="h-4 w-4" />
                  {t('installUpdate')}
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

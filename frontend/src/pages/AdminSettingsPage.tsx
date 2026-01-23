import { useQuery } from '@tanstack/react-query';
import { appApi, updateApi, adminApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardAction } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { useTranslation } from 'react-i18next';
import {
  Download,
  AlertCircle,
  Loader2,
  Mail,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/use-document-title';
import type { AppInfo, SmtpSettings } from '@/types/api';
import { toast } from '@/lib/toast';

export function AdminSettingsPage() {
  useDocumentTitle('Admin Settings');
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const activeTab = searchParams.get('tab') || 'general';
  const [isCheckingUpdate, setIsCheckingUpdate] = useState(false);
  const [smtpSettings, setSmtpSettings] = useState<SmtpSettings>({
    enabled: false,
    host: '',
    port: 587,
    username: '',
    password: '',
    from_address: '',
    use_tls: true,
    use_ssl: false,
  });

  const { data: appInfo } = useQuery<AppInfo>({
    queryKey: ['app', 'info'],
    queryFn: appApi.getInfo,
  });

  const { data: updateStatus, refetch: refetchUpdate } = useQuery({
    queryKey: ['update', 'status'],
    queryFn: updateApi.getStatus,
    refetchInterval: 10000,
  });

  const { data: smtpData, refetch: refetchSmtp } = useQuery({
    queryKey: ['admin', 'smtp'],
    queryFn: adminApi.getSmtp,
  });

  useEffect(() => {
    if (smtpData?.settings) {
      setSmtpSettings({
        enabled: !!smtpData.settings.enabled,
        host: smtpData.settings.host || '',
        port: smtpData.settings.port || 587,
        username: smtpData.settings.username || '',
        password: smtpData.settings.password === '********' ? '' : (smtpData.settings.password || ''),
        from_address: smtpData.settings.from_address || '',
        use_tls: smtpData.settings.use_tls ?? true,
        use_ssl: smtpData.settings.use_ssl ?? false,
      });
    }
  }, [smtpData]);

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

  const handleSaveSmtp = async () => {
    try {
      await adminApi.updateSmtp(smtpSettings);
      toast.success('Settings Saved', 'SMTP settings have been updated');
      refetchSmtp();
    } catch {
      toast.error('Save Failed', 'Failed to save SMTP settings');
    }
  };

  const handleTestSmtp = async () => {
    try {
      const result = await adminApi.testSmtp(smtpSettings);
      if (result.success) {
        toast.success('Test Email Sent', result.message || 'Check your inbox for the test email');
      } else {
        toast.error('Test Failed', result.error || 'Failed to send test email');
      }
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        toast.error('Test Failed', axiosError.response?.data?.error || 'Failed to send test email');
      } else {
        toast.error('Test Failed', 'Failed to send test email');
      }
    }
  };

  const smtpRequiredFields = [
    smtpSettings.host.trim(),
    smtpSettings.port,
    smtpSettings.from_address.trim(),
  ];
  const isSmtpComplete = smtpRequiredFields.every((value) => !!value);
  const smtpSaveDisabled = smtpSettings.enabled && !isSmtpComplete;

  const tabMeta: Record<string, { title: string; description: string }> = {
    general: {
      title: 'General',
      description: 'Application information and updates',
    },
    notifications: {
      title: 'Notifications',
      description: 'Configure notification channels and settings',
    },
    integrations: {
      title: 'Integrations',
      description: 'Connect third-party services',
    },
  };

  const activeMeta = tabMeta[activeTab] ?? tabMeta.general;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">{activeMeta.title}</h1>
        <p className="text-muted-foreground">
          {activeMeta.description}
        </p>
      </div>

      {activeTab === 'general' && (
        <div className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-3">
            <Card className="lg:col-span-1">
              <CardHeader>
                <CardTitle>{t('application')}</CardTitle>
                <CardDescription>{t('applicationDesc')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Application</span>
                  <span className="font-medium">{appInfo?.app_name || 'Continuum'}</span>
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
      )}

      {activeTab === 'notifications' && (
        <div className="space-y-6">
          <Card className={!smtpSettings.enabled ? 'opacity-60' : undefined}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Mail className="h-5 w-5" />
                SMTP Server Configuration
              </CardTitle>
              <CardDescription>
                Configure the email server used to send notifications to users. Each user receives emails at their configured account email address.
              </CardDescription>
              <CardAction>
                <Switch
                  checked={smtpSettings.enabled}
                  onCheckedChange={(value) =>
                    setSmtpSettings({ ...smtpSettings, enabled: value })
                  }
                  className="data-checked:bg-[var(--switch-on)]"
                  style={{ ['--switch-on' as never]: 'oklch(0.72 0.19 145)' }}
                />
              </CardAction>
            </CardHeader>
            <AnimatePresence initial={false}>
              {smtpSettings.enabled && (
                <motion.div
                  key="smtp-settings"
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.25, ease: 'easeOut' }}
                  className="overflow-hidden"
                >
                  <CardContent className="space-y-6">
                    <div className="grid gap-4 lg:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="smtp-host">
                          {t('smtpHost')} <span className="text-error">*</span>
                        </Label>
                        <Input
                          id="smtp-host"
                          value={smtpSettings.host}
                          onChange={(e) => setSmtpSettings({ ...smtpSettings, host: e.target.value })}
                          placeholder="smtp.gmail.com"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="smtp-port">
                          {t('smtpPort')} <span className="text-error">*</span>
                        </Label>
                        <Input
                          id="smtp-port"
                          type="number"
                          value={smtpSettings.port}
                          onChange={(e) => setSmtpSettings({ ...smtpSettings, port: Number(e.target.value) })}
                        />
                      </div>
                    </div>

                    <div className="grid gap-4 lg:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="smtp-username">{t('smtpUsername')}</Label>
                        <Input
                          id="smtp-username"
                          value={smtpSettings.username}
                          onChange={(e) => setSmtpSettings({ ...smtpSettings, username: e.target.value })}
                          placeholder="your-email@company.com"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="smtp-password">{t('smtpPassword')}</Label>
                        <Input
                          id="smtp-password"
                          type="password"
                          value={smtpSettings.password}
                          onChange={(e) => setSmtpSettings({ ...smtpSettings, password: e.target.value })}
                          placeholder={smtpSettings.password === '********' ? '********' : ''}
                        />
                      </div>
                    </div>

                    <Separator />

                    <div className="space-y-2">
                      <Label htmlFor="smtp-from">
                        {t('smtpFrom')} <span className="text-error">*</span>
                      </Label>
                      <Input
                        id="smtp-from"
                        value={smtpSettings.from_address}
                        onChange={(e) => setSmtpSettings({ ...smtpSettings, from_address: e.target.value })}
                        placeholder="noreply@company.com"
                      />
                      <p className="text-xs text-muted-foreground">
                        The email address that notifications will be sent from
                      </p>
                    </div>

                    <Separator />

                    <div className="flex flex-wrap items-center gap-6">
                      <div className="flex items-center gap-2">
                        <Checkbox
                          checked={smtpSettings.use_tls}
                          onCheckedChange={(value) =>
                            setSmtpSettings({ ...smtpSettings, use_tls: value === true })
                          }
                        />
                        <Label>{t('useTls')}</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Checkbox
                          checked={smtpSettings.use_ssl}
                          onCheckedChange={(value) =>
                            setSmtpSettings({ ...smtpSettings, use_ssl: value === true })
                          }
                        />
                        <Label>{t('useSsl')}</Label>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <Button onClick={handleSaveSmtp} disabled={smtpSaveDisabled}>
                        {t('saveSettings')}
                      </Button>
                      <Button variant="outline" onClick={handleTestSmtp} disabled={!isSmtpComplete}>
                        Send Test Email
                      </Button>
                    </div>
                  </CardContent>
                </motion.div>
              )}
            </AnimatePresence>
          </Card>
        </div>
      )}

      {activeTab === 'integrations' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Integrations</CardTitle>
              <CardDescription>
                Third-party service integrations will be available in a future release
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-center py-12">
                <div className="text-center space-y-3">
                  <div className="text-6xl">🚧</div>
                  <h3 className="text-lg font-semibold">Coming Soon</h3>
                  <p className="text-sm text-muted-foreground max-w-md">
                    Integration features are currently under development and will be available in an upcoming update.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

import { useQuery } from '@tanstack/react-query';
import { adminApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardAction } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { useTranslation } from 'react-i18next';
import { Mail } from 'lucide-react';
import { useState, useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { useDocumentTitle } from '@/hooks/use-document-title';
import type { SmtpSettings } from '@/types/api';
import { toast } from '@/lib/toast';

export function AdminNotificationsPage() {
  useDocumentTitle('Notification Settings');
  const { t } = useTranslation();
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

  const { data: smtpData, refetch: refetchSmtp } = useQuery({
    queryKey: ['admin', 'smtp'],
    queryFn: adminApi.getSmtp,
  });

  useEffect(() => {
    if (smtpData?.settings) {
      const settings = smtpData.settings;
      setSmtpSettings(prev => ({
        ...prev,
        enabled: !!settings.enabled,
        host: settings.host || '',
        port: settings.port || 587,
        username: settings.username || '',
        password: settings.password === '********' ? '' : (settings.password || ''),
        from_address: settings.from_address || '',
        use_tls: settings.use_tls ?? true,
        use_ssl: settings.use_ssl ?? false,
      }));
    }
  }, [smtpData]);

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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Notification Settings</h1>
        <p className="text-muted-foreground">
          Configure notification channels and settings
        </p>
      </div>

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
  );
}

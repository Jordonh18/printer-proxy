import { useQuery } from '@tanstack/react-query';
import { appApi, updateApi, settingsApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Separator } from '@/components/ui/separator';
import {
  Settings as SettingsIcon,
  Download,
  CheckCircle,
  AlertCircle,
  Loader2,
  RefreshCw,
  Mail,
  Send,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import type { AppInfo, SmtpSettings } from '@/types/api';

export function SettingsPage() {
  const [isCheckingUpdate, setIsCheckingUpdate] = useState(false);
  const [updateMessage, setUpdateMessage] = useState('');
  const [smtpMessage, setSmtpMessage] = useState('');
  const [smtpSettings, setSmtpSettings] = useState<SmtpSettings>({
    enabled: false,
    host: '',
    port: 587,
    username: '',
    password: '',
    from_address: '',
    to_addresses: '',
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
    queryKey: ['settings', 'smtp'],
    queryFn: settingsApi.getSmtp,
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
        to_addresses: smtpData.settings.to_addresses || '',
        use_tls: smtpData.settings.use_tls ?? true,
        use_ssl: smtpData.settings.use_ssl ?? false,
      });
    }
  }, [smtpData]);

  const handleCheckUpdate = async () => {
    setIsCheckingUpdate(true);
    setUpdateMessage('');
    try {
      const result = await updateApi.check();
      if (result.update_available) {
        setUpdateMessage(`Update available: ${result.available_version}`);
      } else {
        setUpdateMessage('You are running the latest version.');
      }
      refetchUpdate();
    } catch {
      setUpdateMessage('Failed to check for updates.');
    } finally {
      setIsCheckingUpdate(false);
    }
  };

  const handleStartUpdate = async () => {
    if (confirm('Are you sure you want to start the update? The application will restart.')) {
      try {
        await updateApi.start();
        refetchUpdate();
      } catch {
        setUpdateMessage('Failed to start update.');
      }
    }
  };

  const handleSaveSmtp = async () => {
    setSmtpMessage('');
    try {
      await settingsApi.updateSmtp(smtpSettings);
      setSmtpMessage('SMTP settings saved.');
      refetchSmtp();
    } catch {
      setSmtpMessage('Failed to save SMTP settings.');
    }
  };

  const handleTestSmtp = async () => {
    setSmtpMessage('');
    try {
      const result = await settingsApi.testSmtp();
      if (result.success) {
        setSmtpMessage(result.message || 'Test email sent successfully.');
      } else {
        setSmtpMessage(result.error || 'Failed to send test email.');
      }
    } catch {
      setSmtpMessage('Failed to send test email.');
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-muted-foreground">Manage application settings and notifications</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <SettingsIcon className="h-5 w-5" />
              Application
            </CardTitle>
            <CardDescription>Environment and version details</CardDescription>
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
            <CardTitle className="flex items-center gap-2">
              <Download className="h-5 w-5" />
              Updates
            </CardTitle>
            <CardDescription>Check for and install updates</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Current Version</span>
              <span className="font-medium">{appInfo?.version || '—'}</span>
            </div>

            {updateStatus?.update_available && (
              <div className="flex items-center gap-2 rounded-lg bg-warning-bg p-3 text-sm">
                <AlertCircle className="h-4 w-4 text-warning" />
                <span>New version available: {updateStatus.available_version}</span>
              </div>
            )}

            {updateStatus?.is_updating && (
              <div className="flex items-center gap-2 rounded-lg bg-info-bg p-3 text-sm">
                <Loader2 className="h-4 w-4 animate-spin text-info" />
                <span>Update in progress...</span>
              </div>
            )}

            {updateMessage && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <CheckCircle className="h-4 w-4" />
                {updateMessage}
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                onClick={handleCheckUpdate}
                disabled={isCheckingUpdate || updateStatus?.is_updating}
              >
                {isCheckingUpdate ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
                Check for Updates
              </Button>

              {updateStatus?.update_available && !updateStatus?.is_updating && (
                <Button onClick={handleStartUpdate}>
                  <Download className="h-4 w-4" />
                  Install Update
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" />
            Email Notifications
          </CardTitle>
          <CardDescription>Configure SMTP delivery for alerts and reports</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {smtpMessage && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <CheckCircle className="h-4 w-4" />
              {smtpMessage}
            </div>
          )}

          <div className="flex items-center gap-3">
            <Checkbox
              checked={smtpSettings.enabled}
              onCheckedChange={(value) =>
                setSmtpSettings({ ...smtpSettings, enabled: value === true })
              }
            />
            <div>
              <Label>Enable SMTP notifications</Label>
              <p className="text-sm text-muted-foreground">Send alerts when printers go offline.</p>
            </div>
          </div>

          <Separator />

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="smtp-host">SMTP Host</Label>
              <Input
                id="smtp-host"
                value={smtpSettings.host}
                onChange={(e) => setSmtpSettings({ ...smtpSettings, host: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="smtp-port">SMTP Port</Label>
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
              <Label htmlFor="smtp-username">Username</Label>
              <Input
                id="smtp-username"
                value={smtpSettings.username}
                onChange={(e) => setSmtpSettings({ ...smtpSettings, username: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="smtp-password">Password</Label>
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

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="smtp-from">From Address</Label>
              <Input
                id="smtp-from"
                value={smtpSettings.from_address}
                onChange={(e) => setSmtpSettings({ ...smtpSettings, from_address: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="smtp-to">To Addresses</Label>
              <Input
                id="smtp-to"
                value={smtpSettings.to_addresses}
                onChange={(e) => setSmtpSettings({ ...smtpSettings, to_addresses: e.target.value })}
                placeholder="comma-separated"
              />
            </div>
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
              <Label>Use TLS</Label>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox
                checked={smtpSettings.use_ssl}
                onCheckedChange={(value) =>
                  setSmtpSettings({ ...smtpSettings, use_ssl: value === true })
                }
              />
              <Label>Use SSL</Label>
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            <Button onClick={handleSaveSmtp}>Save Settings</Button>
            <Button variant="outline" onClick={handleTestSmtp}>
              <Send className="h-4 w-4" />
              Send Test Email
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

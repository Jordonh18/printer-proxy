import { useQuery } from '@tanstack/react-query';
import { appApi, updateApi, settingsApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardAction } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { QRCodeCanvas } from 'qrcode.react';
import { useTranslation } from 'react-i18next';
import moment from 'moment-timezone';
import {
  Download,
  CheckCircle,
  AlertCircle,
  Loader2,
  Mail,
} from 'lucide-react';
import { useState, useEffect, useMemo } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import i18n from '@/i18n';
import { authApi } from '@/lib/api';
import type { AppInfo, SmtpSettings } from '@/types/api';

export function SettingsPage() {
  const { t } = useTranslation();
  const { user, checkAuth } = useAuth();
  const [searchParams] = useSearchParams();
  const activeTab = searchParams.get('tab') || 'account';
  const [isCheckingUpdate, setIsCheckingUpdate] = useState(false);
  const [updateMessage, setUpdateMessage] = useState('');
  const [smtpMessage, setSmtpMessage] = useState('');
  const [notificationPrefs, setNotificationPrefs] = useState({
    healthAlerts: true,
    offlineAlerts: true,
    jobFailures: true,
    securityEvents: true,
    weeklyReports: false,
  });
  const [accountForm, setAccountForm] = useState({
    username: '',
    email: '',
  });
  const [accountMessage, setAccountMessage] = useState('');
  const [accountError, setAccountError] = useState('');
  const [isSavingAccount, setIsSavingAccount] = useState(false);
  const [preferencesForm, setPreferencesForm] = useState({
    theme: 'system',
    language: 'en',
    timezone: 'UTC',
  });
  const [preferencesMessage, setPreferencesMessage] = useState('');
  const [preferencesError, setPreferencesError] = useState('');
  const [isSavingPreferences, setIsSavingPreferences] = useState(false);
  const [mfaSetupOpen, setMfaSetupOpen] = useState(false);
  const [mfaSetupData, setMfaSetupData] = useState<{ otpauth_uri: string } | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  const [mfaMessage, setMfaMessage] = useState('');
  const timezones = useMemo(() => moment.tz.names(), []);
  const [mfaError, setMfaError] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [recoveryCopied, setRecoveryCopied] = useState(false);
  const [recoveryDownloaded, setRecoveryDownloaded] = useState(false);
  const [disableMfaOpen, setDisableMfaOpen] = useState(false);
  const [disableMfaCode, setDisableMfaCode] = useState('');
  const [resetRecoveryOpen, setResetRecoveryOpen] = useState(false);

  useEffect(() => {
    if (user) {
      setAccountForm({
        username: user.username || '',
        email: user.email || '',
      });
      setPreferencesForm({
        theme: user.theme || 'system',
        language: user.language || 'en',
        timezone: (user.timezone || 'UTC').toUpperCase() === 'UTC' ? 'UTC' : (user.timezone || 'UTC'),
      });
    }
  }, [user]);
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

  const { data: sessions, refetch: refetchSessions, isLoading: isSessionsLoading } = useQuery({
    queryKey: ['auth', 'sessions'],
    queryFn: authApi.getSessions,
    enabled: activeTab === 'security',
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
      const result = await settingsApi.testSmtp(smtpSettings);
      if (result.success) {
        setSmtpMessage(result.message || 'Test email sent successfully.');
      } else {
        setSmtpMessage(result.error || 'Failed to send test email.');
      }
    } catch {
      setSmtpMessage('Failed to send test email.');
    }
  };

  const smtpRequiredFields = [
    smtpSettings.host.trim(),
    smtpSettings.port,
    smtpSettings.from_address.trim(),
    smtpSettings.to_addresses.trim(),
  ];
  const isSmtpComplete = smtpRequiredFields.every((value) => !!value);
  const smtpSaveDisabled = smtpSettings.enabled && !isSmtpComplete;
  const canCloseRecoveryModal = recoveryCopied || recoveryDownloaded;

  const handleDownloadRecoveryCodes = () => {
    const content = recoveryCodes.join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'printer-proxy-recovery-codes.txt';
    link.click();
    URL.revokeObjectURL(url);
    setRecoveryDownloaded(true);
  };
  const accountHasChanges =
    !!user &&
    (accountForm.username.trim() !== user.username || (accountForm.email || '') !== (user.email || ''));
  const preferencesHasChanges =
    !!user &&
    (preferencesForm.theme !== (user.theme || 'system') ||
      preferencesForm.language !== (user.language || 'en') ||
      preferencesForm.timezone !== ((user.timezone || 'UTC').toUpperCase() === 'UTC' ? 'UTC' : (user.timezone || 'UTC')));

  const tabMeta: Record<string, { title: string; description: string }> = {
    general: {
      title: t('general'),
      description: t('settingsMetaGeneral'),
    },
    account: {
      title: t('accountInfo'),
      description: t('settingsMetaAccount'),
    },
    security: {
      title: t('security'),
      description: t('settingsMetaSecurity'),
    },
    notifications: {
      title: t('notifications'),
      description: t('settingsMetaNotifications'),
    },
    'api-tokens': {
      title: t('apiTokens'),
      description: t('settingsMetaApiTokens'),
    },
    'personal-tokens': {
      title: t('personalTokens'),
      description: t('settingsMetaPersonalTokens'),
    },
    integrations: {
      title: t('integrations'),
      description: t('settingsMetaIntegrations'),
    },
  };

  const activeMeta = tabMeta[activeTab] ?? tabMeta.account;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">{t('settings')}</h1>
        <p className="text-muted-foreground">
          {activeMeta.title} · {activeMeta.description}
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

      {activeTab === 'account' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>{t('profile')}</CardTitle>
              <CardDescription>{t('profileDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {accountError && (
                <div className="rounded-lg bg-error-bg p-3 text-sm text-error">
                  {accountError}
                </div>
              )}
              {accountMessage && (
                <div className="rounded-lg bg-muted p-3 text-sm text-muted-foreground">
                  {accountMessage}
                </div>
              )}
              <div className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <Label>{t('username')}</Label>
                  <p className="text-xs text-muted-foreground">{t('usernameHelp')}</p>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Input
                    value={accountForm.username}
                    onChange={(e) => setAccountForm({ ...accountForm, username: e.target.value })}
                  />
                </div>
              </div>
              <div className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <Label>{t('email')}</Label>
                  <p className="text-xs text-muted-foreground">{t('emailHelp')}</p>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Input
                    value={accountForm.email}
                    onChange={(e) => setAccountForm({ ...accountForm, email: e.target.value })}
                    placeholder="name@company.com"
                  />
                </div>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <Label>{t('role')}</Label>
                  <p className="text-xs text-muted-foreground">{t('roleHelp')}</p>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Input value={user?.role || ''} disabled />
                </div>
              </div>
              <div className="flex justify-end">
                <Button
                  onClick={async () => {
                    setAccountError('');
                    setAccountMessage('');
                    setIsSavingAccount(true);
                    try {
                      const updated = await authApi.updateMe({
                        username: accountForm.username.trim(),
                        email: accountForm.email.trim() || null,
                      });
                      setAccountMessage(t('profileSaved'));
                      await checkAuth();
                      setAccountForm({
                        username: updated.username,
                        email: updated.email || '',
                      });
                    } catch (err: unknown) {
                      if (err && typeof err === 'object' && 'response' in err) {
                        const axiosError = err as { response?: { data?: { error?: string } } };
                        setAccountError(axiosError.response?.data?.error || 'Failed to update profile');
                      } else {
                        setAccountError('Failed to update profile');
                      }
                    } finally {
                      setIsSavingAccount(false);
                    }
                  }}
                  disabled={!accountHasChanges || isSavingAccount}
                >
                  {isSavingAccount ? t('saving') : t('saveChanges')}
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('preferences')}</CardTitle>
              <CardDescription>{t('preferencesDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {preferencesError && (
                <div className="rounded-lg bg-error-bg p-3 text-sm text-error">
                  {preferencesError}
                </div>
              )}
              {preferencesMessage && (
                <div className="rounded-lg bg-muted p-3 text-sm text-muted-foreground">
                  {preferencesMessage}
                </div>
              )}
              <div className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <Label>{t('theme')}</Label>
                  <p className="text-xs text-muted-foreground">{t('themeHelp')}</p>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Select
                    value={preferencesForm.theme}
                    onValueChange={(value) =>
                      setPreferencesForm((prev) => ({ ...prev, theme: value }))
                    }
                  >
                    <SelectTrigger className="h-10 w-full">
                      <SelectValue placeholder={t('selectTheme')} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="system">System</SelectItem>
                      <SelectItem value="light">Light</SelectItem>
                      <SelectItem value="dark">Dark</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <Label>{t('language')}</Label>
                  <p className="text-xs text-muted-foreground">{t('languageHelp')}</p>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Select
                    value={preferencesForm.language}
                    onValueChange={(value) =>
                      setPreferencesForm((prev) => ({ ...prev, language: value }))
                    }
                  >
                    <SelectTrigger className="h-10 w-full">
                      <SelectValue placeholder={t('selectLanguage')} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="en">English</SelectItem>
                      <SelectItem value="es">Spanish</SelectItem>
                      <SelectItem value="fr">French</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <Label>{t('timezone')}</Label>
                  <p className="text-xs text-muted-foreground">{t('timezoneHelp')}</p>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Select
                    value={preferencesForm.timezone}
                    onValueChange={(value) =>
                      setPreferencesForm((prev) => ({ ...prev, timezone: value }))
                    }
                  >
                    <SelectTrigger className="h-10 w-full">
                      <SelectValue placeholder={t('selectTimezone')} />
                    </SelectTrigger>
                    <SelectContent>
                      {timezones.map((tz) => (
                        <SelectItem key={tz} value={tz}>
                          {tz}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex justify-end">
                <Button
                  onClick={async () => {
                    setPreferencesError('');
                    setPreferencesMessage('');
                    setIsSavingPreferences(true);
                    try {
                      const updated = await authApi.updateMe({
                        username: accountForm.username.trim(),
                        email: accountForm.email.trim() || null,
                        theme: preferencesForm.theme,
                        language: preferencesForm.language,
                        timezone: preferencesForm.timezone,
                      });
                      setPreferencesMessage(t('preferencesSaved'));
                      setPreferencesForm({
                        theme: updated.theme || 'system',
                        language: updated.language || 'en',
                        timezone: (updated.timezone || 'UTC').toUpperCase() === 'UTC' ? 'UTC' : (updated.timezone || 'UTC'),
                      });
                      i18n.changeLanguage(updated.language || 'en');
                      if (updated.theme) {
                        const root = document.documentElement;
                        if (updated.theme === 'dark') {
                          root.classList.add('dark');
                        } else if (updated.theme === 'light') {
                          root.classList.remove('dark');
                        } else {
                          const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                          root.classList.toggle('dark', prefersDark);
                        }
                      }
                      await checkAuth();
                    } catch (err: unknown) {
                      if (err && typeof err === 'object' && 'response' in err) {
                        const axiosError = err as { response?: { data?: { error?: string } } };
                        setPreferencesError(axiosError.response?.data?.error || 'Failed to update preferences');
                      } else {
                        setPreferencesError('Failed to update preferences');
                      }
                    } finally {
                      setIsSavingPreferences(false);
                    }
                  }}
                  disabled={!preferencesHasChanges || isSavingPreferences}
                >
                  {isSavingPreferences ? t('saving') : t('savePreferences')}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === 'security' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>{t('changePassword')}</CardTitle>
              <CardDescription>{t('changePasswordDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <Label htmlFor="current-password">{t('currentPassword')}</Label>
                  <p className="text-xs text-muted-foreground">{t('currentPasswordHelp')}</p>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Input id="current-password" type="password" placeholder="••••••••" />
                </div>
              </div>
              <div className="flex flex-col gap-3 border-b border-border pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <Label htmlFor="new-password">{t('newPassword')}</Label>
                  <p className="text-xs text-muted-foreground">{t('newPasswordHelp')}</p>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Input id="new-password" type="password" placeholder="••••••••" />
                </div>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <Label htmlFor="confirm-password">{t('confirmPassword')}</Label>
                  <p className="text-xs text-muted-foreground">{t('confirmPasswordHelp')}</p>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Input id="confirm-password" type="password" placeholder="••••••••" />
                </div>
              </div>
              <div className="flex justify-end">
                <Button disabled>{t('updatePassword')}</Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('activeSessions')}</CardTitle>
              <CardDescription>{t('activeSessionsDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {isSessionsLoading ? (
                <div className="flex h-24 items-center justify-center">
                  <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                </div>
              ) : sessions && sessions.length > 0 ? (
                sessions.map((session) => (
                  <div
                    key={session.id}
                    className="flex flex-col gap-3 rounded-lg border border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div>
                      <p className="text-sm font-medium">
                        {session.is_current ? t('sessionCurrent') : t('session')}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {session.ip_address || t('unknownIp')} · {session.user_agent || t('unknownDevice')}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {t('sessionLastActive')} {session.last_used ? new Date(session.last_used).toLocaleString(undefined, {
                          timeZone: localStorage.getItem('timezone') || undefined,
                        }) : '—'}
                      </p>
                    </div>
                    {session.is_current ? (
                      <Badge variant="outline">Active</Badge>
                    ) : (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={async () => {
                          await authApi.revokeSession(session.id);
                          refetchSessions();
                        }}
                      >
                        {t('revoke')}
                      </Button>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-sm text-muted-foreground">{t('noSessions')}</div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('mfa')}</CardTitle>
              <CardDescription>{t('mfaDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {mfaError && (
                <div className="rounded-lg bg-error-bg p-3 text-sm text-error">{mfaError}</div>
              )}
              {mfaMessage && (
                <div className="rounded-lg bg-muted p-3 text-sm text-muted-foreground">{mfaMessage}</div>
              )}
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-medium">{t('mfaApp')}</p>
                  <p className="text-xs text-muted-foreground">
                    {user?.mfa_enabled ? t('mfaEnabled') : t('mfaNotConfigured')}
                  </p>
                </div>
                <div className="w-full sm:w-[320px] flex justify-end gap-2">
                  {user?.mfa_enabled ? (
                    <>
                      <Button variant="outline" onClick={() => setResetRecoveryOpen(true)}>
                        {t('resetRecovery')}
                      </Button>
                      <Button variant="outline" onClick={() => setDisableMfaOpen(true)}>
                        {t('mfaDisable')}
                      </Button>
                    </>
                  ) : (
                    <Button
                      onClick={async () => {
                        setMfaError('');
                        setMfaMessage('');
                        try {
                          const setup = await authApi.setupMfa();
                          setMfaSetupData({ otpauth_uri: setup.otpauth_uri });
                          setRecoveryCodes([]);
                          setRecoveryCopied(false);
                          setRecoveryDownloaded(false);
                          setMfaSetupOpen(true);
                        } catch (err: unknown) {
                          if (err && typeof err === 'object' && 'response' in err) {
                            const axiosError = err as { response?: { data?: { error?: string } } };
                            setMfaError(axiosError.response?.data?.error || 'Failed to start MFA setup');
                          } else {
                            setMfaError('Failed to start MFA setup');
                          }
                        }
                      }}
                    >
                      {t('mfaSetup')}
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          <Dialog
            open={mfaSetupOpen}
            onOpenChange={(open) => {
              if (!open && recoveryCodes.length > 0 && !canCloseRecoveryModal) return;
              setMfaSetupOpen(open);
            }}
          >
            <DialogContent className="max-w-md">
              <DialogHeader>
                <DialogTitle>{t('mfaDialogTitle')}</DialogTitle>
                <DialogDescription>{t('mfaDialogDesc')}</DialogDescription>
              </DialogHeader>
              <div className="flex flex-col items-center gap-4">
                {mfaSetupData?.otpauth_uri && (
                  <QRCodeCanvas value={mfaSetupData.otpauth_uri} size={180} />
                )}
                {recoveryCodes.length === 0 ? (
                  <>
                    <div className="w-full space-y-2">
                      <Label>{t('verificationCode')}</Label>
                      <Input
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value)}
                        placeholder="123456"
                      />
                    </div>
                    <Button
                      className="w-full"
                      onClick={async () => {
                        setMfaError('');
                        setMfaMessage('');
                        try {
                          const result = await authApi.verifyMfa(mfaCode);
                          setRecoveryCodes(result.recovery_codes || []);
                          setRecoveryCopied(false);
                          setRecoveryDownloaded(false);
                          setMfaMessage(t('mfaEnabledMessage'));
                          setMfaCode('');
                          await checkAuth();
                        } catch (err: unknown) {
                          if (err && typeof err === 'object' && 'response' in err) {
                            const axiosError = err as { response?: { data?: { error?: string } } };
                            setMfaError(axiosError.response?.data?.error || 'Failed to verify MFA');
                          } else {
                            setMfaError('Failed to verify MFA');
                          }
                        }
                      }}
                    >
                      {t('verifyEnable')}
                    </Button>
                  </>
                ) : (
                  <div className="w-full space-y-3">
                    <div className="rounded-lg border border-border p-4">
                      <p className="text-sm font-medium">{t('recoveryCodes')}</p>
                      <p className="text-xs text-muted-foreground">
                        {t('recoveryCodesHelp')}
                      </p>
                      <div className="mt-3 grid gap-2 sm:grid-cols-2">
                        {recoveryCodes.map((code) => (
                          <code key={code} className="rounded bg-muted px-2 py-1 text-xs">
                            {code}
                          </code>
                        ))}
                      </div>
                    </div>
                    {!canCloseRecoveryModal && (
                      <p className="text-xs text-muted-foreground">
                        {t('recoveryRequired')}
                      </p>
                    )}
                    <div className="flex flex-col gap-2 sm:flex-row">
                      <Button
                        className="w-full"
                        variant="outline"
                        onClick={async () => {
                          await navigator.clipboard.writeText(recoveryCodes.join('\n'));
                          setRecoveryCopied(true);
                        }}
                      >
                        {t('copyCodes')}
                      </Button>
                      <Button className="w-full" onClick={handleDownloadRecoveryCodes}>
                        {t('downloadCodes')}
                      </Button>
                    </div>
                    <Button
                      className="w-full"
                      disabled={!canCloseRecoveryModal}
                      onClick={() => setMfaSetupOpen(false)}
                    >
                      {t('close')}
                    </Button>
                  </div>
                )}
              </div>
            </DialogContent>
          </Dialog>

          <Dialog open={disableMfaOpen} onOpenChange={setDisableMfaOpen}>
            <DialogContent className="max-w-md">
              <DialogHeader>
                <DialogTitle>{t('disableMfaTitle')}</DialogTitle>
                <DialogDescription>{t('disableMfaDesc')}</DialogDescription>
              </DialogHeader>
              <div className="space-y-3">
                <div className="space-y-2">
                  <Label>{t('verificationCode')}</Label>
                  <Input
                    value={disableMfaCode}
                    onChange={(e) => setDisableMfaCode(e.target.value)}
                    placeholder="123456"
                  />
                </div>
                <Button
                  className="w-full"
                  onClick={async () => {
                    setMfaError('');
                    setMfaMessage('');
                    try {
                      await authApi.disableMfa({ code: disableMfaCode });
                      setMfaMessage(t('mfaDisabledMessage'));
                      setDisableMfaCode('');
                      setDisableMfaOpen(false);
                      await checkAuth();
                    } catch (err: unknown) {
                      if (err && typeof err === 'object' && 'response' in err) {
                        const axiosError = err as { response?: { data?: { error?: string } } };
                        setMfaError(axiosError.response?.data?.error || 'Failed to disable MFA');
                      } else {
                        setMfaError('Failed to disable MFA');
                      }
                    }
                  }}
                >
                  {t('mfaDisable')}
                </Button>
              </div>
            </DialogContent>
          </Dialog>

          <Dialog
            open={resetRecoveryOpen}
            onOpenChange={(open) => {
              if (!open && recoveryCodes.length > 0 && !canCloseRecoveryModal) return;
              setResetRecoveryOpen(open);
            }}
          >
            <DialogContent className="max-w-md">
              <DialogHeader>
                <DialogTitle>{t('resetRecoveryTitle')}</DialogTitle>
                <DialogDescription>{t('resetRecoveryDesc')}</DialogDescription>
              </DialogHeader>
              <div className="space-y-3">
                <Button
                  className="w-full"
                  variant="outline"
                  onClick={async () => {
                    setMfaError('');
                    setMfaMessage('');
                    try {
                      const setup = await authApi.setupMfa();
                      setMfaSetupData({ otpauth_uri: setup.otpauth_uri });
                      setRecoveryCodes([]);
                      setRecoveryCopied(false);
                      setRecoveryDownloaded(false);
                      setResetRecoveryOpen(false);
                      setMfaSetupOpen(true);
                    } catch (err: unknown) {
                      if (err && typeof err === 'object' && 'response' in err) {
                        const axiosError = err as { response?: { data?: { error?: string } } };
                        setMfaError(axiosError.response?.data?.error || 'Failed to reset recovery codes');
                      } else {
                        setMfaError('Failed to reset recovery codes');
                      }
                    }
                  }}
                >
                  {t('resetRecoveryConfirm')}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      )}

      {activeTab === 'notifications' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>{t('notificationsPrefs')}</CardTitle>
              <CardDescription>{t('notificationsPrefsDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 lg:grid-cols-2">
              <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{t('healthAlerts')}</p>
                  <p className="text-xs text-muted-foreground">{t('healthAlertsDesc')}</p>
                </div>
                <Switch
                  checked={notificationPrefs.healthAlerts}
                  onCheckedChange={(value) =>
                    setNotificationPrefs((prev) => ({ ...prev, healthAlerts: value }))
                  }
                />
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{t('offlineAlerts')}</p>
                  <p className="text-xs text-muted-foreground">{t('offlineAlertsDesc')}</p>
                </div>
                <Switch
                  checked={notificationPrefs.offlineAlerts}
                  onCheckedChange={(value) =>
                    setNotificationPrefs((prev) => ({ ...prev, offlineAlerts: value }))
                  }
                />
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{t('jobFailures')}</p>
                  <p className="text-xs text-muted-foreground">{t('jobFailuresDesc')}</p>
                </div>
                <Switch
                  checked={notificationPrefs.jobFailures}
                  onCheckedChange={(value) =>
                    setNotificationPrefs((prev) => ({ ...prev, jobFailures: value }))
                  }
                />
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{t('securityEvents')}</p>
                  <p className="text-xs text-muted-foreground">{t('securityEventsDesc')}</p>
                </div>
                <Switch
                  checked={notificationPrefs.securityEvents}
                  onCheckedChange={(value) =>
                    setNotificationPrefs((prev) => ({ ...prev, securityEvents: value }))
                  }
                />
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{t('weeklyReports')}</p>
                  <p className="text-xs text-muted-foreground">{t('weeklyReportsDesc')}</p>
                </div>
                <Switch
                  checked={notificationPrefs.weeklyReports}
                  onCheckedChange={(value) =>
                    setNotificationPrefs((prev) => ({ ...prev, weeklyReports: value }))
                  }
                />
              </div>
            </CardContent>
          </Card>

          <Card className={!smtpSettings.enabled ? 'opacity-60' : undefined}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Mail className="h-5 w-5" />
                {t('emailDelivery')}
              </CardTitle>
              <CardDescription>{t('emailDeliveryDesc')}</CardDescription>
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
                    {smtpMessage && (
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <CheckCircle className="h-4 w-4" />
                        {smtpMessage}
                      </div>
                    )}

                    <Separator />

                    <div className="grid gap-4 lg:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="smtp-host">
                          {t('smtpHost')} <span className="text-error">*</span>
                        </Label>
                        <Input
                          id="smtp-host"
                          value={smtpSettings.host}
                          onChange={(e) => setSmtpSettings({ ...smtpSettings, host: e.target.value })}
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

                    <div className="grid gap-4 lg:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="smtp-from">
                          {t('smtpFrom')} <span className="text-error">*</span>
                        </Label>
                        <Input
                          id="smtp-from"
                          value={smtpSettings.from_address}
                          onChange={(e) => setSmtpSettings({ ...smtpSettings, from_address: e.target.value })}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="smtp-to">
                          {t('smtpTo')} <span className="text-error">*</span>
                        </Label>
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
                        {t('sendTestEmail')}
                      </Button>
                    </div>
                  </CardContent>
                </motion.div>
              )}
            </AnimatePresence>
          </Card>
        </div>
      )}

      {activeTab === 'api-tokens' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>{t('apiTokens')}</CardTitle>
              <CardDescription>{t('apiTokensDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">Primary Automation</p>
                  <p className="text-xs text-muted-foreground">Last used 2 days ago</p>
                </div>
                <Badge variant="outline">Active</Badge>
              </div>
              <Button disabled>Create new token</Button>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === 'personal-tokens' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>{t('personalTokens')}</CardTitle>
              <CardDescription>{t('personalTokensDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">Admin CLI</p>
                  <p className="text-xs text-muted-foreground">Created Jan 10, 2026</p>
                </div>
                <Button variant="outline" size="sm" disabled>
                  Revoke
                </Button>
              </div>
              <Button disabled>Generate token</Button>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === 'integrations' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>{t('integrations')}</CardTitle>
              <CardDescription>{t('integrationsDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">Webhook Endpoint</p>
                  <p className="text-xs text-muted-foreground">{t('notConfigured')}</p>
                </div>
                <Button variant="outline" size="sm" disabled>
                  Configure
                </Button>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                <div>
                  <p className="text-sm font-medium">Slack Notifications</p>
                  <p className="text-xs text-muted-foreground">Disconnected</p>
                </div>
                <Button variant="outline" size="sm" disabled>
                  Connect
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

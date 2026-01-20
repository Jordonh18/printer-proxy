import { useQuery } from '@tanstack/react-query';
import { authApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
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
import { Loader2 } from 'lucide-react';
import { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { APITokensTab } from '@/components/settings/APITokensTab';
import { useDocumentTitle } from '@/hooks/use-document-title';
import i18n from '@/i18n';

export function SettingsPage() {
  useDocumentTitle('Settings');
  const { t } = useTranslation();
  const { user, checkAuth } = useAuth();
  const [searchParams] = useSearchParams();
  const activeTab = searchParams.get('tab') || 'account';
  const [notificationPrefs, setNotificationPrefs] = useState({
    healthAlerts: true,
    offlineAlerts: true,
    jobFailures: true,
    securityEvents: true,
  });
  const [isSavingNotifications, setIsSavingNotifications] = useState(false);
  const [notificationMessage, setNotificationMessage] = useState('');
  const [notificationError, setNotificationError] = useState('');
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

  const { data: notificationPrefsData } = useQuery({
    queryKey: ['auth', 'notifications'],
    queryFn: authApi.getNotificationPreferences,
  });

  const { data: sessions, refetch: refetchSessions, isLoading: isSessionsLoading } = useQuery({
    queryKey: ['auth', 'sessions'],
    queryFn: authApi.getSessions,
    enabled: activeTab === 'security',
  });

  useEffect(() => {
    if (notificationPrefsData) {
      setNotificationPrefs({
        healthAlerts: notificationPrefsData.health_alerts ?? true,
        offlineAlerts: notificationPrefsData.offline_alerts ?? true,
        jobFailures: notificationPrefsData.job_failures ?? true,
        securityEvents: notificationPrefsData.security_events ?? true,
      });
    }
  }, [notificationPrefsData]);

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
        <h1 className="text-2xl font-bold">{activeMeta.title}</h1>
        <p className="text-muted-foreground">
          {activeMeta.description}
        </p>
      </div>

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
            <CardContent className="space-y-4">
              {notificationError && (
                <div className="rounded-lg bg-error-bg p-3 text-sm text-error">
                  {notificationError}
                </div>
              )}
              {notificationMessage && (
                <div className="rounded-lg bg-muted p-3 text-sm text-muted-foreground">
                  {notificationMessage}
                </div>
              )}
              <div className="grid gap-4 lg:grid-cols-2">
                <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                  <div>
                    <p className="text-sm font-medium">{t('healthAlerts')}</p>
                    <p className="text-xs text-muted-foreground">{t('healthAlertsDesc')}</p>
                  </div>
                  <Switch
                    checked={notificationPrefs.healthAlerts}
                    disabled={isSavingNotifications}
                    onCheckedChange={async (value) => {
                      const newPrefs = { ...notificationPrefs, healthAlerts: value };
                      setNotificationPrefs(newPrefs);
                      setIsSavingNotifications(true);
                      setNotificationError('');
                      setNotificationMessage('');
                      try {
                        await authApi.updateNotificationPreferences({
                          health_alerts: value,
                          offline_alerts: notificationPrefs.offlineAlerts,
                          job_failures: notificationPrefs.jobFailures,
                          security_events: notificationPrefs.securityEvents,
                        });
                        setNotificationMessage('Notification preferences updated');
                        setTimeout(() => setNotificationMessage(''), 3000);
                      } catch (err) {
                        setNotificationError('Failed to update preferences');
                        setNotificationPrefs(notificationPrefs);
                      } finally {
                        setIsSavingNotifications(false);
                      }
                    }}
                  />
                </div>
                <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                  <div>
                    <p className="text-sm font-medium">{t('offlineAlerts')}</p>
                    <p className="text-xs text-muted-foreground">{t('offlineAlertsDesc')}</p>
                  </div>
                  <Switch
                    checked={notificationPrefs.offlineAlerts}
                    disabled={isSavingNotifications}
                    onCheckedChange={async (value) => {
                      const newPrefs = { ...notificationPrefs, offlineAlerts: value };
                      setNotificationPrefs(newPrefs);
                      setIsSavingNotifications(true);
                      setNotificationError('');
                      setNotificationMessage('');
                      try {
                        await authApi.updateNotificationPreferences({
                          health_alerts: notificationPrefs.healthAlerts,
                          offline_alerts: value,
                          job_failures: notificationPrefs.jobFailures,
                          security_events: notificationPrefs.securityEvents,
                        });
                        setNotificationMessage('Notification preferences updated');
                        setTimeout(() => setNotificationMessage(''), 3000);
                      } catch (err) {
                        setNotificationError('Failed to update preferences');
                        setNotificationPrefs(notificationPrefs);
                      } finally {
                        setIsSavingNotifications(false);
                      }
                    }}
                  />
                </div>
                <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                  <div>
                    <p className="text-sm font-medium">{t('jobFailures')}</p>
                    <p className="text-xs text-muted-foreground">{t('jobFailuresDesc')}</p>
                  </div>
                  <Switch
                    checked={notificationPrefs.jobFailures}
                    disabled={isSavingNotifications}
                    onCheckedChange={async (value) => {
                      const newPrefs = { ...notificationPrefs, jobFailures: value };
                      setNotificationPrefs(newPrefs);
                      setIsSavingNotifications(true);
                      setNotificationError('');
                      setNotificationMessage('');
                      try {
                        await authApi.updateNotificationPreferences({
                          health_alerts: notificationPrefs.healthAlerts,
                          offline_alerts: notificationPrefs.offlineAlerts,
                          job_failures: value,
                          security_events: notificationPrefs.securityEvents,
                        });
                        setNotificationMessage('Notification preferences updated');
                        setTimeout(() => setNotificationMessage(''), 3000);
                      } catch (err) {
                        setNotificationError('Failed to update preferences');
                        setNotificationPrefs(notificationPrefs);
                      } finally {
                        setIsSavingNotifications(false);
                      }
                    }}
                  />
                </div>
                <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                  <div>
                    <p className="text-sm font-medium">{t('securityEvents')}</p>
                    <p className="text-xs text-muted-foreground">{t('securityEventsDesc')}</p>
                  </div>
                  <Switch
                    checked={notificationPrefs.securityEvents}
                    disabled={isSavingNotifications}
                    onCheckedChange={async (value) => {
                      const newPrefs = { ...notificationPrefs, securityEvents: value };
                      setNotificationPrefs(newPrefs);
                      setIsSavingNotifications(true);
                      setNotificationError('');
                      setNotificationMessage('');
                      try {
                        await authApi.updateNotificationPreferences({
                          health_alerts: notificationPrefs.healthAlerts,
                          offline_alerts: notificationPrefs.offlineAlerts,
                          job_failures: notificationPrefs.jobFailures,
                          security_events: value,
                        });
                        setNotificationMessage('Notification preferences updated');
                        setTimeout(() => setNotificationMessage(''), 3000);
                      } catch (err) {
                        setNotificationError('Failed to update preferences');
                        setNotificationPrefs(notificationPrefs);
                      } finally {
                        setIsSavingNotifications(false);
                      }
                    }}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === 'api-tokens' && <APITokensTab />}
    </div>
  );
}

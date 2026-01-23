import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { authApi } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Loader2, AlertCircle } from 'lucide-react';
import { useDocumentTitle } from '@/hooks/use-document-title';

export function LoginPage() {
  useDocumentTitle('Login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [requiresMfa, setRequiresMfa] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [totpDigits, setTotpDigits] = useState<string[]>(['', '', '', '', '', '']);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/dashboard';

  useEffect(() => {
    let isMounted = true;
    authApi
      .setupStatus()
      .then((result) => {
        if (isMounted && result.setup_required) {
          navigate('/setup', { replace: true });
        }
      })
      .catch(() => {
        // ignore
      });
    return () => {
      isMounted = false;
    };
  }, [navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const totpValue = totpDigits.join('');
      await login(username, password, useRecovery ? { recovery_code: recoveryCode } : { totp: totpValue });
      navigate(from, { replace: true });
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string; code?: string } } };
        if (axiosError.response?.data?.code === 'MFA_REQUIRED') {
          setRequiresMfa(true);
          setError('');
        } else {
          setError(axiosError.response?.data?.error || 'Invalid credentials');
        }
      } else {
        setError('An error occurred. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleTotpChange = (index: number, value: string) => {
    const nextValue = value.replace(/\D/g, '').slice(-1);
    setTotpDigits((prev) => {
      const next = [...prev];
      next[index] = nextValue;
      return next;
    });

    if (nextValue && index < 5) {
      const nextInput = document.getElementById(`totp-${index + 1}`) as HTMLInputElement | null;
      nextInput?.focus();
    }
  };

  const handleTotpKeyDown = (index: number, event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Backspace' && !totpDigits[index] && index > 0) {
      const prevInput = document.getElementById(`totp-${index - 1}`) as HTMLInputElement | null;
      prevInput?.focus();
      setTotpDigits((prev) => {
        const next = [...prev];
        next[index - 1] = '';
        return next;
      });
    }
  };

  const totpFilled = useMemo(() => totpDigits.every((digit) => digit.length === 1), [totpDigits]);

  return (
    <div className="min-h-screen bg-background">
      <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[2fr_1fr]">
        <div className="hidden lg:flex flex-col bg-foreground text-background relative overflow-hidden">
          <div
            className="absolute inset-0 opacity-40 z-0"
            style={{
              backgroundImage:
                "linear-gradient(90deg, rgba(0,0,0,0.98) 0%, rgba(0,0,0,0.75) 55%, rgba(0,0,0,0.35) 100%), url('https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1600&q=80')",
              backgroundSize: 'cover',
              backgroundPosition: 'center',
            }}
          />
          <div className="px-10 py-8 relative z-10">
            <span className="text-sm font-semibold tracking-wide text-background/80">Continuum</span>
          </div>
          <div className="flex flex-1 flex-col justify-between px-10 pb-12 relative z-10">
            <div className="max-w-md space-y-6 pt-10">
              <p className="text-3xl font-semibold leading-tight">
                Keep print workflows resilient and always-on.
              </p>
              <p className="text-base text-background/70">
                Monitor, redirect, and recover print traffic in seconds. Built for modern IT teams that
                can’t afford downtime.
              </p>
              <div className="h-px w-16 bg-background/30" />
              <p className="text-sm text-background/60">“Zero disruption printing for critical operations.”</p>
            </div>
          </div>
        </div>
        <div className="bg-card text-card-foreground">
          <div className="flex min-h-screen items-center justify-center px-6 py-12">
            <div className="w-full max-w-lg">
              <div className="mb-6 text-center">
                <h1 className="text-2xl font-semibold">
                  {requiresMfa ? 'Verify your account' : 'Login to your account'}
                </h1>
                <p className="mt-1 text-sm text-accent-foreground/70">
                  {requiresMfa
                    ? 'Enter the 6-digit code to continue'
                    : 'Enter your credentials to continue'}
                </p>
              </div>

              <form
                key={requiresMfa ? 'mfa' : 'login'}
                onSubmit={handleSubmit}
                className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300"
              >
                {error && (
                  <div className="flex items-center gap-2 rounded-lg bg-error-bg p-3 text-sm text-error">
                    <AlertCircle className="h-4 w-4 shrink-0" />
                    {error}
                  </div>
                )}

                {requiresMfa ? (
                  <div className="space-y-4">
                    {useRecovery ? (
                      <>
                        <Input
                          id="totp"
                          type="text"
                          placeholder="Enter recovery code"
                          className="bg-card text-foreground border-border ring-1 ring-border/40"
                          value={recoveryCode}
                          onChange={(e) => setRecoveryCode(e.target.value)}
                          required
                          autoComplete="one-time-code"
                          autoFocus
                        />
                      </>
                    ) : (
                      <>
                        <div className="flex items-center justify-center gap-0">
                          {totpDigits.map((digit, index) => {
                            const isGroupStart = index === 0 || index === 3;
                            const isGroupEnd = index === 2 || index === 5;
                            const rounding = isGroupStart
                              ? '!rounded-none !rounded-l-md'
                              : isGroupEnd
                                ? '!rounded-none !rounded-r-md'
                                : '!rounded-none';
                            const borderLeft = isGroupStart ? 'border-l' : 'border-l-0';

                            return (
                              <div key={`totp-${index}`} className="flex items-center">
                                <Input
                                  id={`totp-${index}`}
                                  inputMode="numeric"
                                  maxLength={1}
                                  className={`h-14 w-14 text-center text-lg bg-card text-foreground border-border ring-1 ring-border/40 ${rounding} ${borderLeft}`}
                                  value={digit}
                                  onChange={(e) => handleTotpChange(index, e.target.value)}
                                  onKeyDown={(e) => handleTotpKeyDown(index, e)}
                                  autoComplete="one-time-code"
                                  autoFocus={index === 0}
                                />
                                {index === 2 && (
                                  <span className="mx-0 w-3 text-center text-muted-foreground">-</span>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </>
                    )}
                  </div>
                ) : (
                  <>
                    <div className="space-y-2">
                      <Label htmlFor="username">Username</Label>
                      <Input
                        id="username"
                        type="text"
                        placeholder="Enter your username"
                        className="bg-card text-foreground border-border ring-1 ring-border/40"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                        autoComplete="username"
                        autoFocus
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="password">Password</Label>
                      <Input
                        id="password"
                        type="password"
                        placeholder="Enter your password"
                        className="bg-card text-foreground border-border ring-1 ring-border/40"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        autoComplete="current-password"
                      />
                    </div>
                  </>
                )}

                <Button
                  type="submit"
                  className="w-full"
                  disabled={isLoading || (requiresMfa && !useRecovery && !totpFilled)}
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      {requiresMfa ? 'Verifying...' : 'Signing in...'}
                    </>
                  ) : (
                    requiresMfa ? 'Verify' : 'Sign in'
                  )}
                </Button>
                {requiresMfa && (
                  <button
                    type="button"
                    className="mx-auto block text-xs text-primary hover:underline"
                    onClick={() => {
                      if (useRecovery) {
                        setUseRecovery(false);
                        setRecoveryCode('');
                      } else {
                        setUseRecovery(true);
                        setTotpDigits(['', '', '', '', '', '']);
                      }
                    }}
                  >
                    {useRecovery ? 'Use authenticator code instead' : 'Use a recovery code'}
                  </button>
                )}
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

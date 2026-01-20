import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authApi } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';
import { useDocumentTitle } from '@/hooks/use-document-title';

export function SetupPage() {
  useDocumentTitle('Setup');
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [slideIndex, setSlideIndex] = useState(0);
  const [textIndex, setTextIndex] = useState(0);
  const [showForm, setShowForm] = useState(false);
  const [step, setStep] = useState(0);
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [isCreating, setIsCreating] = useState(false);

  const slides = useMemo(
    () => [
      {
        title: 'Launch your print command center.',
        subtitle: 'Create the first admin and take control of routing, health, and uptime.',
        image:
          "https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?auto=format&fit=crop&w=1600&q=80",
      },
      {
        title: 'Built for on-prem teams.',
        subtitle: 'Fast setup, local control, and a UI designed for daily operations.',
        image:
          "https://images.unsplash.com/photo-1441974231531-c6227db76b6e?auto=format&fit=crop&w=1600&q=80",
      },
      {
        title: 'Be ready for every failure.',
        subtitle: 'Create a resilient print stack before the first job hits the queue.',
        image:
          "https://images.unsplash.com/photo-1501785888041-af3ef285b470?auto=format&fit=crop&w=1600&q=80",
      },
      {
        title: 'Calm focus, reliable output.',
        subtitle: 'Designed to keep operators steady when systems change fast.',
        image:
          "https://images.unsplash.com/photo-1500534314209-a25ddb2bd429?auto=format&fit=crop&w=1600&q=80",
      },
      {
        title: 'Precision in every route.',
        subtitle: 'Make every redirect intentional with clear, predictable flows.',
        image:
          "https://images.unsplash.com/photo-1470770903676-69b98201ea1c?auto=format&fit=crop&w=1600&q=80",
      },
      {
        title: 'Keep operations moving.',
        subtitle: 'Set the baseline now so future issues stay invisible.',
        image:
          "https://images.unsplash.com/photo-1472214103451-9374bd1c798e?auto=format&fit=crop&w=1600&q=80",
      },
      {
        title: 'Resilience feels effortless.',
        subtitle: 'Your printing stack should be as dependable as the sunrise.',
        image:
          "https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?auto=format&fit=crop&w=1600&q=80&sat=-15",
      },
    ],
    []
  );

  useEffect(() => {
    const interval = setInterval(() => {
      setSlideIndex((prev) => (prev + 1) % slides.length);
    }, 4500);
    return () => clearInterval(interval);
  }, [slides.length]);

  useEffect(() => {
    const interval = setInterval(() => {
      setTextIndex((prev) => (prev + 1) % slides.length);
    }, 7000);
    return () => clearInterval(interval);
  }, [slides.length]);

  useEffect(() => {
    slides.forEach((slide) => {
      const img = new Image();
      img.src = slide.image;
    });
  }, [slides]);


  useEffect(() => {
    let isMounted = true;
    authApi
      .setupStatus()
      .then((result) => {
        if (isMounted && !result.setup_required) {
          navigate('/login', { replace: true });
        }
      })
      .catch(() => {
        // ignore
      });
    return () => {
      isMounted = false;
    };
  }, [navigate]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setMessage('');

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setIsLoading(true);
    setIsCreating(true);
    try {
      await authApi.createInitialAdmin({
        username: username.trim(),
        password,
        email: email.trim() || null,
        full_name: fullName.trim() || null,
      });
      // Redirect to login after successful creation
      setTimeout(() => navigate('/login', { replace: true }), 1000);
    } catch (err: unknown) {
      setIsCreating(false);
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosError = err as { response?: { data?: { error?: string } } };
        setError(axiosError.response?.data?.error || 'Failed to create admin account.');
      } else {
        setError('Failed to create admin account.');
      }
      setIsLoading(false);
    }
  };

  const canContinue = () => {
    if (step === 0) {
      return fullName.trim().length > 0 && email.trim().length > 0;
    }
    if (step === 1) {
      return username.trim().length > 0;
    }
    if (step === 2) {
      return password.length > 0 && confirmPassword.length > 0;
    }
    return false;
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="relative min-h-screen overflow-hidden">
        <div className="absolute inset-0 bg-foreground text-background">
          <AnimatePresence mode="wait">
            <motion.div
              key={slideIndex}
              className="absolute inset-0 pointer-events-none"
              initial={{ opacity: 0 }}
              animate={{ opacity: 0.35 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.4, ease: 'easeInOut' }}
              style={{
                backgroundImage: `linear-gradient(120deg, rgba(0,0,0,0.75) 0%, rgba(0,0,0,0.5) 55%, rgba(0,0,0,0.25) 100%), url('${slides[slideIndex].image}')`,
                backgroundSize: 'cover',
                backgroundPosition: 'center',
              }}
            />
          </AnimatePresence>
          <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_center,rgba(0,0,0,0.03)_0%,rgba(0,0,0,0.2)_60%,rgba(0,0,0,0.35)_100%)]" />
          <div className="relative z-10 flex min-h-screen flex-col items-center justify-center px-10 py-16 text-center pointer-events-auto">
            <div className="max-w-2xl space-y-6">
              <div className="relative h-[3.5rem] overflow-hidden">
                <AnimatePresence mode="wait">
                  <motion.p
                    key={`title-${textIndex}`}
                    className="text-4xl font-semibold leading-tight"
                    initial={{ y: 24, opacity: 0 }}
                    animate={{ y: 0, opacity: 1 }}
                    exit={{ y: -24, opacity: 0 }}
                    transition={{ duration: 0.35, ease: 'easeInOut' }}
                  >
                    {slides[textIndex].title}
                  </motion.p>
                </AnimatePresence>
              </div>
              <div className="relative h-[1.75rem] overflow-hidden">
                <AnimatePresence mode="wait">
                  <motion.p
                    key={`subtitle-${textIndex}`}
                    className="text-base text-background/70"
                    initial={{ y: 18, opacity: 0 }}
                    animate={{ y: 0, opacity: 1 }}
                    exit={{ y: -18, opacity: 0 }}
                    transition={{ duration: 0.35, ease: 'easeInOut' }}
                  >
                    {slides[textIndex].subtitle}
                  </motion.p>
                </AnimatePresence>
              </div>
            </div>
            {!showForm && (
              <motion.button
                type="button"
                onClick={() => {
                  setShowForm(true);
                  setStep(0);
                }}
                className="absolute bottom-8 z-20 cursor-pointer text-sm font-medium text-background/90"
                style={{ willChange: 'transform' }}
                animate={{ y: [0, -6, 0], opacity: [0.95, 1, 0.95] }}
                transition={{ duration: 1.6, ease: 'easeInOut', repeat: Infinity }}
              >
                Get started
              </motion.button>
            )}
          </div>
        </div>

        <AnimatePresence>
          {showForm && (
            <motion.div
              className="fixed inset-0 z-30 flex items-center justify-center bg-black/20 px-6 py-12"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <motion.div
                className="w-full max-w-xl rounded-3xl bg-card p-10 text-card-foreground shadow-2xl"
                initial={{ opacity: 0, y: 24, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 24, scale: 0.98 }}
                transition={{ duration: 0.35, ease: 'easeOut' }}
              >
                {isCreating ? (
                  <div className="flex flex-col items-center justify-center py-20 space-y-4">
                    <Loader2 className="h-12 w-12 animate-spin text-primary" />
                    <p className="text-lg font-medium">Creating your admin account...</p>
                    <p className="text-sm text-muted-foreground">You'll be redirected to login shortly</p>
                  </div>
                ) : (
                  <>
                <div className="mb-8 flex items-center justify-between">
                  <div>
                    <h1 className="text-2xl font-semibold">Create your admin workspace</h1>
                  </div>
                  <div className="text-sm text-muted-foreground">Step {step + 1} of 3</div>
                </div>

                <form onSubmit={handleSubmit} className="space-y-8">
                  {error && (
                    <div className="flex items-center gap-2 rounded-lg bg-error-bg p-3 text-sm text-error">
                      <AlertCircle className="h-4 w-4 shrink-0" />
                      {error}
                    </div>
                  )}
                  {message && (
                    <div className="flex items-center gap-2 rounded-lg bg-success/10 p-3 text-sm text-success">
                      <CheckCircle2 className="h-4 w-4 shrink-0" />
                      {message}
                    </div>
                  )}

                  <AnimatePresence mode="wait">
                    {step === 0 && (
                      <motion.div
                        key="step-profile"
                        className="space-y-6"
                        initial={{ x: 40, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        exit={{ x: -40, opacity: 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        <div className="space-y-2">
                          <Label htmlFor="setup-full-name">Full name</Label>
                          <Input
                            id="setup-full-name"
                            type="text"
                            placeholder="Jane Doe"
                            className="bg-card text-foreground border-border ring-1 ring-border/40"
                            value={fullName}
                            onChange={(e) => setFullName(e.target.value)}
                            required
                            autoComplete="name"
                            autoFocus
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="setup-email">Email</Label>
                          <Input
                            id="setup-email"
                            type="email"
                            placeholder="you@company.com"
                            className="bg-card text-foreground border-border ring-1 ring-border/40"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                            autoComplete="email"
                          />
                        </div>
                      </motion.div>
                    )}

                    {step === 1 && (
                      <motion.div
                        key="step-username"
                        className="space-y-6"
                        initial={{ x: 40, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        exit={{ x: -40, opacity: 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        <div className="space-y-2">
                          <Label htmlFor="setup-username">Admin username</Label>
                          <Input
                            id="setup-username"
                            type="text"
                            placeholder="Choose a username"
                            className="bg-card text-foreground border-border ring-1 ring-border/40"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                            autoComplete="username"
                            autoFocus
                          />
                        </div>
                      </motion.div>
                    )}

                    {step === 2 && (
                      <motion.div
                        key="step-password"
                        className="space-y-6"
                        initial={{ x: 40, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        exit={{ x: -40, opacity: 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        <div className="space-y-2">
                          <Label htmlFor="setup-password">Password</Label>
                          <Input
                            id="setup-password"
                            type="password"
                            placeholder="Choose a strong password"
                            className="bg-card text-foreground border-border ring-1 ring-border/40"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            autoComplete="new-password"
                            autoFocus
                          />
                          <p className="text-xs text-muted-foreground">
                            Minimum 12 characters with uppercase, lowercase, number, and symbol.
                          </p>
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="setup-confirm">Confirm password</Label>
                          <Input
                            id="setup-confirm"
                            type="password"
                            placeholder="Confirm your password"
                            className="bg-card text-foreground border-border ring-1 ring-border/40"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                            autoComplete="new-password"
                          />
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  <div className="flex items-center justify-between">
                    <Button
                      type="button"
                      variant="ghost"
                      onClick={() => setStep((prev) => Math.max(0, prev - 1))}
                      disabled={step === 0}
                    >
                      Back
                    </Button>
                    {step < 2 ? (
                      <Button type="button" onClick={() => setStep((prev) => prev + 1)} disabled={!canContinue()}>
                        Continue
                      </Button>
                    ) : (
                      <Button type="submit" disabled={isLoading || !canContinue()}>
                        {isLoading ? (
                          <>
                            <Loader2 className="h-4 w-4 animate-spin" />
                            Creating account...
                          </>
                        ) : (
                          'Create admin account'
                        )}
                      </Button>
                    )}
                  </div>
                </form>
                </>
                )}
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

import { ServerOff } from 'lucide-react';

export function BackendUnavailable() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="max-w-md w-full text-center space-y-6">
        <div className="flex justify-center">
          <ServerOff className="w-16 h-16 text-destructive" />
        </div>
        
        <div className="space-y-2">
          <h1 className="text-2xl font-bold text-foreground">
            Backend Unavailable
          </h1>
          <p className="text-muted-foreground">
            The Continuum backend service is not responding. Please check that the service is running.
          </p>
        </div>

        <a
          href="https://github.com/jordonh18/continuum/issues"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors underline underline-offset-4"
        >
          Need help? Report an issue →
        </a>
      </div>
    </div>
  );
}

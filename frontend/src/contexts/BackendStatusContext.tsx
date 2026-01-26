import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import axios from 'axios';

interface BackendStatusContextType {
  isBackendAvailable: boolean;
  isChecking: boolean;
  lastChecked: Date | null;
  error: string | null;
  retryConnection: () => Promise<void>;
}

const BackendStatusContext = createContext<BackendStatusContextType | undefined>(undefined);

const HEALTH_CHECK_INTERVAL = 30000; // 30 seconds
const HEALTH_CHECK_TIMEOUT = 5000; // 5 seconds

export function BackendStatusProvider({ children }: { children: ReactNode }) {
  const [isBackendAvailable, setIsBackendAvailable] = useState(true);
  const [isChecking, setIsChecking] = useState(false);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [consecutiveFailures, setConsecutiveFailures] = useState(0);

  const checkBackendHealth = useCallback(async (): Promise<boolean> => {
    try {
      // Use a simple endpoint that doesn't require auth
      const response = await axios.get('/api/auth/setup', {
        timeout: HEALTH_CHECK_TIMEOUT,
      });
      return response.status === 200;
    } catch (err) {
      if (axios.isAxiosError(err)) {
        // Network error (no response at all) means backend is truly down
        if (!err.response) {
          return false;
        }
        // If we got any response (even 4xx/5xx), backend is reachable
        // Only 500+ errors might indicate backend issues
        if (err.response.status >= 500) {
          return false;
        }
        // 4xx errors mean backend is working (just auth/validation issues)
        return true;
      }
      return false;
    }
  }, []);

  const retryConnection = useCallback(async () => {
    setIsChecking(true);
    setError(null);
    
    const isAvailable = await checkBackendHealth();
    
    setIsBackendAvailable(isAvailable);
    setLastChecked(new Date());
    setIsChecking(false);
    
    if (isAvailable) {
      setConsecutiveFailures(0);
      setError(null);
    } else {
      setConsecutiveFailures(prev => prev + 1);
      setError('Unable to connect to the Continuum backend server');
    }
  }, [checkBackendHealth]);

  // Initial check on mount
  useEffect(() => {
    retryConnection();
  }, []);

  // Periodic health checks
  useEffect(() => {
    const interval = setInterval(async () => {
      const isAvailable = await checkBackendHealth();
      
      if (isAvailable) {
        if (!isBackendAvailable) {
          // Backend recovered
          setIsBackendAvailable(true);
          setConsecutiveFailures(0);
          setError(null);
        }
      } else {
        setConsecutiveFailures(prev => prev + 1);
        // Only mark as unavailable after 2 consecutive failures
        // to avoid false positives from temporary network blips
        if (consecutiveFailures >= 1) {
          setIsBackendAvailable(false);
          setError('Unable to connect to the Continuum backend server');
        }
      }
      
      setLastChecked(new Date());
    }, HEALTH_CHECK_INTERVAL);

    return () => clearInterval(interval);
  }, [checkBackendHealth, isBackendAvailable, consecutiveFailures]);

  // Listen for network errors from axios globally
  useEffect(() => {
    const handleOnline = () => {
      // Browser came online, check backend
      retryConnection();
    };

    const handleOffline = () => {
      setIsBackendAvailable(false);
      setError('Your device appears to be offline');
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [retryConnection]);

  return (
    <BackendStatusContext.Provider
      value={{
        isBackendAvailable,
        isChecking,
        lastChecked,
        error,
        retryConnection,
      }}
    >
      {children}
    </BackendStatusContext.Provider>
  );
}

export function useBackendStatus() {
  const context = useContext(BackendStatusContext);
  if (context === undefined) {
    throw new Error('useBackendStatus must be used within a BackendStatusProvider');
  }
  return context;
}

// Export a function to manually trigger backend unavailable state
// This can be called from the API interceptor
let setBackendUnavailableCallback: ((unavailable: boolean, error?: string) => void) | null = null;

export function registerBackendStatusCallback(callback: (unavailable: boolean, error?: string) => void) {
  setBackendUnavailableCallback = callback;
}

export function notifyBackendUnavailable(error?: string) {
  if (setBackendUnavailableCallback) {
    setBackendUnavailableCallback(true, error);
  }
}

export function notifyBackendAvailable() {
  if (setBackendUnavailableCallback) {
    setBackendUnavailableCallback(false);
  }
}

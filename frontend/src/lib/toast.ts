import { toast as sonnerToast } from 'sonner';

/**
 * Centralized toast notification utility
 * Provides consistent toast notifications across the app
 */
export const toast = {
  success: (title: string, description?: string) => {
    sonnerToast.success(title, description ? { description } : undefined);
  },

  error: (title: string, description?: string) => {
    sonnerToast.error(title, description ? { description } : undefined);
  },

  warning: (title: string, description?: string) => {
    sonnerToast.warning(title, description ? { description } : undefined);
  },

  info: (title: string, description?: string) => {
    sonnerToast.info(title, description ? { description } : undefined);
  },

  promise: <T,>(
    promise: Promise<T>,
    options: {
      loading: string;
      success: string | ((data: T) => string);
      error: string | ((error: Error) => string);
    }
  ) => {
    return sonnerToast.promise(promise, options);
  },

  loading: (title: string, description?: string) => {
    return sonnerToast.loading(title, description ? { description } : undefined);
  },

  dismiss: (toastId?: string | number) => {
    sonnerToast.dismiss(toastId);
  },
};

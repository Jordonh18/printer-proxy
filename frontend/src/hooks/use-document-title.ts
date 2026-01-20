import { useEffect } from 'react';

/**
 * Hook to set the document title for the current page
 * @param title - The page title (will be appended with " - Printer Proxy")
 */
export function useDocumentTitle(title: string) {
  useEffect(() => {
    const previousTitle = document.title;
    document.title = `${title} - Printer Proxy`;

    return () => {
      document.title = previousTitle;
    };
  }, [title]);
}

import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';

interface StatusBadgeProps {
  status: 'online' | 'offline' | 'redirected' | 'target';
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const variants = {
    online: { variant: 'success' as const, label: 'Online' },
    offline: { variant: 'error' as const, label: 'Offline' },
    redirected: { variant: 'warning' as const, label: 'Redirected' },
    target: { variant: 'info' as const, label: 'Target' },
  };

  const { variant, label } = variants[status];

  return (
    <Badge variant={variant} className={cn('gap-1.5', className)}>
      <span className={cn(
        'h-1.5 w-1.5 rounded-full',
        status === 'online' && 'bg-success',
        status === 'offline' && 'bg-error',
        status === 'redirected' && 'bg-warning',
        status === 'target' && 'bg-info'
      )} />
      {label}
    </Badge>
  );
}

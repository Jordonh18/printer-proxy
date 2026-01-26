import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';

interface StatusBadgeProps {
  status: 'online' | 'offline' | 'redirected' | 'target';
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const variants = {
    online: { variant: 'outline' as const, label: 'Online' },
    offline: { variant: 'outline' as const, label: 'Offline' },
    redirected: { variant: 'outline' as const, label: 'Redirected' },
    target: { variant: 'outline' as const, label: 'Target' },
  };

  const { variant, label } = variants[status];

  return (
    <Badge
      variant={variant}
      className={cn(
        'border-transparent',
        status === 'online' && 'bg-emerald-500/10 text-emerald-700',
        status === 'offline' && 'bg-destructive/10 text-destructive',
        status === 'redirected' && 'bg-amber-500/10 text-amber-700',
        status === 'target' && 'bg-sky-500/10 text-sky-700',
        className
      )}
    >
      {label}
    </Badge>
  );
}

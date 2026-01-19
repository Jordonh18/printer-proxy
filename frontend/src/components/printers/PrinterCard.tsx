import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { StatusBadge } from './StatusBadge';
import { Printer, MapPin, ArrowRight } from 'lucide-react';
import type { PrinterStatus } from '@/types/api';

interface PrinterCardProps {
  printerStatus: PrinterStatus;
}

export function PrinterCard({ printerStatus }: PrinterCardProps) {
  const { printer, is_online, has_redirect, is_target, redirect_target, redirect_source } = printerStatus;

  const getStatus = () => {
    if (has_redirect) return 'redirected';
    if (is_target) return 'target';
    if (is_online) return 'online';
    return 'offline';
  };

  return (
    <Link to={`/printers/${printer.id}`}>
      <Card className="group cursor-pointer transition-all hover:shadow-lg hover:-translate-y-0.5">
        <CardHeader className="flex flex-row items-start justify-between gap-3 pb-3">
          <div className="flex items-center gap-4">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-primary/10 text-primary transition-colors group-hover:bg-primary group-hover:text-primary-foreground">
              <Printer className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <h3 className="font-semibold truncate">{printer.name}</h3>
              <p className="text-sm text-muted-foreground">{printer.ip}</p>
            </div>
          </div>
          <StatusBadge status={getStatus()} />
        </CardHeader>
        <CardContent className="pt-0 space-y-3">
          {printer.location && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <MapPin className="h-4 w-4" />
              {printer.location}
            </div>
          )}

          {has_redirect && redirect_target && (
            <div className="flex items-center gap-2 rounded-lg bg-warning-bg/60 p-3 text-sm">
              <ArrowRight className="h-4 w-4 text-warning" />
              <span>
                Redirecting to <strong>{redirect_target.name}</strong>
              </span>
            </div>
          )}

          {is_target && redirect_source && (
            <div className="flex items-center gap-2 rounded-lg bg-info-bg/60 p-3 text-sm">
              <ArrowRight className="h-4 w-4 text-info rotate-180" />
              <span>
                Receiving from <strong>{redirect_source.name}</strong>
              </span>
            </div>
          )}

          {printer.model && (
            <p className="text-xs text-muted-foreground">{printer.model}</p>
          )}
        </CardContent>
      </Card>
    </Link>
  );
}

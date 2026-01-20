import { useQuery } from '@tanstack/react-query';
import { auditLogsApi, printersApi } from '@/lib/api';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Loader2 } from 'lucide-react';
import type { AuditLog, PrinterStatus } from '@/types/api';

export function AuditLogPage() {
  const {
    data: logs,
    isLoading,
    refetch,
    isRefetching,
  } = useQuery<AuditLog[]>({
    queryKey: ['audit-logs'],
    queryFn: () => auditLogsApi.getAll({ limit: 200 }),
  });

  const { data: printers } = useQuery<PrinterStatus[]>({
    queryKey: ['printers'],
    queryFn: printersApi.getAll,
  });

  const printerNameMap = new Map(
    printers?.map((status) => [status.printer.id, status.printer.name]) || []
  );

  const getPrinterLabel = (printerId?: string, printerIp?: string) => {
    if (printerId && printerNameMap.has(printerId)) {
      return printerNameMap.get(printerId);
    }
    return printerIp || printerId || '—';
  };

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-9rem)] flex-col gap-6 overflow-hidden">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">Audit Log</h1>
          <p className="text-muted-foreground">Track authentication and system events</p>
        </div>
        <Button variant="outline" onClick={() => refetch()} disabled={isRefetching}>
          {isRefetching ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Refresh'}
        </Button>
      </div>

      {logs && logs.length > 0 ? (
        <Card className="flex min-h-0 flex-1 flex-col gap-0 py-0">
          <CardContent className="min-h-0 flex-1 p-0">
            <div className="h-full overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-background">
                  <TableRow>
                    <TableHead className="px-4">Timestamp</TableHead>
                    <TableHead className="px-4">User</TableHead>
                    <TableHead className="px-4">Action</TableHead>
                    <TableHead className="px-4">Source</TableHead>
                    <TableHead className="px-4">Target</TableHead>
                    <TableHead className="px-4">Details</TableHead>
                    <TableHead className="px-4">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.map((log) => (
                    <TableRow key={log.id}>
                      <TableCell className="px-4 text-sm text-muted-foreground">
                        {new Date(log.timestamp).toLocaleString(undefined, {
                          timeZone: localStorage.getItem('timezone') || undefined,
                        })}
                      </TableCell>
                      <TableCell className="px-4">
                        <div className="font-medium">{log.username}</div>
                      </TableCell>
                      <TableCell className="px-4">
                        <Badge variant="outline">{log.action}</Badge>
                      </TableCell>
                      <TableCell className="px-4">
                        {getPrinterLabel(log.source_printer_id, log.source_ip)}
                      </TableCell>
                      <TableCell className="px-4">
                        {getPrinterLabel(log.target_printer_id, log.target_ip)}
                      </TableCell>
                      <TableCell className="px-4 text-sm text-muted-foreground">
                        {log.details || '—'}
                      </TableCell>
                      <TableCell className="px-4">
                        <span
                          className={`inline-flex h-2 w-2 rounded-full ${
                            log.success ? 'bg-emerald-500' : 'bg-red-500'
                          }`}
                          aria-label={log.success ? 'Success' : 'Failed'}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
          <div className="relative">
            <div className="absolute inset-0 -z-10 h-48 w-48 rounded-full bg-primary/5 blur-2xl" />
            <svg
              className="h-40 w-40 text-primary"
              viewBox="0 0 200 200"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <rect x="50" y="52" width="100" height="96" rx="14" className="fill-primary/15" />
              <path d="M70 78h60" className="stroke-primary/35" strokeWidth="8" strokeLinecap="round" />
              <path d="M70 104h60" className="stroke-primary/35" strokeWidth="8" strokeLinecap="round" />
              <circle cx="80" cy="128" r="6" className="fill-primary/35" />
            </svg>
          </div>
          <h3 className="mt-6 text-2xl font-semibold">No audit activity yet</h3>
          <p className="mt-3 max-w-xl text-sm text-muted-foreground">
            Audit events will appear here as users sign in and system changes occur.
          </p>
        </div>
      )}

      {logs && logs.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Showing last 200 entries. Full logs are stored in /var/log/printer-proxy/.
        </p>
      )}
    </div>
  );
}

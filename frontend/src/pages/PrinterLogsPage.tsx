import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { printersApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Loader2, XCircle, AlertCircle, Info, Search, RefreshCw } from 'lucide-react';
import { useDocumentTitle } from '@/hooks/use-document-title';
import type { SyslogMessage } from '@/types/api';

export function PrinterLogsPage() {
  const { id } = useParams();
  const [logSearch, setLogSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<number | undefined>(undefined);

  const { data: printerStatus } = useQuery({
    queryKey: ['printer', id],
    queryFn: () => printersApi.getById(id!),
  });

  const { data: syslogConfig } = useQuery({
    queryKey: ['printer', id, 'syslog-config'],
    queryFn: () => printersApi.getSyslogConfig(id!),
  });

  const { data: syslogData, isLoading: syslogLoading, refetch } = useQuery({
    queryKey: ['printer', id, 'syslog', logSearch, severityFilter],
    queryFn: () => printersApi.getSyslogMessages(id!, { 
      limit: 100, 
      search: logSearch || undefined,
      severity: severityFilter 
    }),
    refetchInterval: 10000, // Auto-refresh every 10s
  });

  useDocumentTitle(`Device Logs - ${printerStatus?.printer?.name || 'Printer'}`);

  const getSeverityIcon = (severity: number) => {
    if (severity <= 3) {
      return <XCircle className="h-4 w-4 text-red-500" />;
    } else if (severity <= 4) {
      return <AlertCircle className="h-4 w-4 text-yellow-500" />;
    }
    return <Info className="h-4 w-4 text-blue-500" />;
  };

  const getSeverityVariant = (severity: number): 'destructive' | 'outline' | 'secondary' => {
    if (severity <= 3) return 'destructive';
    if (severity <= 4) return 'outline';
    return 'secondary';
  };

  return (
    <div className="space-y-4">
      <div>
        <Link to={`/printers/${id}`}>
          <Button variant="ghost" size="sm" className="text-muted-foreground">
            Back to Printer
          </Button>
        </Link>
      </div>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Device Logs</h1>
          <p className="text-sm text-muted-foreground">
            {printerStatus?.printer?.name} ({printerStatus?.printer?.ip})
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()} size="sm">
          <RefreshCw className="h-4 w-4 mr-1" />
          Refresh
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
          <CardDescription>Search and filter device log messages</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search log messages..."
                value={logSearch}
                onChange={(e) => setLogSearch(e.target.value)}
                className="pl-9"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex gap-2">
              <Button
                variant={severityFilter === undefined ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSeverityFilter(undefined)}
              >
                All
              </Button>
              <Button
                variant={severityFilter === 3 ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSeverityFilter(3)}
              >
                Errors
              </Button>
              <Button
                variant={severityFilter === 4 ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSeverityFilter(4)}
              >
                Warnings
              </Button>
              <Button
                variant={severityFilter === 6 ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSeverityFilter(6)}
              >
                Info
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Log Messages */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Log Messages</CardTitle>
              <CardDescription>
                {syslogData?.total ? `${syslogData.total} total messages` : 'No messages'}
              </CardDescription>
            </div>
            {syslogData?.messages?.length > 0 && (
              <Badge variant="secondary">
                Showing {syslogData.messages.length} of {syslogData.total}
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {syslogLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : syslogData?.messages?.length ? (
            <div className="space-y-3">
              {syslogData.messages.map((log: SyslogMessage) => (
                <div key={log.id} className="rounded-lg border p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {getSeverityIcon(log.severity)}
                      <Badge 
                        variant={getSeverityVariant(log.severity)}
                        className="text-xs"
                      >
                        {log.severity_name}
                      </Badge>
                      {log.facility_name && (
                        <Badge variant="outline" className="text-xs">
                          {log.facility_name}
                        </Badge>
                      )}
                      {log.app_name && (
                        <span className="text-xs text-muted-foreground font-mono">
                          {log.app_name}
                        </span>
                      )}
                      {log.proc_id && (
                        <span className="text-xs text-muted-foreground font-mono">
                          [{log.proc_id}]
                        </span>
                      )}
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {new Date(log.received_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-sm font-mono bg-muted/30 p-2 rounded">{log.message}</p>
                  {log.hostname && (
                    <div className="text-xs text-muted-foreground">
                      Host: {log.hostname}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-muted-foreground space-y-4">
              <Search className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <div>
                <p className="text-sm font-medium">No log messages found</p>
                {logSearch || severityFilter !== undefined ? (
                  <p className="text-xs mt-1">Try adjusting your filters</p>
                ) : !syslogConfig?.syslog_enabled ? (
                  <p className="text-xs mt-1">Log collection is not enabled for this printer</p>
                ) : (
                  <div className="mt-4 max-w-md mx-auto">
                    <p className="text-xs mb-3">Configure your printer to send RFC 5424 syslog messages to:</p>
                    <div className="flex items-center justify-center gap-2 mb-3">
                      <code className="rounded bg-muted px-3 py-2 font-mono text-sm">
                        {syslogConfig?.syslog_destination}
                      </code>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      For HP printers: Settings → Network → Advanced → Syslog Server
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

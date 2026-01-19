import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '@/lib/api';
import { PrinterCard } from '@/components/printers/PrinterCard';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';
import {
  Printer,
  CheckCircle,
  XCircle,
  ArrowRightLeft,
  Loader2,
} from 'lucide-react';
import type { PrinterStatus } from '@/types/api';

export function DashboardPage() {
  const { data: printers, isLoading, refetch, isRefetching } = useQuery<PrinterStatus[]>({
    queryKey: ['dashboard', 'status'],
    queryFn: dashboardApi.getStatus,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const stats = [
    {
      label: 'Total Printers',
      value: printers?.length || 0,
      icon: Printer,
      tone: 'bg-primary/10 text-primary',
    },
    {
      label: 'Online',
      value: printers?.filter((p) => p.is_online && !p.has_redirect).length || 0,
      icon: CheckCircle,
      tone: 'bg-success/10 text-success',
    },
    {
      label: 'Offline',
      value: printers?.filter((p) => !p.is_online && !p.has_redirect).length || 0,
      icon: XCircle,
      tone: 'bg-error/10 text-error',
    },
    {
      label: 'Redirected',
      value: printers?.filter((p) => p.has_redirect).length || 0,
      icon: ArrowRightLeft,
      tone: 'bg-warning/10 text-warning',
    },
  ];

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {printers && printers.length === 0 ? (
        <div className="flex min-h-[calc(100vh-9rem)] flex-col gap-6">
          <div className="rounded-2xl border border-border bg-gradient-to-br from-background via-background to-muted/60 p-8 lg:p-12">
            <div className="grid gap-8 lg:grid-cols-2 lg:items-center">
              <div>
                <p className="text-sm font-semibold uppercase tracking-wide text-primary">Printer Proxy</p>
                <h2 className="mt-3 text-3xl font-semibold">Keep printing, even when hardware fails.</h2>
                <p className="mt-4 text-base text-muted-foreground">
                  Automatically reroute print traffic and maintain uptime without asking users to
                  change drivers or IPs. Monitor health, detect issues early, and stay ahead of outages.
                </p>
                <p className="mt-4 text-sm text-muted-foreground">
                  Ready to get started? Visit the Printers page to add your first device.
                </p>
                <Link to="/printers?add=1" className="mt-4 inline-flex text-sm font-medium text-primary underline-offset-4 hover:underline">
                  Go to Printers
                </Link>
              </div>
              <div className="grid gap-4">
                <Card className="shadow-sm">
                  <CardContent className="space-y-2 p-5">
                    <p className="text-sm font-semibold">Failover without disruption</p>
                    <p className="text-sm text-muted-foreground">
                      Preserve the same destination IP while traffic is forwarded to a healthy printer.
                    </p>
                  </CardContent>
                </Card>
                <Card className="shadow-sm">
                  <CardContent className="space-y-2 p-5">
                    <p className="text-sm font-semibold">Live status intelligence</p>
                    <p className="text-sm text-muted-foreground">
                      Health checks, SNMP telemetry, and redirect visibility in one place.
                    </p>
                  </CardContent>
                </Card>
                <Card className="shadow-sm">
                  <CardContent className="space-y-2 p-5">
                    <p className="text-sm font-semibold">Designed for IT teams</p>
                    <p className="text-sm text-muted-foreground">
                      Quick setup, role-based access, and audit trails for compliance.
                    </p>
                  </CardContent>
                </Card>
              </div>
            </div>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="shadow-sm">
              <CardContent className="space-y-4 p-6">
                <p className="text-sm font-semibold text-foreground">Start with your first printer</p>
                <p className="text-sm text-muted-foreground">
                  Add a device to begin health checks, telemetry, and automatic failover workflows.
                </p>
                <div className="space-y-2 rounded-lg bg-muted/50 p-4 text-sm text-muted-foreground">
                  <p>• Provide name, IP address, and location.</p>
                  <p>• Save once, then monitor status here.</p>
                </div>
                <Link
                  to="/printers?add=1"
                  className="text-sm font-medium text-primary underline-offset-4 hover:underline"
                >
                  Go to Printers
                </Link>
              </CardContent>
            </Card>

            <Card className="shadow-sm">
              <CardContent className="space-y-4 p-6">
                <p className="text-sm font-semibold text-foreground">Discover printers automatically</p>
                <p className="text-sm text-muted-foreground">
                  Run a discovery scan to find devices on your network and add them in seconds.
                </p>
                <div className="space-y-2 rounded-lg bg-muted/50 p-4 text-sm text-muted-foreground">
                  <p>• Scan the default subnet or specify a CIDR block.</p>
                  <p>• Review the list and add the ones you want.</p>
                </div>
                <Link
                  to="/printers?add=1"
                  className="text-sm font-medium text-primary underline-offset-4 hover:underline"
                >
                  Open Discovery
                </Link>
              </CardContent>
            </Card>
          </div>
        </div>
      ) : (
        <>
          {/* Header */}
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h1 className="text-2xl font-bold">Dashboard</h1>
              <p className="text-muted-foreground">Monitor and manage your printers</p>
            </div>
          </div>

          {/* Stats cards */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {stats.map((stat) => (
              <Card key={stat.label} className="shadow-sm">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <p className="text-sm font-medium text-muted-foreground">{stat.label}</p>
                  <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${stat.tone}`}>
                    <stat.icon className="h-5 w-5" />
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-3xl font-semibold">{stat.value}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {printers?.map((printerStatus) => (
              <PrinterCard key={printerStatus.printer.id} printerStatus={printerStatus} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

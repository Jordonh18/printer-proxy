import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '@/lib/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from '@/components/ui/chart';
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';
import { Loader2, Plus, Printer, RotateCcw } from 'lucide-react';
import { Bar, BarChart } from 'recharts';
import { useDocumentTitle } from '@/hooks/use-document-title';
import type { DashboardAnalytics, PrinterStatus } from '@/types/api';

export function DashboardPage() {
  useDocumentTitle('Dashboard');
  const { data: printers, isLoading } = useQuery<PrinterStatus[]>({
    queryKey: ['dashboard', 'status'],
    queryFn: dashboardApi.getStatus,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const {
    data: analytics,
    isLoading: isAnalyticsLoading,
    isFetching: isAnalyticsFetching,
  } = useQuery<DashboardAnalytics>({
    queryKey: ['dashboard', 'analytics'],
    queryFn: dashboardApi.getAnalytics,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  });


  const stats = [
    {
      label: 'Total Printers',
      value: printers?.length || 0,
    },
    {
      label: 'Online',
      value:
        printers?.filter((p) => (p.status?.is_online ?? (p as unknown as { is_online?: boolean }).is_online) && !(p.status?.is_redirected ?? (p as unknown as { has_redirect?: boolean }).has_redirect)).length ||
        0,
    },
    {
      label: 'Offline',
      value:
        printers?.filter((p) => !(p.status?.is_online ?? (p as unknown as { is_online?: boolean }).is_online) && !(p.status?.is_redirected ?? (p as unknown as { has_redirect?: boolean }).has_redirect)).length ||
        0,
    },
    {
      label: 'Redirected',
      value: printers?.filter((p) => p.status?.is_redirected ?? (p as unknown as { has_redirect?: boolean }).has_redirect).length || 0,
    },
  ];

  const modelCounts = printers?.reduce<Record<string, number>>((acc, p) => {
    const model = p.printer.model || 'Unknown';
    acc[model] = (acc[model] || 0) + 1;
    return acc;
  }, {}) ?? {};

  const modelBarData = Object.entries(modelCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([model, count]) => ({ model, count }));


  const pagesByPrinterData = analytics?.top_pages?.map((row) => ({
    name: row.name,
    pages: row.total_pages,
    uptime: row.uptime_hours ?? 0,
  })) ?? [];

  // Create uptime data sorted by uptime for better visualization
  const uptimeData = [...pagesByPrinterData]
    .filter(row => row.uptime > 0)
    .sort((a, b) => b.uptime - a.uptime);

  const hasPagesByPrinter = pagesByPrinterData.length > 0 && pagesByPrinterData.some((row) => row.pages > 0);
  const hasUptime = uptimeData.length > 0;

  const atRiskPrinters = printers
    ?.filter((p) => {
      const isOnline = p.status?.is_online ?? (p as unknown as { is_online?: boolean }).is_online ?? false;
      const tcp = p.status?.tcp_reachable ?? (p as unknown as { tcp_reachable?: boolean }).tcp_reachable ?? false;
      return !isOnline || !tcp;
    })
    .slice(0, 5);

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
                <CardHeader className="pb-2">
                  <p className="text-sm font-medium text-muted-foreground">{stat.label}</p>
                </CardHeader>
                <CardContent>
                  <p className="text-3xl font-semibold">{stat.value}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Charts Row - 3 columns */}
          <div className="grid gap-4 md:grid-cols-3">
            {/* Total Pages by Printer */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base">Total Pages by Printer</CardTitle>
              </CardHeader>
              <CardContent>
                {isAnalyticsLoading || isAnalyticsFetching ? (
                  <div className="flex h-[220px] items-center justify-center">
                    <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                  </div>
                ) : hasPagesByPrinter ? (
                  <ChartContainer
                    config={{
                      pages: { label: 'Total Pages', color: 'hsl(var(--chart-1))' },
                    }}
                    className="h-[220px] w-full"
                  >
                    <BarChart
                      accessibilityLayer
                      data={pagesByPrinterData.slice(0, 15)}
                      margin={{ left: 0, right: 0, top: 4, bottom: 4 }}
                      barCategoryGap={0}
                    >
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            labelFormatter={(_, payload) => payload?.[0]?.payload?.name || ''}
                          />
                        }
                      />
                      <Bar dataKey="pages" fill="var(--color-pages)" radius={[3, 3, 0, 0]} minPointSize={4} />
                    </BarChart>
                  </ChartContainer>
                ) : (
                  <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
                    No page data yet
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Top Printer Models */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base">Top Models</CardTitle>
              </CardHeader>
              <CardContent>
                {modelBarData.length > 0 ? (
                  <ChartContainer
                    config={{
                      count: { label: 'Count', color: 'hsl(var(--chart-2))' },
                    }}
                    className="h-[220px] w-full"
                  >
                    <BarChart
                      accessibilityLayer
                      data={modelBarData.slice(0, 15)}
                      margin={{ left: 0, right: 0, top: 4, bottom: 4 }}
                      barCategoryGap={0}
                    >
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            labelFormatter={(_, payload) => payload?.[0]?.payload?.model || ''}
                          />
                        }
                      />
                      <Bar dataKey="count" fill="var(--color-count)" radius={[3, 3, 0, 0]} minPointSize={4} />
                    </BarChart>
                  </ChartContainer>
                ) : (
                  <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
                    No model data
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Uptime Leaders */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base">Uptime Leaders</CardTitle>
              </CardHeader>
              <CardContent>
                {hasUptime ? (
                  <ChartContainer
                    config={{
                      uptime: { label: 'Uptime (hours)', color: 'hsl(var(--chart-3))' },
                    }}
                    className="h-[220px] w-full"
                  >
                    <BarChart
                      accessibilityLayer
                      data={uptimeData.slice(0, 15)}
                      margin={{ left: 0, right: 0, top: 4, bottom: 4 }}
                      barCategoryGap={0}
                    >
                      <ChartTooltip
                        cursor={false}
                        content={
                          <ChartTooltipContent
                            labelFormatter={(_, payload) => payload?.[0]?.payload?.name || ''}
                          />
                        }
                      />
                      <Bar dataKey="uptime" fill="var(--color-uptime)" radius={[3, 3, 0, 0]} minPointSize={4} />
                    </BarChart>
                  </ChartContainer>
                ) : (
                  <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
                    No uptime data
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* At-Risk and Quick Actions row */}
          <div className="grid gap-4 md:grid-cols-2">
            {/* At-Risk Printers */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle>At-Risk Printers</CardTitle>
                {!atRiskPrinters?.length && (
                  <CardDescription>No printers currently at risk.</CardDescription>
                )}
              </CardHeader>
              <CardContent className="flex h-full flex-col gap-2">
                {atRiskPrinters?.length ? (
                  <div className="space-y-2">
                    {atRiskPrinters.slice(0, 3).map((item) => (
                      <div key={item.printer.id} className="flex items-center gap-2">
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{item.printer.name}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex-1" />
                )}
                <Link to="/printers" className="mt-auto text-xs text-primary hover:underline">
                  View all printers
                </Link>
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle>Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-1.5">
                <Button variant="outline" size="sm" className="justify-start gap-2 h-8" asChild>
                  <Link to="/printers?add=1">
                    <Plus className="h-3.5 w-3.5" />
                    Add printer
                  </Link>
                </Button>
                <Button variant="outline" size="sm" className="justify-start gap-2 h-8" asChild>
                  <Link to="/printers">
                    <Printer className="h-3.5 w-3.5" />
                    View printers
                  </Link>
                </Button>
                <Button variant="outline" size="sm" className="justify-start gap-2 h-8" asChild>
                  <Link to="/redirects">
                    <RotateCcw className="h-3.5 w-3.5" />
                    Redirects
                  </Link>
                </Button>
              </CardContent>
            </Card>
          </div>

        </>
      )}
    </div>
  );
}

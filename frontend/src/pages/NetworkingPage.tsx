/**
 * NetworkingPage - Comprehensive view of network state managed by Continuum
 */

import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { networkApi } from '@/lib/api';
import { useDocumentTitle } from '@/hooks/use-document-title';
import { useAuth } from '@/contexts/AuthContext';
import { toast } from '@/lib/toast';

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Loader2,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Radio,
  Activity,
  Send,
} from 'lucide-react';

import type {
  NetworkOverview,
  PortInfo,
  SafetyInfo,
  DiagnosticResult,
} from '@/types/api';

// ============================================================================
// Main Page Component
// ============================================================================

export function NetworkingPage() {
  useDocumentTitle('Networking');
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const isAdmin = user?.role === 'admin';

  const [arpOnlyOwned, setArpOnlyOwned] = useState(true);
  const [reAnnounceIp, setReAnnounceIp] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [showSudoPrompt, setShowSudoPrompt] = useState(false);
  const [sudoPassword, setSudoPassword] = useState('');
  const [sudoError, setSudoError] = useState('');
  const [interfaceDetailModal, setInterfaceDetailModal] = useState<string | null>(null);
  const [ipDetailModal, setIpDetailModal] = useState<string | null>(null);
  const [isSudoReady, setIsSudoReady] = useState(false);

  // Check if sudo is available FIRST (before any network queries)
  useEffect(() => {
    const checkSudo = async () => {
      try {
        const result = await networkApi.checkSudoStatus();
        if (result.sudo_available) {
          // Sudo is available without password, proceed
          setIsSudoReady(true);
        } else {
          // Need sudo password, show prompt immediately
          setShowSudoPrompt(true);
        }
      } catch {
        // If check fails, assume sudo is available (production mode)
        setIsSudoReady(true);
      }
    };
    checkSudo();
  }, []);

  // Network queries - ONLY run after sudo is ready
  const {
    data: overview,
    isLoading,
  } = useQuery<NetworkOverview>({
    queryKey: ['network', 'overview'],
    queryFn: networkApi.getOverview,
    refetchInterval: 5000,
    enabled: isSudoReady, // Block until sudo is authenticated
  });

  const { data: portsData } = useQuery({
    queryKey: ['network', 'ports'],
    queryFn: networkApi.getPorts,
    refetchInterval: 10000,
    enabled: isSudoReady, // Block until sudo is authenticated
  });

  const { data: safetyData, refetch: refetchSafety } = useQuery({
    queryKey: ['network', 'safety'],
    queryFn: networkApi.getSafety,
    refetchInterval: 30000,
    // Safety settings can load immediately - reading from DB doesn't need sudo
  });

  const sudoAuthMutation = useMutation({
    mutationFn: (password: string) => networkApi.authenticateSudo(password),
    onSuccess: (data) => {
      if (data.success) {
        toast.success('Sudo authentication successful');
        setShowSudoPrompt(false);
        setSudoPassword('');
        setSudoError('');
        setIsSudoReady(true); // Enable network queries
      } else {
        setSudoError(data.error || 'Authentication failed');
      }
    },
    onError: () => {
      setSudoError('Failed to authenticate');
    },
  });

  const reAnnounceMutation = useMutation({
    mutationFn: (ip: string) => networkApi.diagnostics.reAnnounceArp(ip, true),
    onSuccess: (data) => {
      if (data.success) {
        toast.success('ARP announcement sent');
        queryClient.invalidateQueries({ queryKey: ['network'] });
      } else {
        toast.error(data.error || 'Failed to send ARP announcement');
      }
      setReAnnounceIp(null);
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { error?: string } } };
      const message = axiosErr?.response?.data?.error || 'Failed to send ARP announcement';
      toast.error(message);
      setReAnnounceIp(null);
    },
  });

  const toggleSafetyMutation = useMutation({
    mutationFn: ({ key, enabled }: { key: string; enabled: boolean }) =>
      networkApi.updateSafetySetting(key, enabled),
    onSuccess: () => {
      refetchSafety();
      toast.success('Safety setting updated');
    },
    onError: () => {
      toast.error('Failed to update safety setting');
    },
  });

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  const routing = overview?.routing || {
    ip_forwarding: false,
    nat_enabled: false,
    policy_routing: false,
    default_gateway: null,
    default_interface: null,
  };

  // Find the primary interface (the one with the default route, not secondary IPs)
  const primaryInterface = overview?.interfaces?.find(i => 
    i.name === routing.default_interface && i.state === 'up'
  ) || overview?.interfaces?.find(i => i.state === 'up' && !i.is_secondary) || overview?.interfaces?.[0];
  
  const claimedCount = overview?.claimed_ips?.length || 0;
  const activeFlows = overview?.traffic_flows?.length || 0;
  const hasWarnings = (overview?.warnings?.length || 0) > 0;

  const selectedInterface = overview?.interfaces?.find(i => i.name === interfaceDetailModal);
  const selectedClaimedIp = overview?.claimed_ips?.find(ip => ip.ip === ipDetailModal);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Networking</h1>
        <p className="text-muted-foreground">
          Network state and traffic flow visibility
        </p>
      </div>

      {/* Warnings Banner */}
      {hasWarnings && (
        <div className="rounded-lg border border-warning/50 bg-warning/10 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-warning shrink-0 mt-0.5" />
            <div className="space-y-1">
              {overview?.warnings?.map((w, i) => (
                <p key={i} className="text-sm">
                  <span className="font-medium">{w.message}</span>
                  {w.remediation && (
                    <span className="text-muted-foreground"> — {w.remediation}</span>
                  )}
                </p>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Summary Stats Row */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <p className="text-sm font-medium text-muted-foreground">Primary Interface</p>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-semibold font-mono">
              {primaryInterface?.name || '—'}
            </span>
            <p className="text-sm text-muted-foreground mt-1">
              {primaryInterface?.primary_ip || 'No IP assigned'}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <p className="text-sm font-medium text-muted-foreground">IP Forwarding</p>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-semibold">
              {routing.ip_forwarding ? 'Enabled' : 'Disabled'}
            </span>
            <p className="text-sm text-muted-foreground mt-1">
              NAT {routing.nat_enabled ? 'active' : 'inactive'}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <p className="text-sm font-medium text-muted-foreground">Claimed IPs</p>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-semibold">{claimedCount}</p>
            <p className="text-sm text-muted-foreground mt-1">
              Secondary addresses
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <p className="text-sm font-medium text-muted-foreground">Active Redirects</p>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-semibold">{activeFlows}</p>
            <p className="text-sm text-muted-foreground mt-1">
              Traffic flows
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content - Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-4 lg:w-auto lg:inline-grid">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="traffic">Traffic</TabsTrigger>
          <TabsTrigger value="diagnostics">Diagnostics</TabsTrigger>
          {isAdmin && <TabsTrigger value="advanced">Advanced</TabsTrigger>}
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6 mt-6">
          <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
            {/* Left Column - Main Info */}
            <div className="space-y-6">
              {/* Network Interfaces */}
              <Card>
                <CardHeader>
                  <CardTitle>Network Interfaces</CardTitle>
                  <CardDescription>Physical and virtual interfaces on this host</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {overview?.interfaces?.map((iface) => (
                      <div
                        key={iface.name}
                        className="flex items-center justify-between rounded-lg border p-3 cursor-pointer hover:bg-muted/50 transition-colors"
                        onClick={() => setInterfaceDetailModal(iface.name)}
                      >
                        <div className="flex items-center gap-3">
                          {iface.state === 'up' ? (
                            <div className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
                          ) : (
                            <div className="h-2.5 w-2.5 rounded-full bg-muted-foreground" />
                          )}
                          <div>
                            <p className="font-mono font-medium">{iface.name}</p>
                            <p className="text-sm text-muted-foreground">
                              {iface.primary_ip ? `${iface.primary_ip}/${iface.cidr || '24'}` : 'No IP'}
                              {iface.mac && <span className="ml-2 text-xs">{iface.mac}</span>}
                            </p>
                          </div>
                        </div>
                        <div className="text-right text-sm text-muted-foreground">
                          <p>MTU {iface.mtu}</p>
                          <p>Speed: {iface.speed && iface.speed !== 'unknown' ? iface.speed : 'Unknown'}</p>
                        </div>
                      </div>
                    ))}
                    {!overview?.interfaces?.length && (
                      <p className="text-center text-muted-foreground py-4">No interfaces found</p>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Claimed IPs */}
              <Card>
                <CardHeader>
                  <CardTitle>Claimed IP Addresses</CardTitle>
                  <CardDescription>Secondary IPs assigned for print traffic interception</CardDescription>
                </CardHeader>
                <CardContent>
                  {overview?.claimed_ips?.length ? (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>IP Address</TableHead>
                          <TableHead>Interface</TableHead>
                          <TableHead>Owner</TableHead>
                          <TableHead className="w-[80px]"></TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {overview.claimed_ips.map((ip) => (
                          <TableRow 
                            key={ip.ip} 
                            className="cursor-pointer hover:bg-muted/50"
                            onClick={() => setIpDetailModal(ip.ip)}
                          >
                            <TableCell className="font-mono">{ip.ip}</TableCell>
                            <TableCell className="font-mono text-muted-foreground">{ip.interface}</TableCell>
                            <TableCell>
                              {ip.owner_name || <span className="text-muted-foreground">—</span>}
                            </TableCell>
                            <TableCell>
                              {isAdmin && (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setReAnnounceIp(ip.ip);
                                  }}
                                  title="Re-announce ARP"
                                >
                                  <Radio className="h-4 w-4" />
                                </Button>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  ) : (
                    <p className="text-center text-muted-foreground py-8">
                      No secondary IPs currently claimed
                    </p>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Right Column - Sidebar Info */}
            <div className="space-y-6">
              {/* Routing Status */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Routing Configuration</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Default Gateway</span>
                    <span className="font-mono">{routing.default_gateway || '—'}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Default Interface</span>
                    <span className="font-mono">{routing.default_interface || '—'}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">IP Forwarding</span>
                    <span className={routing.ip_forwarding ? 'text-emerald-600 font-medium' : 'text-destructive font-medium'}>
                      {routing.ip_forwarding ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">NAT Active</span>
                    <span className={routing.nat_enabled ? 'text-emerald-600 font-medium' : 'text-muted-foreground'}>
                      {routing.nat_enabled ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Policy Routing</span>
                    <span className="text-muted-foreground">
                      {routing.policy_routing ? 'In Use' : 'Not Used'}
                    </span>
                  </div>
                </CardContent>
              </Card>

              {/* Intercepted Ports */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Intercepted Ports</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {portsData?.ports?.map((port: PortInfo) => (
                      <div
                        key={port.port}
                        className="flex items-center justify-between rounded border px-3 py-2"
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-mono">{port.port}</span>
                          <span className="text-sm text-muted-foreground capitalize">
                            {port.name}
                          </span>
                        </div>
                        <span className="text-sm text-muted-foreground">{port.redirect_count} redirects</span>
                      </div>
                    ))}
                    {!portsData?.ports?.length && (
                      <p className="text-sm text-muted-foreground text-center py-4">
                        No ports configured
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Safety Controls - Now with toggles */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Safety Controls</CardTitle>
                  <CardDescription>Toggle to enable/disable protections</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {[
                    { key: 'ip_conflict_detection', label: 'IP Conflict Detection', description: 'Check for IP conflicts before claiming' },
                    { key: 'refuse_active_ips', label: 'Refuse Active IPs', description: 'Block claiming IPs that respond to ARP' },
                    { key: 'arp_rate_limiting', label: 'ARP Rate Limiting', description: 'Limit ARP announcement frequency' },
                  ].map(({ key, label, description }) => {
                    const enabled = safetyData?.safety?.[key as keyof SafetyInfo] as boolean;
                    return (
                      <div key={key} className="flex items-start justify-between gap-4">
                        <div className="space-y-0.5">
                          <Label htmlFor={key} className="text-sm font-medium">{label}</Label>
                          <p className="text-xs text-muted-foreground">{description}</p>
                        </div>
                        <Switch
                          id={key}
                          checked={enabled}
                          onCheckedChange={(checked) => {
                            if (isAdmin) {
                              toggleSafetyMutation.mutate({ key, enabled: checked });
                            } else {
                              toast.error('Admin access required');
                            }
                          }}
                          disabled={!isAdmin || toggleSafetyMutation.isPending}
                        />
                      </div>
                    );
                  })}
                  <div className="pt-2 border-t">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Claimed IPs</span>
                      <span>
                        {safetyData?.safety?.current_claimed_count || 0} / {safetyData?.safety?.max_claimed_ips_per_interface || 50}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        {/* Traffic Tab */}
        <TabsContent value="traffic" className="space-y-6 mt-6">
          {/* Active Flows */}
          <Card>
            <CardHeader>
              <CardTitle>Active Traffic Flows</CardTitle>
              <CardDescription>Real-time redirect traffic interception and forwarding</CardDescription>
            </CardHeader>
            <CardContent>
              {overview?.traffic_flows?.length ? (
                <div className="space-y-4">
                  {overview.traffic_flows.map((flow) => (
                    <div
                      key={flow.redirect_id}
                      className="flex flex-col gap-4 rounded-lg border p-4 sm:flex-row sm:items-center"
                    >
                      {/* Source */}
                      <div className="flex-1">
                        <p className="font-medium">{flow.source_printer_name}</p>
                        <p className="text-sm font-mono text-muted-foreground">
                          {flow.source_ip}:{flow.source_port}
                        </p>
                      </div>

                      {/* Arrow */}
                      <div className="flex items-center gap-2 text-muted-foreground">
                        <ArrowRight className="h-5 w-5" />
                        <span className="text-xs uppercase">{flow.nat_type}</span>
                      </div>

                      {/* Target */}
                      <div className="flex-1">
                        <p className="font-medium">{flow.target_printer_name}</p>
                        <p className="text-sm font-mono text-muted-foreground">
                          {flow.target_ip}:{flow.target_port}
                        </p>
                      </div>

                      {/* Stats */}
                      <div className="flex gap-4 text-sm">
                        <div className="text-center">
                          <p className="font-mono font-medium">{flow.active_connections}</p>
                          <p className="text-xs text-muted-foreground">conns</p>
                        </div>
                        <div className="text-center">
                          <p className="font-mono font-medium">{flow.bytes_forwarded}</p>
                          <p className="text-xs text-muted-foreground">bytes</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12">
                  <Activity className="h-12 w-12 text-muted-foreground/50 mx-auto mb-4" />
                  <p className="text-lg font-medium">No Active Redirects</p>
                  <p className="text-sm text-muted-foreground">
                    Traffic flows will appear here when redirects are active
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* ARP Table */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>ARP / Neighbour Table</CardTitle>
                  <CardDescription>Layer 2 address resolution entries</CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Switch
                    id="arp-filter"
                    checked={arpOnlyOwned}
                    onCheckedChange={setArpOnlyOwned}
                  />
                  <Label htmlFor="arp-filter" className="text-sm">
                    Only owned IPs
                  </Label>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <ArpTableContent onlyOwned={arpOnlyOwned} />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Diagnostics Tab */}
        <TabsContent value="diagnostics" className="space-y-6 mt-6">
          <DiagnosticsPanel />
        </TabsContent>

        {/* Advanced Tab (Admin Only) */}
        {isAdmin && (
          <TabsContent value="advanced" className="space-y-6 mt-6">
            <AdvancedPanel />
          </TabsContent>
        )}
      </Tabs>

      {/* ARP Re-announce Confirmation Dialog */}
      <AlertDialog open={!!reAnnounceIp} onOpenChange={() => setReAnnounceIp(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Re-announce ARP?</AlertDialogTitle>
            <AlertDialogDescription>
              This will send gratuitous ARP packets for <code className="font-mono bg-muted px-1 rounded">{reAnnounceIp}</code> on the network.
              This helps update switches and routers with the correct MAC address.
              <br /><br />
              This action will be logged.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => reAnnounceIp && reAnnounceMutation.mutate(reAnnounceIp)}
              disabled={reAnnounceMutation.isPending}
            >
              {reAnnounceMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Send ARP
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Interface Detail Modal */}
      <Dialog open={!!interfaceDetailModal} onOpenChange={() => setInterfaceDetailModal(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="font-mono">{selectedInterface?.name}</DialogTitle>
            <DialogDescription>Network interface details</DialogDescription>
          </DialogHeader>
          {selectedInterface && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground">State</p>
                  <p className="font-medium capitalize">{selectedInterface.state}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">MAC Address</p>
                  <p className="font-mono">{selectedInterface.mac || '—'}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">IP Address</p>
                  <p className="font-mono">{selectedInterface.primary_ip || '—'}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">CIDR</p>
                  <p className="font-mono">/{selectedInterface.cidr || '—'}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">MTU</p>
                  <p>{selectedInterface.mtu}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Speed</p>
                  <p>{selectedInterface.speed && selectedInterface.speed !== 'unknown' ? selectedInterface.speed : 'Unknown'}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Gateway</p>
                  <p className="font-mono">{selectedInterface.gateway || '—'}</p>
                </div>
                {selectedInterface.vlan && (
                  <div>
                    <p className="text-muted-foreground">VLAN ID</p>
                    <p>{selectedInterface.vlan}</p>
                  </div>
                )}
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setInterfaceDetailModal(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* IP Detail Modal */}
      <Dialog open={!!ipDetailModal} onOpenChange={() => setIpDetailModal(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="font-mono">{selectedClaimedIp?.ip}</DialogTitle>
            <DialogDescription>Claimed IP address details</DialogDescription>
          </DialogHeader>
          {selectedClaimedIp && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground">Interface</p>
                  <p className="font-mono">{selectedClaimedIp.interface}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Status</p>
                  <p className="capitalize">{selectedClaimedIp.status}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Owner Type</p>
                  <p className="capitalize">{selectedClaimedIp.owner_type}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Owner</p>
                  <p>{selectedClaimedIp.owner_name || '—'}</p>
                </div>
              </div>
              {isAdmin && (
                <div className="pt-4 border-t">
                  <Button
                    variant="outline"
                    onClick={() => {
                      setIpDetailModal(null);
                      setReAnnounceIp(selectedClaimedIp.ip);
                    }}
                  >
                    <Radio className="mr-2 h-4 w-4" />
                    Re-announce ARP
                  </Button>
                </div>
              )}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setIpDetailModal(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Sudo Password Prompt Modal */}
      <Dialog open={showSudoPrompt} onOpenChange={setShowSudoPrompt}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Sudo Authentication Required</DialogTitle>
            <DialogDescription>
              Network operations require elevated privileges. Please enter your password to continue.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="sudo-password">Password</Label>
              <Input
                id="sudo-password"
                type="password"
                value={sudoPassword}
                onChange={(e) => setSudoPassword(e.target.value)}
                placeholder="Enter your sudo password"
                className="mt-1"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && sudoPassword) {
                    sudoAuthMutation.mutate(sudoPassword);
                  }
                }}
              />
            </div>
            {sudoError && (
              <p className="text-sm text-destructive">{sudoError}</p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowSudoPrompt(false)}>
              Skip for Now
            </Button>
            <Button
              onClick={() => sudoAuthMutation.mutate(sudoPassword)}
              disabled={!sudoPassword || sudoAuthMutation.isPending}
            >
              {sudoAuthMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Authenticate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ============================================================================
// Sub-components
// ============================================================================

function ArpTableContent({ onlyOwned }: { onlyOwned: boolean }) {
  const { data, isLoading } = useQuery({
    queryKey: ['network', 'arp-table', onlyOwned],
    queryFn: () => networkApi.getArpTable(onlyOwned),
    refetchInterval: 10000,
  });

  if (isLoading) {
    return (
      <div className="flex justify-center py-8">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!data?.entries?.length) {
    return (
      <p className="text-center text-muted-foreground py-8">
        {onlyOwned ? 'No owned IPs in ARP table' : 'ARP table is empty'}
      </p>
    );
  }

  const getStateColor = (state: string) => {
    switch (state) {
      case 'REACHABLE': return 'text-emerald-600';
      case 'STALE': return 'text-yellow-600';
      case 'FAILED': return 'text-destructive';
      default: return 'text-muted-foreground';
    }
  };

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>IP Address</TableHead>
          <TableHead>MAC Address</TableHead>
          <TableHead>Interface</TableHead>
          <TableHead>State</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.entries.map((entry: { ip: string; mac?: string; interface: string; state: string }, idx: number) => (
          <TableRow key={`${entry.ip}-${idx}`}>
            <TableCell className="font-mono">{entry.ip}</TableCell>
            <TableCell className="font-mono text-sm text-muted-foreground">{entry.mac || '—'}</TableCell>
            <TableCell className="font-mono">{entry.interface}</TableCell>
            <TableCell>
              <span className={`font-medium ${getStateColor(entry.state)}`}>
                {entry.state}
              </span>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function DiagnosticsPanel() {
  const [targetIp, setTargetIp] = useState('');
  const [targetPort, setTargetPort] = useState('9100');
  const [results, setResults] = useState<Array<{ type: string; result: DiagnosticResult; timestamp: Date }>>([]);

  const pingMutation = useMutation({
    mutationFn: (ip: string) => networkApi.diagnostics.ping(ip),
    onSuccess: (data) => {
      setResults((prev) => [{ type: 'ping', result: data.result, timestamp: new Date() }, ...prev]);
      if (data.result.result === 'success') {
        toast.success(`Ping: ${data.result.rtt_ms}ms`);
      } else {
        toast.error('Ping failed');
      }
    },
    onError: () => toast.error('Ping test failed'),
  });

  const arpProbeMutation = useMutation({
    mutationFn: (ip: string) => networkApi.diagnostics.arpProbe(ip),
    onSuccess: (data) => {
      setResults((prev) => [{ type: 'arp', result: data.result, timestamp: new Date() }, ...prev]);
      if (data.result.result === 'response') {
        toast.success(`ARP: ${data.result.mac}`);
      } else {
        toast.info('No ARP response');
      }
    },
    onError: () => toast.error('ARP probe failed'),
  });

  const tcpTestMutation = useMutation({
    mutationFn: ({ ip, port }: { ip: string; port: number }) =>
      networkApi.diagnostics.tcpTest(ip, port),
    onSuccess: (data) => {
      setResults((prev) => [{ type: 'tcp', result: data.result, timestamp: new Date() }, ...prev]);
      if (data.result.result === 'success') {
        toast.success(`TCP: ${data.result.latency_ms}ms`);
      } else {
        toast.error('TCP connection failed');
      }
    },
    onError: () => toast.error('TCP test failed'),
  });

  const runTest = (type: 'ping' | 'arp' | 'tcp') => {
    if (!targetIp.trim()) {
      toast.error('Enter an IP address');
      return;
    }
    if (type === 'tcp') {
      const port = parseInt(targetPort, 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        toast.error('Invalid port');
        return;
      }
      tcpTestMutation.mutate({ ip: targetIp.trim(), port });
    } else if (type === 'arp') {
      arpProbeMutation.mutate(targetIp.trim());
    } else {
      pingMutation.mutate(targetIp.trim());
    }
  };

  const isLoading = pingMutation.isPending || arpProbeMutation.isPending || tcpTestMutation.isPending;

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_2fr]">
      {/* Controls */}
      <Card>
        <CardHeader>
          <CardTitle>Network Tests</CardTitle>
          <CardDescription>Safe, logged diagnostic tools</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="diag-ip">Target IP</Label>
            <Input
              id="diag-ip"
              placeholder="192.168.1.100"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              className="font-mono mt-1"
            />
          </div>
          <div>
            <Label htmlFor="diag-port">Port (TCP only)</Label>
            <Input
              id="diag-port"
              placeholder="9100"
              value={targetPort}
              onChange={(e) => setTargetPort(e.target.value)}
              className="font-mono mt-1"
            />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <Button
              variant="outline"
              onClick={() => runTest('ping')}
              disabled={isLoading}
              className="w-full"
            >
              {pingMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Ping'}
            </Button>
            <Button
              variant="outline"
              onClick={() => runTest('arp')}
              disabled={isLoading}
              className="w-full"
            >
              {arpProbeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'ARP'}
            </Button>
            <Button
              variant="outline"
              onClick={() => runTest('tcp')}
              disabled={isLoading}
              className="w-full"
            >
              {tcpTestMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'TCP'}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            All tests are logged to the Audit Log
          </p>
        </CardContent>
      </Card>

      {/* Results */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Results</CardTitle>
            {results.length > 0 && (
              <Button variant="ghost" size="sm" onClick={() => setResults([])}>
                Clear
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {results.length > 0 ? (
            <div className="space-y-2 max-h-[400px] overflow-y-auto">
              {results.map((r, idx) => (
                <div
                  key={idx}
                  className={`flex items-center justify-between rounded-lg border p-3 ${
                    r.result.result === 'success' || r.result.result === 'response'
                      ? 'border-emerald-500/30 bg-emerald-500/5'
                      : 'border-destructive/30 bg-destructive/5'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    {r.result.result === 'success' || r.result.result === 'response' ? (
                      <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-destructive" />
                    )}
                    <div>
                      <p className="font-mono text-sm">
                        <span className="uppercase text-xs font-medium mr-2 px-1.5 py-0.5 rounded bg-muted">{r.type}</span>
                        {r.result.ip}
                        {r.result.port && `:${r.result.port}`}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {r.result.result}
                        {(r.result.rtt_ms || r.result.latency_ms) && ` • ${r.result.rtt_ms || r.result.latency_ms}ms`}
                        {r.result.mac && ` • ${r.result.mac}`}
                      </p>
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {r.timestamp.toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-muted-foreground">
              <Send className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>Run a test to see results</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function AdvancedPanel() {
  const [activeCmd, setActiveCmd] = useState<string | null>(null);
  const [output, setOutput] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);

  const commands = [
    { id: 'ip-addr', label: 'ip addr show', fn: () => networkApi.advanced.getIpAddr() },
    { id: 'ip-route', label: 'ip route', fn: () => networkApi.advanced.getIpRoute() },
    { id: 'ip-rule', label: 'ip rule', fn: () => networkApi.advanced.getIpRule() },
    { id: 'nat-rules', label: 'iptables -t nat -S', fn: () => networkApi.advanced.getNatRules() },
  ];

  const runCommand = async (cmd: typeof commands[0]) => {
    setIsLoading(true);
    setActiveCmd(cmd.id);
    try {
      const result = await cmd.fn();
      setOutput(result.output);
    } catch {
      setOutput('Failed to fetch output');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div>
            <CardTitle>Raw Command Output</CardTitle>
            <CardDescription>Read-only view of network configuration commands</CardDescription>
          </div>
          <span className="text-xs text-warning flex items-center gap-1">
            <AlertTriangle className="h-3 w-3" />
            Admin Only
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          {commands.map((cmd) => (
            <Button
              key={cmd.id}
              variant={activeCmd === cmd.id ? 'default' : 'outline'}
              size="sm"
              onClick={() => runCommand(cmd)}
              disabled={isLoading}
            >
              {cmd.label}
            </Button>
          ))}
        </div>

        {isLoading ? (
          <div className="flex justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin" />
          </div>
        ) : output ? (
          <pre className="overflow-x-auto rounded-lg bg-zinc-950 p-4 text-xs font-mono text-zinc-200 max-h-[500px]">
            {output}
          </pre>
        ) : (
          <div className="text-center text-muted-foreground py-12">
            Select a command above
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default NetworkingPage;

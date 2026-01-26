import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { integrationsApi } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
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
  Search,
  Plus,
  Settings,
  ExternalLink,
  CheckCircle2,
  XCircle,
  AlertCircle,
  RefreshCw,
  Trash2,
  Zap,
  Cable,
  Power,
  PowerOff,
  History,
  ArrowUpDown,
} from 'lucide-react';
import { useDocumentTitle } from '@/hooks/use-document-title';
import { toast } from '@/lib/toast';
import type {
  IntegrationMetadata,
  IntegrationConnection,
} from '@/types/api';

// Integration logos - use real icon files from public/icons where available
const INTEGRATION_LOGOS: Record<string, React.ReactNode> = {
  splunk: <img src="/icons/Splunk_logo.svg" alt="Splunk" className="w-full h-full object-contain" />,
  datadog: <img src="/icons/dd_vertical_white.avif" alt="Datadog" className="w-full h-full object-contain" />,
  elastic: <img src="/icons/elasticsearch.svg" alt="Elasticsearch" className="w-full h-full object-contain" />,
  grafana: <img src="/icons/Grafana_logo.svg" alt="Grafana" className="w-full h-full object-contain" />,
  pagerduty: <img src="/icons/pagerduty-icon.svg" alt="PagerDuty" className="w-full h-full object-contain" />,
  opsgenie: <img src="/icons/opsgenie-seeklogo.svg" alt="Opsgenie" className="w-full h-full object-contain" />,
  // Fallback SVGs for integrations without icon files
  syslog: (
    <svg viewBox="0 0 40 40" className="w-full h-full">
      <rect width="40" height="40" rx="8" fill="#4A5568"/>
      <path d="M10 12h20v2H10zM10 17h16v2H10zM10 22h20v2H10zM10 27h12v2H10z" fill="#A0AEC0"/>
      <circle cx="30" cy="28" r="4" fill="#48BB78"/>
    </svg>
  ),
  prometheus: (
    <svg viewBox="0 0 40 40" className="w-full h-full">
      <circle cx="20" cy="20" r="18" fill="#E6522C"/>
      <path d="M20 6c-7.7 0-14 6.3-14 14s6.3 14 14 14 14-6.3 14-14S27.7 6 20 6zm0 25c-6.1 0-11-4.9-11-11s4.9-11 11-11 11 4.9 11 11-4.9 11-11 11z" fill="#fff"/>
      <path d="M20 10v8l6 3.5" stroke="#fff" strokeWidth="2" fill="none"/>
      <circle cx="20" cy="20" r="3" fill="#fff"/>
      <path d="M14 30h12M12 33h16" stroke="#fff" strokeWidth="2"/>
    </svg>
  ),
  newrelic: (
    <svg viewBox="0 0 40 40" className="w-full h-full">
      <rect width="40" height="40" rx="8" fill="#008C99"/>
      <path d="M20 8l10 6v12l-10 6-10-6V14l10-6z" fill="#fff"/>
      <path d="M20 12l6 3.5v7L20 26l-6-3.5v-7L20 12z" fill="#008C99"/>
      <path d="M20 16l3 1.75v3.5L20 23l-3-1.75v-3.5L20 16z" fill="#fff"/>
    </svg>
  ),
  nagios: (
    <svg viewBox="0 0 40 40" className="w-full h-full">
      <rect width="40" height="40" rx="8" fill="#2B2B2B"/>
      <path d="M20 6L8 14v12l12 8 12-8V14L20 6z" fill="#C2CF4A"/>
      <path d="M20 10l8 5.5v9L20 30l-8-5.5v-9L20 10z" fill="#2B2B2B"/>
      <path d="M16 18l4 2.5 4-2.5M16 22l4 2.5 4-2.5" stroke="#C2CF4A" strokeWidth="1.5"/>
    </svg>
  ),
};

// Category labels
const CATEGORY_LABELS: Record<string, string> = {
  all: 'All',
  logging: 'Logging',
  monitoring: 'Monitoring',
  alerting: 'Alerting',
  ticketing: 'Ticketing',
  communication: 'Communication',
  security: 'Security',
  automation: 'Automation',
};

type ConnectionStatus = IntegrationConnection['status'];

const STATUS_CONFIG: Record<ConnectionStatus, { label: string; variant: 'success' | 'warning' | 'error' | 'secondary' | 'info'; icon: typeof CheckCircle2 }> = {
  connected: { label: 'Connected', variant: 'success', icon: CheckCircle2 },
  connecting: { label: 'Connecting...', variant: 'info', icon: Loader2 },
  disconnected: { label: 'Disconnected', variant: 'secondary', icon: PowerOff },
  error: { label: 'Error', variant: 'error', icon: XCircle },
  rate_limited: { label: 'Rate Limited', variant: 'warning', icon: AlertCircle },
  authenticating: { label: 'Authenticating...', variant: 'info', icon: Loader2 },
  pending_oauth: { label: 'Pending OAuth', variant: 'warning', icon: AlertCircle },
};

export function AdminIntegrationsPage() {
  useDocumentTitle('Integrations Marketplace');
  const queryClient = useQueryClient();
  
  // UI State
  const [activeTab, setActiveTab] = useState<'marketplace' | 'connected'>('marketplace');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  
  // Modal State
  const [connectDialogOpen, setConnectDialogOpen] = useState(false);
  const [configDialogOpen, setConfigDialogOpen] = useState(false);
  const [routingDialogOpen, setRoutingDialogOpen] = useState(false);
  const [historyDialogOpen, setHistoryDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  
  // Selected items
  const [selectedIntegration, setSelectedIntegration] = useState<IntegrationMetadata | null>(null);
  const [selectedConnection, setSelectedConnection] = useState<IntegrationConnection | null>(null);
  
  // Form state for new connection
  const [connectionForm, setConnectionForm] = useState<{
    name: string;
    description: string;
    config: Record<string, unknown>;
    credentials: Record<string, string>;
  }>({
    name: '',
    description: '',
    config: {},
    credentials: {},
  });

  // Fetch ALL integrations once for category counts (no filtering)
  const { data: allCatalogData } = useQuery({
    queryKey: ['integrations', 'catalog', 'all'],
    queryFn: () => integrationsApi.getCatalog({}),
    staleTime: 60000, // Keep counts cached for 1 minute
  });

  // Fetch filtered catalog based on selection
  const { data: catalogData, isLoading: catalogLoading } = useQuery({
    queryKey: ['integrations', 'catalog', selectedCategory, searchQuery],
    queryFn: () => integrationsApi.getCatalog({
      category: selectedCategory !== 'all' ? selectedCategory : undefined,
      search: searchQuery || undefined,
    }),
    placeholderData: (prev) => prev, // Keep previous data while loading
  });

  // Fetch connections
  const { data: connectionsData, isLoading: connectionsLoading } = useQuery({
    queryKey: ['integrations', 'connections'],
    queryFn: () => integrationsApi.listConnections({ include_disabled: true }),
  });

  // Fetch event types
  const { data: eventTypesData } = useQuery({
    queryKey: ['integrations', 'events'],
    queryFn: integrationsApi.listEventTypes,
  });

  // Fetch routing for selected connection
  const { data: routingData, refetch: refetchRouting } = useQuery({
    queryKey: ['integrations', 'routing', selectedConnection?.id],
    queryFn: () => selectedConnection ? integrationsApi.getEventRouting(selectedConnection.id) : null,
    enabled: !!selectedConnection && routingDialogOpen,
  });

  // Fetch history for selected connection
  const { data: historyData } = useQuery({
    queryKey: ['integrations', 'history', selectedConnection?.id],
    queryFn: () => selectedConnection ? integrationsApi.getConnectionHistory(selectedConnection.id, { limit: 50 }) : null,
    enabled: !!selectedConnection && historyDialogOpen,
  });

  // Calculate stable category counts from allCatalogData
  const categoryCounts = useMemo(() => {
    if (!allCatalogData?.categories) return {};
    return allCatalogData.categories;
  }, [allCatalogData?.categories]);

  // Mutations
  const createConnectionMutation = useMutation({
    mutationFn: integrationsApi.createConnection,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations', 'connections'] });
      setConnectDialogOpen(false);
      resetConnectionForm();
      toast.success('Connection Created', 'Integration connection has been created successfully');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Failed to create connection';
      toast.error('Connection Failed', message);
    },
  });

  const updateConnectionMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof integrationsApi.updateConnection>[1] }) =>
      integrationsApi.updateConnection(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations', 'connections'] });
      setConfigDialogOpen(false);
      toast.success('Connection Updated', 'Integration settings have been saved');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Failed to update connection';
      toast.error('Update Failed', message);
    },
  });

  const deleteConnectionMutation = useMutation({
    mutationFn: integrationsApi.deleteConnection,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations', 'connections'] });
      setDeleteDialogOpen(false);
      setSelectedConnection(null);
      toast.success('Connection Deleted', 'Integration connection has been removed');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Failed to delete connection';
      toast.error('Delete Failed', message);
    },
  });

  const testConnectionMutation = useMutation({
    mutationFn: integrationsApi.testConnection,
    onSuccess: (result) => {
      if (result.success) {
        toast.success('Connection Test Passed', `Response time: ${result.health.response_time_ms}ms`);
      } else {
        toast.error('Connection Test Failed', result.health.last_error || 'Unable to connect');
      }
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Connection test failed';
      toast.error('Test Failed', message);
    },
  });

  const connectMutation = useMutation({
    mutationFn: integrationsApi.connectIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations', 'connections'] });
      toast.success('Connected', 'Integration is now active');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Failed to connect';
      toast.error('Connection Failed', message);
    },
  });

  const disconnectMutation = useMutation({
    mutationFn: integrationsApi.disconnectIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations', 'connections'] });
      toast.success('Disconnected', 'Integration has been disconnected');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Failed to disconnect';
      toast.error('Disconnect Failed', message);
    },
  });

  const setRoutingMutation = useMutation({
    mutationFn: ({ connectionId, data }: { connectionId: string; data: Parameters<typeof integrationsApi.setEventRouting>[1] }) =>
      integrationsApi.setEventRouting(connectionId, data),
    onSuccess: () => {
      refetchRouting();
      toast.success('Routing Updated', 'Event routing has been configured');
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Failed to update routing';
      toast.error('Routing Failed', message);
    },
  });

  // Helpers
  const resetConnectionForm = () => {
    setConnectionForm({
      name: '',
      description: '',
      config: {},
      credentials: {},
    });
    setSelectedIntegration(null);
  };

  const openConnectDialog = (integration: IntegrationMetadata) => {
    setSelectedIntegration(integration);
    setConnectionForm({
      name: `${integration.name} Connection`,
      description: '',
      config: {},
      credentials: {},
    });
    setConnectDialogOpen(true);
  };

  const openConfigDialog = (connection: IntegrationConnection) => {
    setSelectedConnection(connection);
    setConnectionForm({
      name: connection.name,
      description: connection.description || '',
      config: connection.config,
      credentials: {},
    });
    setConfigDialogOpen(true);
  };

  const openRoutingDialog = (connection: IntegrationConnection) => {
    setSelectedConnection(connection);
    setRoutingDialogOpen(true);
  };

  const openHistoryDialog = (connection: IntegrationConnection) => {
    setSelectedConnection(connection);
    setHistoryDialogOpen(true);
  };

  const handleCreateConnection = () => {
    if (!selectedIntegration) return;
    createConnectionMutation.mutate({
      integration_id: selectedIntegration.id,
      name: connectionForm.name,
      description: connectionForm.description || undefined,
      config: connectionForm.config,
      credentials: connectionForm.credentials,
    });
  };

  const handleUpdateConnection = () => {
    if (!selectedConnection) return;
    updateConnectionMutation.mutate({
      id: selectedConnection.id,
      data: {
        name: connectionForm.name,
        description: connectionForm.description || undefined,
        config: connectionForm.config,
        credentials: Object.keys(connectionForm.credentials).length > 0 ? connectionForm.credentials : undefined,
      },
    });
  };

  // Filter integrations
  const filteredIntegrations = useMemo(() => {
    return catalogData?.integrations || [];
  }, [catalogData]);

  // Get connection for an integration
  const getConnectionsForIntegration = (integrationId: string) => {
    return connectionsData?.connections.filter(c => c.integration_id === integrationId) || [];
  };

  // Loading state
  if (catalogLoading && connectionsLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">Integrations</h1>
          <p className="text-muted-foreground">
            Connect third-party services to enhance your print management
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="gap-1">
            <Zap className="h-3 w-3" />
            {connectionsData?.connections.filter(c => c.status === 'connected').length || 0} Active
          </Badge>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as typeof activeTab)}>
        <TabsList>
          <TabsTrigger value="marketplace" className="gap-2">
            <Cable className="h-4 w-4" />
            Marketplace
          </TabsTrigger>
          <TabsTrigger value="connected" className="gap-2">
            <Settings className="h-4 w-4" />
            Connected ({connectionsData?.connections.length || 0})
          </TabsTrigger>
        </TabsList>

        {/* Marketplace Tab */}
        <TabsContent value="marketplace" className="space-y-6">
          {/* Search & Filter */}
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search integrations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(CATEGORY_LABELS).map(([key, label]) => (
                <Button
                  key={key}
                  variant={selectedCategory === key ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setSelectedCategory(key)}
                >
                  {label}
                  {key !== 'all' && categoryCounts[key] !== undefined && (
                    <Badge variant={selectedCategory === key ? 'outline' : 'secondary'} className="ml-1.5 h-5 px-1.5">
                      {categoryCounts[key]}
                    </Badge>
                  )}
                </Button>
              ))}
            </div>
          </div>

          {/* Integration Grid */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {filteredIntegrations.map((integration) => {
              const connections = getConnectionsForIntegration(integration.id);
              const hasConnection = connections.length > 0;
              const connectedCount = connections.filter(c => c.status === 'connected').length;
              
              return (
                <Card
                  key={integration.id}
                  className="group relative overflow-hidden transition-shadow hover:shadow-md"
                >
                  {integration.beta && (
                    <Badge variant="warning" className="absolute right-3 top-3">
                      Beta
                    </Badge>
                  )}
                  {integration.deprecated && (
                    <Badge variant="error" className="absolute right-3 top-3">
                      Deprecated
                    </Badge>
                  )}
                  
                  <CardHeader className="pb-3">
                    <div className="flex items-start gap-3">
                      <div
                        className="flex h-12 w-12 items-center justify-center rounded-lg overflow-hidden"
                        style={{ backgroundColor: `${integration.color}15` }}
                      >
                        {INTEGRATION_LOGOS[integration.id] || (
                          <span className="text-2xl">{integration.icon || '🔗'}</span>
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <CardTitle className="text-base">{integration.name}</CardTitle>
                        <CardDescription className="text-xs">
                          by {integration.vendor}
                        </CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  
                  <CardContent className="space-y-4">
                    <p className="text-sm text-muted-foreground line-clamp-2">
                      {integration.description}
                    </p>
                    
                    {/* Capabilities */}
                    <div className="flex flex-wrap gap-1">
                      {integration.capabilities.slice(0, 3).map((cap) => (
                        <Badge key={cap} variant="secondary" className="text-xs">
                          {cap}
                        </Badge>
                      ))}
                      {integration.capabilities.length > 3 && (
                        <Badge variant="secondary" className="text-xs">
                          +{integration.capabilities.length - 3}
                        </Badge>
                      )}
                    </div>

                    {/* Status & Actions */}
                    <div className="flex items-center justify-between pt-2 border-t">
                      {hasConnection ? (
                        <Badge variant={connectedCount > 0 ? 'success' : 'secondary'}>
                          {connectedCount > 0 ? `${connectedCount} Connected` : 'Configured'}
                        </Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">Not configured</span>
                      )}
                      
                      <div className="flex gap-2">
                        {integration.docs_url && (
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            asChild
                          >
                            <a href={integration.docs_url} target="_blank" rel="noopener noreferrer">
                              <ExternalLink className="h-4 w-4" />
                            </a>
                          </Button>
                        )}
                        <Button
                          size="sm"
                          onClick={() => openConnectDialog(integration)}
                          disabled={integration.deprecated}
                        >
                          <Plus className="h-4 w-4 mr-1" />
                          Connect
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {filteredIntegrations.length === 0 && (
            <Card>
              <CardContent className="py-12 text-center">
                <Cable className="mx-auto h-12 w-12 text-muted-foreground/50" />
                <h3 className="mt-4 text-lg font-medium">No integrations found</h3>
                <p className="text-sm text-muted-foreground">
                  Try adjusting your search or filter criteria
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Connected Tab */}
        <TabsContent value="connected" className="space-y-4">
          {connectionsData?.connections.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Cable className="mx-auto h-12 w-12 text-muted-foreground/50" />
                <h3 className="mt-4 text-lg font-medium">No connections yet</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Connect your first integration from the marketplace
                </p>
                <Button onClick={() => setActiveTab('marketplace')}>
                  Browse Marketplace
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {connectionsData?.connections.map((connection) => {
                const statusConfig = STATUS_CONFIG[connection.status];
                const StatusIcon = statusConfig.icon;
                
                return (
                  <Card key={connection.id}>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div
                            className="flex h-10 w-10 items-center justify-center rounded-lg overflow-hidden"
                            style={{ backgroundColor: connection.integration?.color ? `${connection.integration.color}15` : undefined }}
                          >
                            {INTEGRATION_LOGOS[connection.integration_id] || (
                              <span className="text-xl">{connection.integration?.icon || '🔗'}</span>
                            )}
                          </div>
                          <div>
                            <CardTitle className="text-base">{connection.name}</CardTitle>
                            <CardDescription className="text-xs">
                              {connection.integration?.name || connection.integration_id}
                            </CardDescription>
                          </div>
                        </div>
                        
                        <div className="flex items-center gap-2">
                          <Badge variant={statusConfig.variant} className="gap-1">
                            <StatusIcon className={`h-3 w-3 ${connection.status === 'connecting' || connection.status === 'authenticating' ? 'animate-spin' : ''}`} />
                            {statusConfig.label}
                          </Badge>
                          
                          <Switch
                            checked={connection.enabled}
                            onCheckedChange={(enabled) => {
                              updateConnectionMutation.mutate({
                                id: connection.id,
                                data: { enabled },
                              });
                            }}
                          />
                        </div>
                      </div>
                    </CardHeader>
                    
                    <CardContent>
                      {connection.description && (
                        <p className="text-sm text-muted-foreground mb-4">
                          {connection.description}
                        </p>
                      )}
                      
                      <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
                        {connection.last_connected_at && (
                          <span>
                            Last connected: {new Date(connection.last_connected_at).toLocaleString()}
                          </span>
                        )}
                        {connection.last_error && (
                          <span className="text-error">
                            Error: {connection.last_error}
                          </span>
                        )}
                        {connection.error_count > 0 && (
                          <Badge variant="error" className="text-xs">
                            {connection.error_count} errors
                          </Badge>
                        )}
                      </div>
                      
                      <Separator className="my-4" />
                      
                      <div className="flex flex-wrap gap-2">
                        {connection.status === 'connected' ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => disconnectMutation.mutate(connection.id)}
                            disabled={disconnectMutation.isPending}
                          >
                            <PowerOff className="h-4 w-4 mr-1" />
                            Disconnect
                          </Button>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => connectMutation.mutate(connection.id)}
                            disabled={connectMutation.isPending || !connection.enabled}
                          >
                            <Power className="h-4 w-4 mr-1" />
                            Connect
                          </Button>
                        )}
                        
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => testConnectionMutation.mutate(connection.id)}
                          disabled={testConnectionMutation.isPending}
                        >
                          {testConnectionMutation.isPending ? (
                            <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                          ) : (
                            <RefreshCw className="h-4 w-4 mr-1" />
                          )}
                          Test
                        </Button>
                        
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openConfigDialog(connection)}
                        >
                          <Settings className="h-4 w-4 mr-1" />
                          Configure
                        </Button>
                        
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openRoutingDialog(connection)}
                        >
                          <ArrowUpDown className="h-4 w-4 mr-1" />
                          Event Routing
                        </Button>
                        
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openHistoryDialog(connection)}
                        >
                          <History className="h-4 w-4 mr-1" />
                          History
                        </Button>
                        
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-error hover:text-error"
                          onClick={() => {
                            setSelectedConnection(connection);
                            setDeleteDialogOpen(true);
                          }}
                        >
                          <Trash2 className="h-4 w-4 mr-1" />
                          Delete
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Connect Dialog */}
      <Dialog open={connectDialogOpen} onOpenChange={setConnectDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedIntegration && (
                <div className="h-6 w-6 flex items-center justify-center">
                  {INTEGRATION_LOGOS[selectedIntegration.id] || (
                    <span className="text-xl">{selectedIntegration.icon || '🔗'}</span>
                  )}
                </div>
              )}
              Connect {selectedIntegration?.name}
            </DialogTitle>
            <DialogDescription>
              Configure your connection settings and credentials.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="connection-name">Connection Name *</Label>
              <Input
                id="connection-name"
                value={connectionForm.name}
                onChange={(e) => setConnectionForm({ ...connectionForm, name: e.target.value })}
                placeholder="My Splunk Connection"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="connection-description">Description</Label>
              <Input
                id="connection-description"
                value={connectionForm.description}
                onChange={(e) => setConnectionForm({ ...connectionForm, description: e.target.value })}
                placeholder="Production logging server"
              />
            </div>
            
            <Separator />
            
            {/* Dynamic config fields based on integration schema */}
            {selectedIntegration?.config_schema?.map((field) => (
              <div key={field.name} className="space-y-2">
                <Label htmlFor={`config-${field.name}`}>
                  {field.label || field.name}
                  {field.required && <span className="text-error"> *</span>}
                </Label>
                <Input
                  id={`config-${field.name}`}
                  type={field.type === 'password' ? 'password' : field.type === 'number' ? 'number' : 'text'}
                  value={(field.sensitive ? connectionForm.credentials[field.name] : connectionForm.config[field.name] as string) || ''}
                  onChange={(e) => {
                    if (field.sensitive) {
                      setConnectionForm({
                        ...connectionForm,
                        credentials: { ...connectionForm.credentials, [field.name]: e.target.value },
                      });
                    } else {
                      setConnectionForm({
                        ...connectionForm,
                        config: { ...connectionForm.config, [field.name]: e.target.value },
                      });
                    }
                  }}
                  placeholder={field.placeholder || field.description}
                />
                {field.description && (
                  <p className="text-xs text-muted-foreground">{field.description}</p>
                )}
              </div>
            ))}
            
            {/* Fallback fields for integrations without schema */}
            {(!selectedIntegration?.config_schema || selectedIntegration.config_schema.length === 0) && (
              <>
                {selectedIntegration?.id === 'splunk' && (
                  <>
                    <div className="space-y-2">
                      <Label>HEC URL *</Label>
                      <Input
                        value={connectionForm.config.hec_url as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, hec_url: e.target.value },
                        })}
                        placeholder="https://splunk.example.com:8088"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>HEC Token *</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.hec_token || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, hec_token: e.target.value },
                        })}
                        placeholder="Your HEC token"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Index</Label>
                      <Input
                        value={connectionForm.config.index as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, index: e.target.value },
                        })}
                        placeholder="main"
                      />
                    </div>
                  </>
                )}
                
                {selectedIntegration?.id === 'datadog' && (
                  <>
                    <div className="space-y-2">
                      <Label>API Key *</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.api_key || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, api_key: e.target.value },
                        })}
                        placeholder="Your Datadog API key"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Region</Label>
                      <Input
                        value={connectionForm.config.region as string || 'us1'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, region: e.target.value },
                        })}
                        placeholder="us1, us3, us5, eu1, ap1"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Service Name</Label>
                      <Input
                        value={connectionForm.config.service as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, service: e.target.value },
                        })}
                        placeholder="continuum"
                      />
                    </div>
                  </>
                )}
                
                {selectedIntegration?.id === 'elastic' && (
                  <>
                    <div className="space-y-2">
                      <Label>Elasticsearch URL *</Label>
                      <Input
                        value={connectionForm.config.url as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, url: e.target.value },
                        })}
                        placeholder="https://elasticsearch.example.com:9200"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>API Key *</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.api_key || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, api_key: e.target.value },
                        })}
                        placeholder="Your Elasticsearch API key"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Index Pattern</Label>
                      <Input
                        value={connectionForm.config.index_pattern as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, index_pattern: e.target.value },
                        })}
                        placeholder="continuum-logs-{date}"
                      />
                    </div>
                  </>
                )}
                
                {selectedIntegration?.id === 'syslog' && (
                  <>
                    <div className="space-y-2">
                      <Label>Syslog Host *</Label>
                      <Input
                        value={connectionForm.config.host as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, host: e.target.value },
                        })}
                        placeholder="syslog.example.com"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Port</Label>
                      <Input
                        type="number"
                        value={connectionForm.config.port as number || 514}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, port: parseInt(e.target.value) },
                        })}
                        placeholder="514"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Protocol</Label>
                      <Input
                        value={connectionForm.config.protocol as string || 'udp'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, protocol: e.target.value },
                        })}
                        placeholder="udp, tcp, tls"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Format</Label>
                      <Input
                        value={connectionForm.config.format as string || 'rfc5424'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, format: e.target.value },
                        })}
                        placeholder="rfc5424 or rfc3164"
                      />
                    </div>
                  </>
                )}
                
                {/* Monitoring Integrations */}
                {selectedIntegration?.id === 'prometheus' && (
                  <>
                    <div className="space-y-2">
                      <Label>Pushgateway URL *</Label>
                      <Input
                        value={connectionForm.config.pushgateway_url as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, pushgateway_url: e.target.value },
                        })}
                        placeholder="http://pushgateway:9091"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Job Name</Label>
                      <Input
                        value={connectionForm.config.job_name as string || 'continuum'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, job_name: e.target.value },
                        })}
                        placeholder="continuum"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Username (optional)</Label>
                      <Input
                        value={connectionForm.credentials.username || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, username: e.target.value },
                        })}
                        placeholder="Basic auth username"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Password (optional)</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.password || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, password: e.target.value },
                        })}
                        placeholder="Basic auth password"
                      />
                    </div>
                  </>
                )}
                
                {selectedIntegration?.id === 'grafana' && (
                  <>
                    <div className="space-y-2">
                      <Label>Grafana URL *</Label>
                      <Input
                        value={connectionForm.config.grafana_url as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, grafana_url: e.target.value },
                        })}
                        placeholder="https://grafana.example.com"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>API Key *</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.api_key || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, api_key: e.target.value },
                        })}
                        placeholder="Your Grafana API key"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Dashboard UID (optional)</Label>
                      <Input
                        value={connectionForm.config.dashboard_uid as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, dashboard_uid: e.target.value },
                        })}
                        placeholder="Dashboard UID for annotations"
                      />
                    </div>
                  </>
                )}
                
                {selectedIntegration?.id === 'newrelic' && (
                  <>
                    <div className="space-y-2">
                      <Label>Account ID *</Label>
                      <Input
                        value={connectionForm.config.account_id as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, account_id: e.target.value },
                        })}
                        placeholder="1234567"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>API Key (License/Ingest Key) *</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.api_key || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, api_key: e.target.value },
                        })}
                        placeholder="Your New Relic License Key"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Region</Label>
                      <Input
                        value={connectionForm.config.region as string || 'us'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, region: e.target.value },
                        })}
                        placeholder="us or eu"
                      />
                    </div>
                  </>
                )}
                
                {selectedIntegration?.id === 'nagios' && (
                  <>
                    <div className="space-y-2">
                      <Label>NSCA Host *</Label>
                      <Input
                        value={connectionForm.config.nsca_host as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, nsca_host: e.target.value },
                        })}
                        placeholder="nagios.example.com"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>NSCA Port</Label>
                      <Input
                        type="number"
                        value={connectionForm.config.nsca_port as number || 5667}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, nsca_port: parseInt(e.target.value) },
                        })}
                        placeholder="5667"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Nagios Host Name *</Label>
                      <Input
                        value={connectionForm.config.nagios_host as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, nagios_host: e.target.value },
                        })}
                        placeholder="Host name as configured in Nagios"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Encryption Key (optional)</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.encryption_key || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, encryption_key: e.target.value },
                        })}
                        placeholder="NSCA encryption key"
                      />
                    </div>
                  </>
                )}
                
                {/* Alerting Integrations */}
                {selectedIntegration?.id === 'pagerduty' && (
                  <>
                    <div className="space-y-2">
                      <Label>Routing Key (Integration Key) *</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.routing_key || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, routing_key: e.target.value },
                        })}
                        placeholder="32-character routing key"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Default Severity</Label>
                      <Input
                        value={connectionForm.config.default_severity as string || 'warning'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, default_severity: e.target.value },
                        })}
                        placeholder="critical, error, warning, info"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Component</Label>
                      <Input
                        value={connectionForm.config.component as string || 'print-infrastructure'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, component: e.target.value },
                        })}
                        placeholder="print-infrastructure"
                      />
                    </div>
                  </>
                )}
                
                {selectedIntegration?.id === 'opsgenie' && (
                  <>
                    <div className="space-y-2">
                      <Label>API Key *</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.api_key || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, api_key: e.target.value },
                        })}
                        placeholder="Your Opsgenie API key"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Region</Label>
                      <Input
                        value={connectionForm.config.region as string || 'us'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, region: e.target.value },
                        })}
                        placeholder="us or eu"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Default Priority</Label>
                      <Input
                        value={connectionForm.config.default_priority as string || 'P3'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, default_priority: e.target.value },
                        })}
                        placeholder="P1, P2, P3, P4, P5"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Default Responders (comma-separated)</Label>
                      <Input
                        value={connectionForm.config.responders as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, responders: e.target.value },
                        })}
                        placeholder="team-name, user-name"
                      />
                    </div>
                  </>
                )}
                
                {selectedIntegration?.id === 'victorops' && (
                  <>
                    <div className="space-y-2">
                      <Label>API Key *</Label>
                      <Input
                        type="password"
                        value={connectionForm.credentials.api_key || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          credentials: { ...connectionForm.credentials, api_key: e.target.value },
                        })}
                        placeholder="Your VictorOps API key"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Routing Key *</Label>
                      <Input
                        value={connectionForm.config.routing_key as string || ''}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, routing_key: e.target.value },
                        })}
                        placeholder="printer-team"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Default Message Type</Label>
                      <Input
                        value={connectionForm.config.default_message_type as string || 'WARNING'}
                        onChange={(e) => setConnectionForm({
                          ...connectionForm,
                          config: { ...connectionForm.config, default_message_type: e.target.value },
                        })}
                        placeholder="CRITICAL, WARNING, INFO"
                      />
                    </div>
                  </>
                )}
              </>
            )}
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setConnectDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreateConnection}
              disabled={createConnectionMutation.isPending || !connectionForm.name}
            >
              {createConnectionMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Create Connection
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Config Dialog */}
      <Dialog open={configDialogOpen} onOpenChange={setConfigDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Configure Connection</DialogTitle>
            <DialogDescription>
              Update connection settings for {selectedConnection?.name}
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-connection-name">Connection Name *</Label>
              <Input
                id="edit-connection-name"
                value={connectionForm.name}
                onChange={(e) => setConnectionForm({ ...connectionForm, name: e.target.value })}
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="edit-connection-description">Description</Label>
              <Input
                id="edit-connection-description"
                value={connectionForm.description}
                onChange={(e) => setConnectionForm({ ...connectionForm, description: e.target.value })}
              />
            </div>
            
            <Separator />
            
            <p className="text-sm text-muted-foreground">
              Configuration values are preserved. Enter new credentials only if you want to update them.
            </p>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfigDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleUpdateConnection}
              disabled={updateConnectionMutation.isPending}
            >
              {updateConnectionMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Event Routing Dialog */}
      <Dialog open={routingDialogOpen} onOpenChange={setRoutingDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Event Routing</DialogTitle>
            <DialogDescription>
              Configure which events are sent to {selectedConnection?.name}
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {eventTypesData?.event_types.map((eventType) => {
              const routing = routingData?.routings.find(r => r.event_type === eventType.type);
              const isEnabled = routing?.enabled ?? false;
              
              return (
                <div
                  key={eventType.type}
                  className="flex items-center justify-between p-3 rounded-lg border"
                >
                  <div>
                    <div className="font-medium text-sm">{eventType.type}</div>
                    <div className="text-xs text-muted-foreground">{eventType.description}</div>
                    <Badge variant="secondary" className="mt-1 text-xs">
                      {eventType.category}
                    </Badge>
                  </div>
                  <Switch
                    checked={isEnabled}
                    onCheckedChange={(enabled) => {
                      if (selectedConnection) {
                        setRoutingMutation.mutate({
                          connectionId: selectedConnection.id,
                          data: { event_type: eventType.type, enabled },
                        });
                      }
                    }}
                    disabled={setRoutingMutation.isPending}
                  />
                </div>
              );
            })}
            
            {(!eventTypesData?.event_types || eventTypesData.event_types.length === 0) && (
              <p className="text-sm text-muted-foreground text-center py-8">
                No event types available
              </p>
            )}
          </div>
          
          <DialogFooter>
            <Button onClick={() => setRoutingDialogOpen(false)}>
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* History Dialog */}
      <Dialog open={historyDialogOpen} onOpenChange={setHistoryDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Connection History</DialogTitle>
            <DialogDescription>
              Recent activity for {selectedConnection?.name}
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {historyData?.history.map((entry) => (
              <div
                key={entry.id}
                className="flex items-start gap-3 p-3 rounded-lg border text-sm"
              >
                <div className={`mt-0.5 h-2 w-2 rounded-full ${
                  entry.status === 'success' ? 'bg-success' :
                  entry.status === 'error' ? 'bg-error' :
                  'bg-muted-foreground'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="font-medium">{entry.action}</div>
                  {entry.error_message && (
                    <div className="text-error text-xs mt-1">{entry.error_message}</div>
                  )}
                  <div className="text-xs text-muted-foreground mt-1">
                    {new Date(entry.created_at).toLocaleString()}
                  </div>
                </div>
              </div>
            ))}
            
            {(!historyData?.history || historyData.history.length === 0) && (
              <p className="text-sm text-muted-foreground text-center py-8">
                No history available
              </p>
            )}
          </div>
          
          <DialogFooter>
            <Button onClick={() => setHistoryDialogOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Connection</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete "{selectedConnection?.name}"? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => selectedConnection && deleteConnectionMutation.mutate(selectedConnection.id)}
              disabled={deleteConnectionMutation.isPending}
            >
              {deleteConnectionMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

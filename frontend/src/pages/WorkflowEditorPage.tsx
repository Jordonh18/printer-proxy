import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  addEdge,
  applyEdgeChanges,
  applyNodeChanges,
  Background,
  ConnectionLineType,
  Controls,
  ReactFlow,
  ReactFlowProvider,
  type Connection,
  type Edge,
  type Node,
  type NodeChange,
  type EdgeChange,
  type ReactFlowInstance,
  type Viewport,
  useEdgesState,
  useNodesState,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Button } from '@/components/ui/button';
import { CardContent, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
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
import { Loader2 } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { printersApi, workflowApi } from '@/lib/api';
import { toast } from '@/lib/toast';
import { useAuth } from '@/contexts/AuthContext';
import WorkflowNode, { type WorkflowNodeData } from '@/components/workflows/WorkflowNode';
import { NodePalette } from '@/components/workflows/NodePalette';
import { VariablePicker } from '@/components/workflows/VariablePicker';
import type { WorkflowEdge, WorkflowNode as WorkflowNodeRecord, WorkflowRegistryNode } from '@/types/api';

const nodeTypes = {
  workflowNode: WorkflowNode,
};

const GRID_SIZE: [number, number] = [20, 20];

export function WorkflowEditorPage() {
  const { id } = useParams();
  const workflowId = id;
  const navigate = useNavigate();
  const { user } = useAuth();
  const canEdit = user?.role !== 'viewer';

  const { data: registry = [] } = useQuery({
    queryKey: ['workflow-registry'],
    queryFn: workflowApi.getRegistry,
    retry: false,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  });

  const { data: workflow, isLoading } = useQuery({
    queryKey: ['workflow', workflowId],
    queryFn: () => {
      if (!workflowId) throw new Error('No workflow ID');
      return workflowApi.getById(workflowId);
    },
    enabled: !!workflowId,
  });

  const { data: printers = [] } = useQuery({
    queryKey: ['printers'],
    queryFn: printersApi.getAll,
  });

  const registryMap = useMemo(() => {
    return registry.reduce<Record<string, WorkflowRegistryNode>>((acc, node) => {
      acc[node.key] = node;
      return acc;
    }, {});
  }, [registry]);

  const printerOptions = useMemo(() => {
    return printers.map((printerStatus: { printer: { id: string; name: string } }) => ({
      label: printerStatus.printer.name,
      value: printerStatus.printer.id,
    }));
  }, [printers]);

  const [nodes, setNodes] = useNodesState<Node<WorkflowNodeData>>([]);
  const [edges, setEdges] = useEdgesState<Edge>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [connectionNodeId, setConnectionNodeId] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [uiState, setUiState] = useState<Record<string, unknown> | null>(null);
  const [reactFlowInstance, setReactFlowInstance] = useState<ReactFlowInstance | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(true);
  const [isDirty, setIsDirty] = useState(false);
  const [exitDialogOpen, setExitDialogOpen] = useState(false);
  const dragStateRef = useRef<{
    nodeId: string | null;
    handleId: string | null;
    handleType: 'source' | 'target' | null;
    active: boolean;
  }>({ nodeId: null, handleId: null, handleType: null, active: false });
  const suppressDirtyRef = useRef(false);

  const history = useRef<{ nodes: Node<WorkflowNodeData>[]; edges: Edge[] }[]>([]);
  const future = useRef<{ nodes: Node<WorkflowNodeData>[]; edges: Edge[] }[]>([]);

  const nodesRef = useRef<Node<WorkflowNodeData>[]>([]);
  const edgesRef = useRef<Edge[]>([]);
  const deleteNodeByIdRef = useRef<(nodeId: string) => void>(() => {});

  useEffect(() => {
    nodesRef.current = nodes;
  }, [nodes]);

  useEffect(() => {
    edgesRef.current = edges;
  }, [edges]);

  const pushHistory = useCallback(() => {
    history.current.push({
      nodes: nodesRef.current.map((node) => ({ ...node, data: { ...node.data } })),
      edges: edgesRef.current.map((edge) => ({ ...edge })),
    });
    future.current = [];
  }, []);

  const markDirty = useCallback(() => {
    if (suppressDirtyRef.current) {
      return;
    }
    setIsDirty(true);
  }, []);

  const deleteNodeById = useCallback((nodeId: string) => {
    if (!canEdit) {
      return;
    }
    pushHistory();
    setNodes((current: Node<WorkflowNodeData>[]) => current.filter((node) => node.id !== nodeId));
    setEdges((current: Edge[]) => current.filter((edge) => edge.source !== nodeId && edge.target !== nodeId));
    setSelectedNodeId((current) => (current === nodeId ? null : current));
    markDirty();
  }, [canEdit, pushHistory, setNodes, setEdges, markDirty]);

  const deleteEdgeById = useCallback((edgeId: string) => {
    if (!canEdit) {
      return;
    }
    pushHistory();
    setEdges((current: Edge[]) => current.filter((edge) => edge.id !== edgeId));
    setSelectedEdgeId((current) => (current === edgeId ? null : current));
    markDirty();
  }, [canEdit, pushHistory, setEdges, markDirty]);

  useEffect(() => {
    if (!workflow) {
      return;
    }

    // Suppress dirty marking during initial load - the change handlers fire after we set nodes/edges
    suppressDirtyRef.current = true;

    const mappedNodes: Node<WorkflowNodeData>[] = (workflow.nodes || []).map((node) => {
      const registryNode = registryMap[node.type];
      return {
        id: node.id,
        type: 'workflowNode',
        position: node.position,
        data: {
          label: registryNode?.name || node.label || node.type,
          description: registryNode?.description || '',
          category: registryNode?.category || 'custom',
          color: registryNode?.color || '#10b981',
          icon: registryNode?.icon,
          inputs: registryNode?.inputs || [],
          outputs: registryNode?.outputs || [],
          properties: node.properties || registryNode?.default_properties || {},
          registryKey: node.type,
          canEdit,
          showHandles: canEdit,
          compatible: true,
          draggingActive: false,
          onDelete: () => deleteNodeByIdRef.current(node.id),
        } as WorkflowNodeData & { registryKey: string },
      };
    });

    const mappedEdges: Edge[] = (workflow.edges || []).map((edge) => {
      const sourceNode = mappedNodes.find((n) => n.id === edge.source);
      return {
        id: edge.id.toString(),
        source: edge.source,
        target: edge.target,
        sourceHandle: edge.sourceHandle || undefined,
        targetHandle: edge.targetHandle || undefined,
        type: 'default',
        style: {
          strokeWidth: 2,
          stroke: sourceNode?.data?.color || '#10b981',
        },
        animated: false,
      };
    });

    setNodes(mappedNodes);
    setEdges(mappedEdges);
    setUiState(workflow.ui_state || null);
    setIsDirty(false);

    // Re-enable dirty marking after a short delay to allow React Flow to process
    requestAnimationFrame(() => {
      suppressDirtyRef.current = false;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workflow?.id, registry, canEdit]);

  // Keep deleteNodeByIdRef in sync with deleteNodeById
  useEffect(() => {
    deleteNodeByIdRef.current = deleteNodeById;
  }, [deleteNodeById]);

  // Keyboard handler for edge deletion
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.key === 'Delete' || event.key === 'Backspace') && selectedEdgeId && canEdit) {
        // Prevent deletion if we're focused on an input element
        const target = event.target as HTMLElement;
        if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
          return;
        }
        event.preventDefault();
        deleteEdgeById(selectedEdgeId);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [selectedEdgeId, canEdit, deleteEdgeById]);

  const handleUndo = () => {
    const previous = history.current.pop();
    if (!previous) {
      return;
    }
    future.current.push({ nodes: nodesRef.current, edges: edgesRef.current });
    setNodes(previous.nodes);
    setEdges(previous.edges);
  };

  const handleRedo = () => {
    const next = future.current.pop();
    if (!next) {
      return;
    }
    history.current.push({ nodes: nodesRef.current, edges: edgesRef.current });
    setNodes(next.nodes);
    setEdges(next.edges);
  };

  const handleNodesChange = useCallback(
    (changes: NodeChange[]) => {
      const hasMove = changes.some((change) => change.type === 'position' || change.type === 'remove');
      if (canEdit && hasMove) {
        pushHistory();
      }
      setNodes((current: Node<WorkflowNodeData>[]) => {
        if (!canEdit) {
          const filtered = changes.filter((change) => change.type !== 'position' && change.type !== 'remove');
          return applyNodeChanges(filtered, current) as Node<WorkflowNodeData>[];
        }
        return applyNodeChanges(changes, current) as Node<WorkflowNodeData>[];
      });
      if (canEdit) {
        markDirty();
      }
    },
    [canEdit, setNodes, pushHistory, markDirty]
  );

  const handleEdgesChange = useCallback(
    (changes: EdgeChange[]) => {
      if (canEdit && changes.some((change) => change.type === 'remove')) {
        pushHistory();
      }
      setEdges((current: Edge[]) => applyEdgeChanges(changes, current));
      if (canEdit) {
        markDirty();
      }
    },
    [canEdit, setEdges, pushHistory, markDirty]
  );

  const normalizeHandleId = (handleId?: string | null) => {
    if (!handleId) return null;
    return handleId.split(':')[0];
  };

  const evaluateCompatibility = useCallback((candidate: Node<WorkflowNodeData>) => {
    const dragState = dragStateRef.current;
    if (!dragState.active || !dragState.handleType || !dragState.handleId || !dragState.nodeId) {
      return true;
    }

    if (candidate.id === dragState.nodeId) {
      return false;
    }

    const sourceNode = nodesRef.current.find((node) => node.id === dragState.nodeId);
    if (!sourceNode) {
      return false;
    }

    const sourceKey = (sourceNode.data as WorkflowNodeData & { registryKey?: string }).registryKey;
    const targetKey = (candidate.data as WorkflowNodeData & { registryKey?: string }).registryKey;
    const sourceRegistry = sourceKey ? registryMap[sourceKey] : undefined;
    const targetRegistry = targetKey ? registryMap[targetKey] : undefined;

    if (!sourceRegistry || !targetRegistry) {
      return false;
    }

    const normalizedHandle = normalizeHandleId(dragState.handleId);

    if (dragState.handleType === 'source') {
      const output = sourceRegistry.outputs.find((item) => item.id === normalizedHandle);
      if (!output) return false;
      if (!targetRegistry.inputs.length) return false;
      return targetRegistry.inputs.some((input) => {
        if (input.type === 'any' || output.type === 'any') return true;
        return input.type === output.type;
      });
    }

    const input = sourceRegistry.inputs.find((item) => item.id === normalizedHandle);
    if (!input) return false;
    if (!targetRegistry.outputs.length) return false;
    return targetRegistry.outputs.some((output) => {
      if (input.type === 'any' || output.type === 'any') return true;
      return input.type === output.type;
    });
  }, [registryMap]);

  const applyDragState = useCallback((active: boolean) => {
    suppressDirtyRef.current = true;
    setNodes((current: Node<WorkflowNodeData>[]) =>
      current.map((node) => {
        const compatible = active ? evaluateCompatibility(node) : true;
        return {
          ...node,
          data: {
            ...node.data,
            draggingActive: active,
            compatible,
            showHandles: canEdit && (!active || compatible),
          },
        };
      })
    );
    setTimeout(() => {
      suppressDirtyRef.current = false;
    }, 0);
  }, [evaluateCompatibility, setNodes, canEdit]);

  const handleConnect = useCallback(
    async (connection: Connection) => {
      if (!canEdit || !connection.source || !connection.target) {
        return;
      }
      const sourceNode = nodesRef.current.find((node) => node.id === connection.source);
      const targetNode = nodesRef.current.find((node) => node.id === connection.target);
      const sourceType = (sourceNode?.data as WorkflowNodeData & { registryKey?: string })?.registryKey;
      const targetType = (targetNode?.data as WorkflowNodeData & { registryKey?: string })?.registryKey;

      if (!workflowId) return false;

      try {
        const validation = await workflowApi.validateConnection(workflowId, {
          source_node_id: connection.source,
          target_node_id: connection.target,
          source_handle: connection.sourceHandle || null,
          target_handle: connection.targetHandle || null,
          source_node_type: sourceType,
          target_node_type: targetType,
        });
        if (!validation.valid) {
          toast.error('Invalid connection', validation.message);
          return;
        }
        pushHistory();
        const sourceNode = nodesRef.current.find((n) => n.id === connection.source);
        const newEdge: Edge = {
          ...connection,
          id: `${connection.source}-${connection.target}-${connection.sourceHandle || 'default'}-${connection.targetHandle || 'default'}`,
          type: 'default',
          style: {
            strokeWidth: 2,
            stroke: sourceNode?.data?.color || '#10b981',
          },
          animated: false,
        };
        setEdges((current) => addEdge(newEdge, current));
        markDirty();
      } catch (error) {
        toast.error('Connection rejected', error instanceof Error ? error.message : undefined);
      }
    },
    [canEdit, workflowId, setEdges, pushHistory, markDirty]
  );

  const handleSelection = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNodeId(node.id);
    setSelectedEdgeId(null);
    // Bring selected node to front by updating its zIndex
    setNodes((current: Node<WorkflowNodeData>[]) =>
      current.map((n) => ({
        ...n,
        zIndex: n.id === node.id ? 1000 : (n.zIndex || 0),
      }))
    );
  }, [setNodes]);

  const handleEdgeClick = useCallback((_: React.MouseEvent, edge: Edge) => {
    setSelectedEdgeId(edge.id);
    setSelectedNodeId(null);
    // Highlight the selected edge
    setEdges((current: Edge[]) =>
      current.map((e) => ({
        ...e,
        style: {
          ...e.style,
          strokeWidth: e.id === edge.id ? 4 : 3,
        },
        selected: e.id === edge.id,
      }))
    );
  }, [setEdges]);

  const handleExit = () => {
    if (isDirty) {
      setExitDialogOpen(true);
      return;
    }
    navigate('/workflows');
  };

  const selectedNode = useMemo(() => {
    return nodes.find((node: Node<WorkflowNodeData>) => node.id === selectedNodeId) || null;
  }, [nodes, selectedNodeId]);

  const selectedRegistry = useMemo(() => {
    const key = (selectedNode?.data as WorkflowNodeData & { registryKey?: string })?.registryKey;
    return key ? registryMap[key] : undefined;
  }, [selectedNode, registryMap]);

  const defaultViewport = useMemo(() => {
    if (!uiState || typeof uiState !== 'object') {
      return undefined;
    }
    const x = typeof uiState.x === 'number' ? uiState.x : 0;
    const y = typeof uiState.y === 'number' ? uiState.y : 0;
    const zoom = typeof uiState.zoom === 'number' ? uiState.zoom : 1;
    return { x, y, zoom };
  }, [uiState]);

  const updateNodeProperty = (key: string, value: unknown) => {
    if (!selectedNode) {
      return;
    }
    pushHistory();
    setNodes((current: Node<WorkflowNodeData>[]) =>
      current.map((node: Node<WorkflowNodeData>) => {
        if (node.id !== selectedNode.id) {
          return node;
        }
        return {
          ...node,
          data: {
            ...node.data,
            properties: {
              ...(node.data as WorkflowNodeData & { properties?: Record<string, unknown> }).properties,
              [key]: value,
            },
          },
        };
      })
    );
    markDirty();
  };

  const updateNodeLabel = (value: string) => {
    if (!selectedNode) {
      return;
    }
    pushHistory();
    setNodes((current: Node<WorkflowNodeData>[]) =>
      current.map((node: Node<WorkflowNodeData>) =>
        node.id === selectedNode.id
          ? {
              ...node,
              data: {
                ...node.data,
                label: value,
              },
            }
          : node
      )
    );
    markDirty();
  };

  const handleAddNode = async (registryNode: WorkflowRegistryNode, position?: { x: number; y: number }) => {
    if (!canEdit) {
      toast.warning('Viewer access is read-only');
      return;
    }
    if (!position) {
      // Only drag-to-place is allowed
      return;
    }
    const generatedProperties = { ...(registryNode.default_properties || {}) };
    if (registryNode.key === 'trigger.webhook') {
      const generatedId = crypto.randomUUID();
      generatedProperties.path = `/api/webhooks/workflows/${workflowId}/${generatedId}`;
      // Generate secret as SHA256 hash
      const randomBytes = crypto.getRandomValues(new Uint8Array(32));
      const hashBuffer = await crypto.subtle.digest('SHA-256', randomBytes);
      generatedProperties.secret = Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
    }
    pushHistory();
    const id = `node_${Date.now()}`;
    const newNode: Node<WorkflowNodeData> = {
      id,
      type: 'workflowNode',
      position,
      data: {
        label: registryNode.name,
        description: registryNode.description,
        category: registryNode.category,
        color: registryNode.color,
        icon: registryNode.icon,
        inputs: registryNode.inputs || [],
        outputs: registryNode.outputs || [],
        properties: generatedProperties,
        registryKey: registryNode.key,
        onDelete: () => deleteNodeByIdRef.current(id),
        canEdit,
      } as WorkflowNodeData & { registryKey: string },
    };
    setNodes((current: Node<WorkflowNodeData>[]) => [...current, newNode]);
    markDirty();
  };

  const handleDragStart = (event: React.DragEvent<HTMLButtonElement>, node: WorkflowRegistryNode) => {
    event.dataTransfer.setData('application/reactflow', JSON.stringify(node));
    event.dataTransfer.effectAllowed = 'move';
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    if (!canEdit) {
      return;
    }
    const data = event.dataTransfer.getData('application/reactflow');
    if (!data) {
      return;
    }
    const registryNode = JSON.parse(data) as WorkflowRegistryNode;
    const position = reactFlowInstance?.screenToFlowPosition({
      x: event.clientX,
      y: event.clientY,
    });
    handleAddNode(registryNode, position);
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  };

  const serializeWorkflow = useCallback((): { nodes: WorkflowNodeRecord[]; edges: WorkflowEdge[]; ui_state: Record<string, unknown> | null } => {
    return {
      nodes: nodes.map((node: Node<WorkflowNodeData>) => ({
        id: node.id,
        type: (node.data as WorkflowNodeData & { registryKey?: string }).registryKey || 'custom',
        label: node.data.label,
        position: node.position,
        properties: (node.data as WorkflowNodeData & { properties?: Record<string, unknown> }).properties || {},
      })),
      edges: edges.map((edge: Edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        sourceHandle: edge.sourceHandle || null,
        targetHandle: edge.targetHandle || null,
      })),
      ui_state: uiState,
    };
  }, [nodes, edges, uiState]);

  const handleSave = useCallback(async () => {
    if (!workflow) {
      return;
    }
    const payload = serializeWorkflow();
    setIsSaving(true);
    try {
      await workflowApi.update(workflow.id, payload);
      toast.success('Workflow saved');
      setIsDirty(false);
    } catch (error) {
      toast.error('Failed to save workflow', error instanceof Error ? error.message : undefined);
    } finally {
      setIsSaving(false);
    }
  }, [workflow, serializeWorkflow]);

  // Autosave effect - debounce changes
  useEffect(() => {
    if (!workflow || !canEdit || !isDirty) {
      return;
    }
    const timeout = setTimeout(() => {
      const payload = serializeWorkflow();
      workflowApi.update(workflow.id, payload)
        .then(() => setIsDirty(false))
        .catch((error) => {
          toast.error('Autosave failed', error instanceof Error ? error.message : undefined);
        });
    }, 8000);
    return () => clearTimeout(timeout);
  }, [nodes, edges, uiState, workflow, canEdit, isDirty, serializeWorkflow]);

  if (!workflowId) {
    return <div className="text-sm text-muted-foreground">Invalid workflow ID.</div>;
  }

  if (isLoading || !workflow) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <ReactFlowProvider>
      <div className="relative h-full w-full bg-background">
        <div className="absolute left-6 right-6 top-6 z-20 flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="text-lg font-semibold">{workflow.name}</div>
            <div className="text-xs text-muted-foreground">{workflow.description || 'No description'}</div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => handleSave()} disabled={!canEdit || isSaving}>
              {isSaving ? 'Saving' : 'Save'}
            </Button>
            <Button variant="outline" size="sm" onClick={handleUndo} disabled={!canEdit || history.current.length === 0}>
              Undo
            </Button>
            <Button variant="outline" size="sm" onClick={handleRedo} disabled={!canEdit || future.current.length === 0}>
              Redo
            </Button>
            <Button variant="outline" size="sm" onClick={handleExit}>
              Exit
            </Button>
          </div>
        </div>

        {selectedNode && (
          <div className="absolute left-6 top-[5.5rem] z-50 w-[280px] rounded-lg bg-card shadow-lg nodrag nowheel" aria-hidden={false}>
            <div className="border-b border-border/60 px-4 py-3">
              <CardTitle>Properties</CardTitle>
            </div>
            <CardContent className="space-y-4 px-4 py-3 max-h-[calc(100vh-12rem)] overflow-y-auto">
              <div className="space-y-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground">Label</label>
                  <Input
                    className="nodrag"
                    value={selectedNode.data.label}
                    onChange={(event) => updateNodeLabel(event.target.value)}
                    disabled={!canEdit}
                  />
                </div>
                {selectedRegistry?.config_schema?.fields?.map((field) => {
                  const currentValue = (selectedNode.data as WorkflowNodeData & { properties?: Record<string, unknown> }).properties?.[field.key];
                  const isReadOnly = field.readOnly || !canEdit;
                  const usesPrinterSelect = field.key.endsWith('_printer_id') || field.key === 'printer_id';
                  const selectOptions = usesPrinterSelect ? printerOptions : (field.options || []);
                  
                  // Boolean fields
                  if (field.type === 'boolean') {
                    return (
                      <div key={field.key} className="flex items-center justify-between nodrag">
                        <label className="text-xs font-medium text-muted-foreground">{field.label}</label>
                        <input
                          type="checkbox"
                          className="h-4 w-4 nodrag"
                          checked={Boolean(currentValue)}
                          onChange={(event) => updateNodeProperty(field.key, event.target.checked)}
                          disabled={isReadOnly}
                        />
                      </div>
                    );
                  }

                  // Select/dropdown fields that support dynamic variables (like printer_id)
                  if ((field.type === 'select' || field.type === 'printer_id' || usesPrinterSelect) && field.supportsDynamic) {
                    return (
                      <div key={field.key} className="nodrag">
                        <label className="text-xs font-medium text-muted-foreground">
                          {field.label}
                          {field.required && <span className="text-red-500 ml-1">*</span>}
                        </label>
                        <VariablePicker
                          value={currentValue !== undefined ? String(currentValue) : ''}
                          onChange={(value) => updateNodeProperty(field.key, value)}
                          nodes={nodes}
                          edges={edges}
                          currentNodeId={selectedNode.id}
                          registry={registry}
                          placeholder={field.placeholder || (usesPrinterSelect ? 'Select printer or use {{variable}}' : 'Select or use {{variable}}')}
                          disabled={isReadOnly}
                          options={selectOptions}
                          acceptsTypes={field.acceptsTypes || []}
                          fieldType={field.type}
                        />
                        {field.helperText && (
                          <p className="mt-1 text-xs text-muted-foreground">{field.helperText}</p>
                        )}
                        <p className="mt-1 text-xs text-muted-foreground/70">
                          Select from dropdown or type {`{{variable}}`}
                        </p>
                      </div>
                    );
                  }

                  // Regular select fields (no dynamic support)
                  if (field.type === 'select' || usesPrinterSelect) {
                    return (
                      <div key={field.key} className="nodrag">
                        <label className="text-xs font-medium text-muted-foreground">{field.label}</label>
                        <Select
                          value={String(currentValue ?? '')}
                          onValueChange={(value) => updateNodeProperty(field.key, value)}
                          disabled={isReadOnly}
                        >
                          <SelectTrigger className="nodrag w-full">
                            <SelectValue placeholder={field.placeholder || (usesPrinterSelect ? 'Select printer' : 'Select')} />
                          </SelectTrigger>
                          <SelectContent position="popper" className="z-[100]">
                            {selectOptions.length === 0 ? (
                              <SelectItem value="__empty__" disabled>
                                No options available
                              </SelectItem>
                            ) : (
                              selectOptions.map((option: { label: string; value: string }, idx: number) => (
                                <SelectItem key={`${field.key}-${option.value}-${idx}`} value={option.value}>
                                  {option.label}
                                </SelectItem>
                              ))
                            )}
                          </SelectContent>
                        </Select>
                        {field.helperText && (
                          <p className="mt-1 text-xs text-muted-foreground">{field.helperText}</p>
                        )}
                      </div>
                    );
                  }

                  // Text/string fields that support dynamic values (including email, textarea, url)
                  if (field.supportsDynamic && (field.type === 'string' || field.type === 'email' || field.type === 'textarea' || field.type === 'url')) {
                    return (
                      <div key={field.key} className="nodrag">
                        <label className="text-xs font-medium text-muted-foreground">
                          {field.label}
                          {field.required && <span className="text-red-500 ml-1">*</span>}
                        </label>
                        <VariablePicker
                          value={currentValue !== undefined ? String(currentValue) : ''}
                          onChange={(value) => updateNodeProperty(field.key, value)}
                          nodes={nodes}
                          edges={edges}
                          currentNodeId={selectedNode.id}
                          registry={registry}
                          placeholder={field.placeholder}
                          disabled={isReadOnly}
                          acceptsTypes={field.acceptsTypes || []}
                          fieldType={field.type}
                        />
                        {field.helperText && (
                          <p className="mt-1 text-xs text-muted-foreground">{field.helperText}</p>
                        )}
                        <p className="mt-1 text-xs text-muted-foreground/70">
                          Supports variables: {`{{variable_name}}`}
                        </p>
                      </div>
                    );
                  }

                  // Regular text/number input fields
                  return (
                    <div key={field.key} className="nodrag">
                      <label className="text-xs font-medium text-muted-foreground">{field.label}</label>
                      <Input
                        className="nodrag"
                        type={field.type === 'number' ? 'number' : 'text'}
                        value={currentValue !== undefined ? String(currentValue) : ''}
                        onChange={(event) => updateNodeProperty(field.key, field.type === 'number' ? Number(event.target.value) : event.target.value)}
                        placeholder={field.placeholder}
                        disabled={isReadOnly}
                      />
                      {field.helperText && (
                        <p className="mt-1 text-xs text-muted-foreground">{field.helperText}</p>
                      )}
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </div>
        )}

        <div className="absolute right-6 top-[5.5rem] z-10">
          <NodePalette
            nodes={registry}
            onAdd={handleAddNode}
            onDragStart={handleDragStart}
            disabled={!canEdit}
            collapsed={!paletteOpen}
            onToggle={() => setPaletteOpen((open) => !open)}
          />
        </div>

        <div className="h-full w-full" onDrop={handleDrop} onDragOver={handleDragOver} style={{ height: 'calc(100vh - 4rem)' }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onInit={setReactFlowInstance}
            onNodesChange={handleNodesChange}
            onEdgesChange={handleEdgesChange}
            onConnect={handleConnect}
            onNodeClick={handleSelection}
            onEdgeClick={handleEdgeClick}
            onPaneClick={() => {
              setSelectedNodeId(null);
              setSelectedEdgeId(null);
              // Reset edge selection styling
              setEdges((current: Edge[]) =>
                current.map((e) => ({
                  ...e,
                  style: { ...e.style, strokeWidth: 3 },
                  selected: false,
                }))
              );
              // Reset node zIndex
              setNodes((current: Node<WorkflowNodeData>[]) =>
                current.map((n) => ({
                  ...n,
                  zIndex: 0,
                }))
              );
            }}
            nodeTypes={nodeTypes}
            fitView
            defaultViewport={defaultViewport}
            snapToGrid
            snapGrid={GRID_SIZE}
            nodesDraggable={canEdit}
            nodesConnectable={canEdit}
            nodesFocusable={false}
            edgesFocusable={canEdit}
            elementsSelectable={canEdit}
            connectionLineType={ConnectionLineType.Bezier}
            connectionLineStyle={{
              strokeWidth: 2,
              stroke: connectionNodeId ? nodes.find(n => n.id === connectionNodeId)?.data?.color || '#10b981' : '#10b981',
            }}
            defaultEdgeOptions={{
              type: 'default',
              animated: false,
              style: { strokeWidth: 2 },
            }}
            onMoveEnd={(_: unknown, viewport: Viewport) => {
              setUiState(viewport);
              if (canEdit) {
                markDirty();
              }
            }}
            onConnectStart={(_, params) => {
              if (!params?.nodeId || !params.handleId || !params.handleType) {
                return;
              }
              dragStateRef.current = {
                nodeId: params.nodeId,
                handleId: params.handleId,
                handleType: params.handleType,
                active: true,
              };
              setConnectionNodeId(params.nodeId);
              applyDragState(true);
            }}
            onConnectEnd={() => {
              dragStateRef.current = { nodeId: null, handleId: null, handleType: null, active: false };
              setConnectionNodeId(null);
              applyDragState(false);
            }}
            proOptions={{ hideAttribution: true }}
          >
            <Controls className="!rounded-lg !shadow-lg" />
            <Background gap={20} size={1} color="#1f2937" />
          </ReactFlow>
        </div>
      </div>
      <AlertDialog open={exitDialogOpen} onOpenChange={setExitDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>
              You have unsaved changes in this workflow. Exit without saving?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => navigate('/workflows')}>
              Exit without saving
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </ReactFlowProvider>
  );
}

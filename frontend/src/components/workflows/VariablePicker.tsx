import { useState, useCallback, useMemo } from 'react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Variable, ChevronDown, Search, Info } from 'lucide-react';
import type { Node, Edge } from '@xyflow/react';
import type { WorkflowRegistryNode } from '@/types/api';

interface OutputSchemaItem {
  key: string;
  type: string;
  description: string;
}

interface VariablePickerProps {
  value: string;
  onChange: (value: string) => void;
  nodes: Node[];
  edges: Edge[];
  currentNodeId: string;
  registry: WorkflowRegistryNode[];
  placeholder?: string;
  disabled?: boolean;
  options?: Array<{ label: string; value: string }>;
}

export function VariablePicker({
  value,
  onChange,
  nodes,
  edges,
  currentNodeId,
  registry,
  placeholder = 'Enter value...',
  disabled = false,
  options,
}: VariablePickerProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const hasOptions = options && options.length > 0;

  // Find upstream nodes by traversing edges backwards
  const upstreamNodes = useMemo(() => {
    const upstream: Node[] = [];
    const visited = new Set<string>();
    
    const findUpstream = (nodeId: string) => {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      
      // Find edges that point TO this node
      const incomingEdges = edges.filter(edge => edge.target === nodeId);
      
      for (const edge of incomingEdges) {
        const sourceNode = nodes.find(n => n.id === edge.source);
        if (sourceNode && sourceNode.id !== currentNodeId) {
          upstream.push(sourceNode);
          findUpstream(sourceNode.id);
        }
      }
    };
    
    findUpstream(currentNodeId);
    return upstream;
  }, [nodes, edges, currentNodeId]);

  // Get available variables from upstream nodes
  const availableVariables = useMemo(() => {
    const variables: Array<{
      nodeId: string;
      nodeLabel: string;
      nodeType: string;
      variable: OutputSchemaItem;
    }> = [];

    for (const node of upstreamNodes) {
      const nodeType = node.type as string;
      const registryNode = registry.find(r => r.node_key === nodeType);
      const outputSchema = registryNode?.output_schema as OutputSchemaItem[] | undefined;
      
      if (outputSchema && Array.isArray(outputSchema)) {
        for (const output of outputSchema) {
          variables.push({
            nodeId: node.id,
            nodeLabel: (node.data as { label?: string })?.label || nodeType,
            nodeType,
            variable: output,
          });
        }
      }
    }

    // Filter by search
    if (search) {
      const lowerSearch = search.toLowerCase();
      return variables.filter(v => 
        v.variable.key.toLowerCase().includes(lowerSearch) ||
        v.variable.description.toLowerCase().includes(lowerSearch) ||
        v.nodeLabel.toLowerCase().includes(lowerSearch)
      );
    }

    return variables;
  }, [upstreamNodes, registry, search]);

  const insertVariable = useCallback((variableKey: string) => {
    // Insert {{variable}} at cursor position or append
    const newValue = value ? `${value}{{${variableKey}}}` : `{{${variableKey}}}`;
    onChange(newValue);
    setOpen(false);
  }, [value, onChange]);

  const selectOption = useCallback((optionValue: string) => {
    onChange(optionValue);
    setOpen(false);
  }, [onChange]);

  const getTypeBadgeColor = (type: string) => {
    switch (type) {
      case 'string': return 'bg-blue-500/20 text-blue-500';
      case 'number': return 'bg-green-500/20 text-green-500';
      case 'boolean': return 'bg-purple-500/20 text-purple-500';
      case 'object': return 'bg-orange-500/20 text-orange-500';
      default: return 'bg-gray-500/20 text-gray-500';
    }
  };

  return (
    <div className="flex gap-2">
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className="flex-1 font-mono text-sm"
      />
      <DropdownMenu open={open} onOpenChange={setOpen}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            disabled={disabled || (availableVariables.length === 0 && !hasOptions)}
            title={
              availableVariables.length === 0 && !hasOptions
                ? 'No options or variables available'
                : hasOptions
                ? 'Select value or insert variable'
                : 'Insert variable'
            }
          >
            <Variable className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent className="w-80 p-0" align="end">
          <div className="border-b p-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={hasOptions ? "Search options or variables..." : "Search variables..."}
                className="pl-8"
              />
            </div>
          </div>
          <div className="max-h-[300px] overflow-y-auto">
            {hasOptions && (
              <div className="border-b p-2">
                <div className="mb-2 px-2 text-xs font-semibold text-muted-foreground">Select Value</div>
                {options
                  .filter(opt => !search || opt.label.toLowerCase().includes(search.toLowerCase()))
                  .map((option) => (
                    <button
                      key={option.value}
                      className="flex w-full items-center gap-2 rounded-md p-2 text-left hover:bg-muted"
                      onClick={() => selectOption(option.value)}
                    >
                      <div className="flex-1">
                        <div className="text-sm font-medium">{option.label}</div>
                        <div className="text-xs text-muted-foreground">{option.value}</div>
                      </div>
                    </button>
                  ))}
              </div>
            )}
            {availableVariables.length === 0 && !hasOptions ? (
              <div className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
                <Info className="h-4 w-4" />
                <span>No variables available from upstream nodes</span>
              </div>
            ) : availableVariables.length > 0 ? (
              <div className="p-2">
                <div className="mb-2 px-2 text-xs font-semibold text-muted-foreground">
                  {hasOptions ? 'Or Use Variable' : 'Available Variables'}
                </div>
                {availableVariables.map((item, index) => (
                  <button
                    key={`${item.nodeId}-${item.variable.key}-${index}`}
                    className="flex w-full flex-col gap-1 rounded-md p-2 text-left hover:bg-muted"
                    onClick={() => insertVariable(item.variable.key)}
                  >
                    <div className="flex items-center justify-between">
                      <code className="text-sm font-semibold text-primary">
                        {`{{${item.variable.key}}}`}
                      </code>
                      <Badge variant="secondary" className={`text-xs ${getTypeBadgeColor(item.variable.type)}`}>
                        {item.variable.type}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {item.variable.description}
                    </div>
                    <div className="flex items-center gap-1 text-xs text-muted-foreground/70">
                      <ChevronDown className="h-3 w-3" />
                      <span>from: {item.nodeLabel}</span>
                    </div>
                  </button>
                ))}
              </div>
            ) : null}
          </div>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

import { useState, useCallback, useMemo } from 'react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Variable, Search, Info } from 'lucide-react';
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
  /** Variable types this field can accept. Empty array = accepts all. */
  acceptsTypes?: string[];
  /** Field type for display purposes */
  fieldType?: string;
}

/**
 * Check if a variable type is compatible with the field's accepted types.
 * This is strict - only exact matches or explicit compatibility.
 */
function isTypeCompatible(variableType: string, acceptsTypes?: string[]): boolean {
  // If no acceptsTypes specified, accept only generic string-like types
  if (!acceptsTypes || acceptsTypes.length === 0) {
    // Be permissive for untyped fields - accept common text types
    return ['string', 'email', 'url', 'timestamp'].includes(variableType);
  }
  
  // 'any' accepts everything
  if (acceptsTypes.includes('any')) return true;
  
  // Check if the variable type is directly in the accepted list
  if (acceptsTypes.includes(variableType)) return true;
  
  // 'string' in acceptsTypes allows generic string-like types
  if (acceptsTypes.includes('string')) {
    return ['string', 'email', 'url', 'timestamp'].includes(variableType);
  }
  
  return false;
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
  acceptsTypes,
  fieldType: _fieldType, // Available for future field-specific rendering
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

  // Get available variables from upstream nodes, filtered by compatibility
  const { compatibleVariables } = useMemo(() => {
    const compatible: Array<{
      nodeId: string;
      nodeLabel: string;
      nodeType: string;
      variable: OutputSchemaItem;
    }> = [];
    const incompatible: Array<{
      nodeId: string;
      nodeLabel: string;
      nodeType: string;
      variable: OutputSchemaItem;
    }> = [];

    for (const node of upstreamNodes) {
      // Use registryKey from node.data, not node.type (which is 'workflowNode' for all custom nodes)
      const nodeData = node.data as { registryKey?: string; label?: string };
      const registryKey = nodeData.registryKey;
      if (!registryKey) continue;
      
      const registryNode = registry.find(r => r.key === registryKey || r.node_key === registryKey);
      const outputSchema = registryNode?.output_schema as OutputSchemaItem[] | undefined;
      
      if (outputSchema && Array.isArray(outputSchema)) {
        for (const output of outputSchema) {
          const varItem = {
            nodeId: node.id,
            nodeLabel: nodeData.label || registryKey,
            nodeType: registryKey,
            variable: output,
          };
          
          if (isTypeCompatible(output.type, acceptsTypes)) {
            compatible.push(varItem);
          } else {
            incompatible.push(varItem);
          }
        }
      }
    }

    // Filter by search
    const filterBySearch = (vars: typeof compatible) => {
      if (!search) return vars;
      const lowerSearch = search.toLowerCase();
      return vars.filter(v => 
        v.variable.key.toLowerCase().includes(lowerSearch) ||
        v.variable.description.toLowerCase().includes(lowerSearch) ||
        v.nodeLabel.toLowerCase().includes(lowerSearch)
      );
    };

    return {
      compatibleVariables: filterBySearch(compatible),
      incompatibleVariables: filterBySearch(incompatible),
    };
  }, [upstreamNodes, registry, search, acceptsTypes]);

  const insertVariable = useCallback((variableKey: string) => {
    // Insert {{variable}} at cursor position or append
    const newValue = value ? `${value}{{${variableKey}}}` : `{{${variableKey}}}`;
    onChange(newValue);
    setOpen(false);
    setSearch('');
  }, [value, onChange]);

  const selectOption = useCallback((optionValue: string) => {
    onChange(optionValue);
    setOpen(false);
    setSearch('');
  }, [onChange]);

  // Only show compatible variables - don't confuse users with incompatible ones
  const availableVariables = compatibleVariables;
  const hasAnyVariables = availableVariables.length > 0;

  return (
    <div className="flex gap-2 nodrag nowheel">
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className="flex-1 font-mono text-sm"
      />
      <DropdownMenu modal={true} open={open} onOpenChange={(newOpen) => { setOpen(newOpen); if (!newOpen) setSearch(''); }}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            disabled={disabled || (!hasAnyVariables && !hasOptions)}
            title={
              !hasAnyVariables && !hasOptions
                ? 'No options or variables available'
                : hasOptions
                ? 'Select value or insert variable'
                : 'Insert variable'
            }
          >
            <Variable className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent className="w-80 p-0 z-[100]" align="end">
          <div className="border-b p-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={hasOptions ? "Search options or variables..." : "Search variables..."}
                className="pl-8 nodrag"
              />
            </div>
          </div>
          <div className="max-h-[300px] overflow-y-auto">
            {/* Static options (e.g., printer list) */}
            {hasOptions && (
              <div className="p-1">
                {options
                  .filter(opt => !search || opt.label.toLowerCase().includes(search.toLowerCase()))
                  .map((option, idx) => (
                    <button
                      key={`opt-${option.value}-${idx}`}
                      className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-accent"
                      onClick={() => selectOption(option.value)}
                    >
                      <span className="flex-1 truncate">{option.label}</span>
                    </button>
                  ))}
              </div>
            )}

            {/* Separator if both options and variables exist */}
            {hasOptions && availableVariables.length > 0 && (
              <div className="mx-2 my-1 border-t" />
            )}

            {/* Variables from upstream nodes */}
            {availableVariables.length > 0 && (
              <div className="p-1">
                <div className="px-2 py-1 text-xs font-medium text-muted-foreground">Variables</div>
                {availableVariables.map((item, index) => (
                  <button
                    key={`var-${item.nodeId}-${item.variable.key}-${index}`}
                    className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-accent"
                    onClick={() => insertVariable(item.variable.key)}
                  >
                    <code className="text-xs font-medium text-primary">{`{{${item.variable.key}}}`}</code>
                    <span className="flex-1 truncate text-xs text-muted-foreground">{item.variable.description}</span>
                  </button>
                ))}
              </div>
            )}

            {/* Empty state */}
            {!hasAnyVariables && !hasOptions && (
              <div className="flex items-center gap-2 p-3 text-sm text-muted-foreground">
                <Info className="h-4 w-4" />
                <span>No variables available</span>
              </div>
            )}
          </div>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

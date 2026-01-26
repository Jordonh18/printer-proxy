import { useMemo, useState } from 'react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { WorkflowRegistryNode } from '@/types/api';

interface NodePaletteProps {
  nodes: WorkflowRegistryNode[];
  onAdd: (node: WorkflowRegistryNode) => void;
  onDragStart: (event: React.DragEvent<HTMLButtonElement>, node: WorkflowRegistryNode) => void;
  disabled?: boolean;
  collapsed?: boolean;
  onToggle?: () => void;
}

export function NodePalette({ nodes, onAdd, onDragStart, disabled, collapsed, onToggle }: NodePaletteProps) {
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    if (!query.trim()) {
      return nodes;
    }
    const lower = query.toLowerCase();
    return nodes.filter((node) =>
      node.name.toLowerCase().includes(lower) ||
      node.description?.toLowerCase().includes(lower) ||
      node.category.toLowerCase().includes(lower)
    );
  }, [nodes, query]);

  const grouped = useMemo(() => {
    return filtered.reduce<Record<string, WorkflowRegistryNode[]>>((acc, node) => {
      const key = node.category || 'other';
      if (!acc[key]) acc[key] = [];
      acc[key].push(node);
      return acc;
    }, {});
  }, [filtered]);

  return (
    <div className="workflow-panel w-[320px]">
      <div className="flex items-center justify-between gap-2 border-b border-border/60 px-4 py-3">
        <div className="text-sm font-semibold">Node Library</div>
        {onToggle && (
          <button
            type="button"
            onClick={onToggle}
            className="text-xs text-muted-foreground hover:text-foreground"
          >
            {collapsed ? 'Expand' : 'Collapse'}
          </button>
        )}
      </div>
      {!collapsed && (
        <div className="space-y-4 px-4 py-3">
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search nodes"
          />
          <div className="workflow-scrollbar space-y-4 max-h-[70vh] overflow-y-auto pr-2">
        {Object.entries(grouped).map(([category, items]) => (
          <div key={category} className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {category}
              </span>
              <Badge variant="outline" className="text-[10px]">
                {items.length}
              </Badge>
            </div>
            <div className="space-y-2">
              {items.map((node) => (
                <button
                  key={node.key}
                  type="button"
                  className={cn(
                    "w-full rounded-lg border border-border/70 bg-background/60 p-3 text-left transition hover:border-primary/60 hover:bg-muted/60",
                    disabled && "cursor-not-allowed opacity-60"
                  )}
                  onClick={() => onAdd(node)}
                  onDragStart={(event) => onDragStart(event, node)}
                  draggable={!disabled}
                  disabled={disabled}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-sm font-semibold" style={{ color: node.color }}>
                        {node.name}
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground">{node.description}</p>
                    </div>
                    <Badge variant="secondary" className="text-[10px] capitalize">
                      {node.category}
                    </Badge>
                  </div>
                </button>
              ))}
            </div>
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="text-sm text-muted-foreground">No nodes match your search.</div>
        )}
          </div>
        </div>
      )}
    </div>
  );
}

import { memo } from 'react';
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu';
import type { WorkflowPort } from '@/types/api';

export interface WorkflowNodeData {
  [key: string]: unknown;
  label: string;
  description?: string;
  category: string;
  color: string;
  icon?: string;
  inputs: WorkflowPort[];
  outputs: WorkflowPort[];
  properties?: Record<string, unknown>;
  registryKey?: string;
  compatible?: boolean;
  draggingActive?: boolean;
  showHandles?: boolean;
  onDelete?: () => void;
  canEdit?: boolean;
}

function WorkflowNode({ data }: NodeProps<Node<WorkflowNodeData>>) {
  const inputs = data.inputs || [];
  const outputs = data.outputs || [];
  const showHandles = data.showHandles !== false && (!data.draggingActive || data.compatible);
  const isGhosted = data.draggingActive && data.compatible === false;

  const shapeRadiusClass = 'rounded-lg';
  const shapeBorderClass = 'border-2';

  const handleBaseClass = showHandles
    ? 'opacity-0 group-hover:opacity-100'
    : 'opacity-0 pointer-events-none';

  return (
    <ContextMenu>
      <ContextMenuTrigger className="group relative min-w-[220px]">
        <div
          className={`workflow-node relative bg-card/90 text-card-foreground shadow-lg ${shapeRadiusClass} ${shapeBorderClass} ${isGhosted ? 'group-hover:opacity-60' : ''}`}
          style={{ borderColor: data.color }}
        >
        <div className="px-4 py-3">
          <div className="text-sm font-semibold text-foreground">{data.label}</div>
          <div className="text-xs text-muted-foreground">{data.description}</div>
        </div>

        {(inputs.length > 0 || outputs.length > 0) && (
          <div className="border-t border-border/60 px-4 py-2 text-xs text-muted-foreground">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                {inputs.map((input: WorkflowPort, index: number) => {
                  const topPercent = `${((index + 1) / (inputs.length + 1)) * 100}%`;
                  return (
                  <div key={input.id} className="relative flex items-center gap-2">
                    <Handle
                      id={`${input.id}:left`}
                      type="target"
                      position={Position.Left}
                      className={`!h-3 !w-3 !border-2 !border-background transition ${handleBaseClass}`}
                      style={{
                        backgroundColor: data.color,
                        left: '-6px',
                        top: topPercent,
                        transform: 'translateY(-50%)',
                      }}
                    />
                    <Handle
                      id={input.id}
                      type="target"
                      position={Position.Left}
                      className="!h-3 !w-3 opacity-0 pointer-events-none"
                      style={{
                        backgroundColor: data.color,
                        left: '-6px',
                        top: topPercent,
                        transform: 'translateY(-50%)',
                      }}
                    />
                    <span className="ml-2 truncate">{input.label || input.id}</span>
                  </div>
                );
                })}
              </div>
              <div className="space-y-2 text-right">
                {outputs.map((output: WorkflowPort, index: number) => {
                  const topPercent = `${((index + 1) / (outputs.length + 1)) * 100}%`;
                  return (
                  <div key={output.id} className="relative flex items-center justify-end gap-2">
                    <span className="mr-2 truncate">{output.label || output.id}</span>
                    <Handle
                      id={`${output.id}:right`}
                      type="source"
                      position={Position.Right}
                      className={`!h-3 !w-3 !border-2 !border-background transition ${handleBaseClass}`}
                      style={{
                        backgroundColor: data.color,
                        right: '-6px',
                        top: topPercent,
                        transform: 'translateY(-50%)',
                      }}
                    />
                    <Handle
                      id={output.id}
                      type="source"
                      position={Position.Right}
                      className="!h-3 !w-3 opacity-0 pointer-events-none"
                      style={{
                        backgroundColor: data.color,
                        right: '-6px',
                        top: topPercent,
                        transform: 'translateY(-50%)',
                      }}
                    />
                  </div>
                );
                })}
              </div>
            </div>
          </div>
        )}

        {isGhosted && (
          <div className={`absolute inset-0 flex items-center justify-center ${shapeRadiusClass} bg-background/70 text-xs font-semibold uppercase tracking-wide text-muted-foreground opacity-0 transition group-hover:opacity-100`}>
            Not compatible
          </div>
        )}
        </div>
      </ContextMenuTrigger>
      <ContextMenuContent>
        <ContextMenuItem
          variant="destructive"
          disabled={!data.canEdit}
          onSelect={() => data.onDelete?.()}
        >
          Delete Node
        </ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem disabled>Duplicate (coming soon)</ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}

export default memo(WorkflowNode);

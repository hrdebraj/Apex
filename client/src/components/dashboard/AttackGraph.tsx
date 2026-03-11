import { useCallback, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  NodeTypes,
  Handle,
  Position,
  useNodesState,
  useEdgesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useAgentStore } from "../../stores/agentStore";
import { useListenerStore } from "../../stores/listenerStore";
import { Radio, Monitor, Server } from "lucide-react";

// Custom node for the team server
function TeamServerNode({ data }: { data: any }) {
  return (
    <div className="px-4 py-3 rounded-lg bg-apex-accent/20 border border-apex-accent/40 text-center min-w-[120px]">
      <Handle type="source" position={Position.Bottom} className="!bg-apex-accent !w-2 !h-2" />
      <Server className="w-5 h-5 text-apex-accent mx-auto mb-1" />
      <div className="text-xs font-semibold text-apex-accent">{data.label}</div>
      <div className="text-[10px] text-apex-muted">{data.sub}</div>
    </div>
  );
}

// Custom node for listeners
function ListenerNode({ data }: { data: any }) {
  return (
    <div className="px-3 py-2.5 rounded-lg bg-apex-warning/15 border border-apex-warning/30 text-center min-w-[110px]">
      <Handle type="target" position={Position.Top} className="!bg-apex-warning !w-2 !h-2" />
      <Handle type="source" position={Position.Bottom} className="!bg-apex-warning !w-2 !h-2" />
      <Radio className="w-4 h-4 text-apex-warning mx-auto mb-1" />
      <div className="text-xs font-medium text-apex-text">{data.label}</div>
      <div className="text-[10px] text-apex-muted font-mono">{data.sub}</div>
    </div>
  );
}

// Custom node for agents
function AgentNode({ data }: { data: any }) {
  const alive = data.alive;
  return (
    <div className={`px-3 py-2.5 rounded-lg border text-center min-w-[110px] ${
      alive
        ? "bg-apex-accent/10 border-apex-accent/30"
        : "bg-apex-muted/10 border-apex-muted/20"
    }`}>
      <Handle type="target" position={Position.Top} className={`!w-2 !h-2 ${alive ? "!bg-apex-accent" : "!bg-apex-muted"}`} />
      <Monitor className={`w-4 h-4 mx-auto mb-1 ${alive ? "text-apex-accent" : "text-apex-muted"}`} />
      <div className="text-xs font-medium text-apex-text">{data.label}</div>
      <div className="text-[10px] text-apex-muted font-mono">{data.sub}</div>
      <div className={`text-[9px] mt-0.5 ${alive ? "text-apex-accent" : "text-apex-muted"}`}>
        {alive ? "ALIVE" : "DEAD"}
      </div>
    </div>
  );
}

const nodeTypes: NodeTypes = {
  teamserver: TeamServerNode,
  listener: ListenerNode,
  agent: AgentNode,
};

export default function AttackGraph() {
  const agents = useAgentStore((s) => s.agents);
  const listeners = useListenerStore((s) => s.listeners);

  const { initialNodes, initialEdges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];

    // Team server at the top
    nodes.push({
      id: "teamserver",
      type: "teamserver",
      position: { x: 300, y: 20 },
      data: { label: "Apex Server", sub: "Team Server" },
    });

    // Listeners in the middle
    const listenerSpacing = 200;
    const listenerStartX = 300 - ((listeners.length - 1) * listenerSpacing) / 2;

    listeners.forEach((l, i) => {
      const id = `listener-${l.id}`;
      nodes.push({
        id,
        type: "listener",
        position: { x: listenerStartX + i * listenerSpacing, y: 140 },
        data: {
          label: l.name,
          sub: `${l.protocol.toUpperCase()}:${l.bindPort}`,
        },
      });
      edges.push({
        id: `e-ts-${l.id}`,
        source: "teamserver",
        target: id,
        animated: l.status === "active",
        style: { stroke: l.status === "active" ? "#00d4aa" : "#6e6e8a", strokeWidth: 1.5 },
      });
    });

    // Agents at the bottom
    const agentsByListener = new Map<string, typeof agents>();
    const orphanAgents: typeof agents = [];

    agents.forEach((a) => {
      if (a.listenerId && listeners.find((l) => l.id === a.listenerId)) {
        const list = agentsByListener.get(a.listenerId) || [];
        list.push(a);
        agentsByListener.set(a.listenerId, list);
      } else {
        orphanAgents.push(a);
      }
    });

    let agentX = 50;
    agentsByListener.forEach((agentList, listenerId) => {
      agentList.forEach((a) => {
        const id = `agent-${a.id}`;
        nodes.push({
          id,
          type: "agent",
          position: { x: agentX, y: 280 },
          data: {
            label: a.hostname,
            sub: `${a.username} | ${a.internalIp}`,
            alive: a.alive,
          },
        });
        edges.push({
          id: `e-${listenerId}-${a.id}`,
          source: `listener-${listenerId}`,
          target: id,
          animated: a.alive,
          style: { stroke: a.alive ? "#00d4aa" : "#6e6e8a", strokeWidth: 1 },
        });
        agentX += 180;
      });
    });

    orphanAgents.forEach((a) => {
      const id = `agent-${a.id}`;
      nodes.push({
        id,
        type: "agent",
        position: { x: agentX, y: 280 },
        data: {
          label: a.hostname,
          sub: `${a.username} | ${a.internalIp}`,
          alive: a.alive,
        },
      });
      edges.push({
        id: `e-ts-${a.id}`,
        source: "teamserver",
        target: id,
        animated: a.alive,
        style: { stroke: "#6e6e8a", strokeDasharray: "5,5", strokeWidth: 1 },
      });
      agentX += 180;
    });

    return { initialNodes: nodes, initialEdges: edges };
  }, [agents, listeners]);

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div className="w-full h-full min-h-[350px]">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        proOptions={{ hideAttribution: true }}
        className="bg-apex-bg"
      >
        <Background color="#1a1a26" gap={20} size={1} />
        <Controls
          className="!bg-apex-surface !border-apex-border !rounded-lg [&>button]:!bg-apex-surface [&>button]:!border-apex-border [&>button]:!text-apex-muted [&>button:hover]:!bg-apex-hover"
        />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === "teamserver") return "#00d4aa";
            if (n.type === "listener") return "#ffaa00";
            return "#6e6e8a";
          }}
          className="!bg-apex-surface !border-apex-border"
        />
      </ReactFlow>
    </div>
  );
}

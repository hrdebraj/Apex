import AttackGraph from "../components/dashboard/AttackGraph";

export default function GraphPage() {
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-apex-text">Attack Graph</h2>
        <span className="text-xs text-apex-muted">
          Drag nodes to rearrange. Scroll to zoom.
        </span>
      </div>
      <div className="flex-1 apex-card overflow-hidden rounded-lg">
        <AttackGraph />
      </div>
    </div>
  );
}

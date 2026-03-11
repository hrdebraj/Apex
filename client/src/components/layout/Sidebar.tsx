import { NavLink, useNavigate } from "react-router-dom";
import { useAuthStore } from "../../stores/authStore";
import { useOpsecStore } from "../../stores/opsecStore";
import {
  LayoutDashboard,
  Radio,
  Monitor,
  Terminal,
  GitGraph,
  Crosshair,
  Settings,
  LogOut,
  Shield,
  Package,
  Layers,
} from "lucide-react";

const navItems = [
  { to: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/listeners", icon: Radio, label: "Listeners" },
  { to: "/agents", icon: Monitor, label: "Agents" },
  { to: "/agent-builder", icon: Package, label: "Agent Builder" },
  { to: "/terminal", icon: Terminal, label: "Terminal" },
  { to: "/modules", icon: Layers, label: "Modules" },
  { to: "/graph", icon: GitGraph, label: "Attack Graph" },
  { to: "/mitre", icon: Crosshair, label: "MITRE ATT&CK" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export default function Sidebar() {
  const { operator, logout } = useAuthStore();
  const unackedWarnings = useOpsecStore((s) => s.warnings.filter((w) => !w.acknowledged).length);
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <aside className="w-60 h-screen bg-apex-surface border-r border-apex-border flex flex-col">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-apex-border">
        <div className="flex items-center gap-2.5">
          <Shield className="w-7 h-7 text-apex-accent" />
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-apex-text">
              APEX
            </h1>
            <p className="text-[10px] font-mono text-apex-muted tracking-widest uppercase">
              Command & Control
            </p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                isActive
                  ? "bg-apex-accent/10 text-apex-accent"
                  : "text-apex-muted hover:text-apex-text hover:bg-apex-hover"
              }`
            }
          >
            <Icon className="w-4 h-4" />
            <span className="flex-1">{label}</span>
            {to === "/terminal" && unackedWarnings > 0 && (
              <span className="w-5 h-5 rounded-full bg-apex-danger/20 text-apex-danger text-[10px] font-bold flex items-center justify-center">
                {unackedWarnings}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Operator */}
      <div className="px-3 py-4 border-t border-apex-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 min-w-0">
            <div className="w-7 h-7 rounded-full bg-apex-accent/20 flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-semibold text-apex-accent">
                {operator?.username?.charAt(0).toUpperCase()}
              </span>
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium text-apex-text truncate">
                {operator?.username}
              </p>
              <p className="text-[10px] text-apex-muted uppercase tracking-wider">
                {operator?.role}
              </p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="p-1.5 rounded text-apex-muted hover:text-apex-danger hover:bg-apex-danger/10 transition-colors"
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}

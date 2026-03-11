import { Routes, Route, Navigate } from "react-router-dom";
import { useAuthStore } from "./stores/authStore";
import { useSSE } from "./hooks/useSSE";
import Layout from "./components/layout/Layout";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import ListenersPage from "./pages/ListenersPage";
import AgentsPage from "./pages/AgentsPage";
import AgentBuilderPage from "./pages/AgentBuilderPage";
import TerminalPage from "./pages/TerminalPage";
import GraphPage from "./pages/GraphPage";
import MitrePage from "./pages/MitrePage";
import ModulesPage from "./pages/ModulesPage";
import SettingsPage from "./pages/SettingsPage";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function AppShell() {
  useSSE();
  return <Layout />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AppShell />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="listeners" element={<ListenersPage />} />
        <Route path="agents" element={<AgentsPage />} />
        <Route path="agent-builder" element={<AgentBuilderPage />} />
        <Route path="terminal" element={<TerminalPage />} />
        <Route path="graph" element={<GraphPage />} />
        <Route path="mitre" element={<MitrePage />} />
        <Route path="modules" element={<ModulesPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../stores/authStore";
import { authService } from "../services/authService";
import { Shield, Loader2, AlertTriangle } from "lucide-react";

export default function LoginPage() {
  const navigate = useNavigate();
  const { login, serverAddr, setServerAddr } = useAuthStore();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await authService.login(username, password);
      login(serverAddr, res.token, {
        id: res.operator.id,
        username: res.operator.username,
        role: res.operator.role,
      });
      navigate("/dashboard");
    } catch (err: any) {
      if (err.message === "Failed to fetch") {
        setError("Cannot connect to team server. Is it running?");
      } else {
        setError(err.message || "Authentication failed");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-apex-bg">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-apex-accent/10 mb-4">
            <Shield className="w-8 h-8 text-apex-accent" />
          </div>
          <h1 className="text-2xl font-bold text-apex-text tracking-tight">
            APEX
          </h1>
          <p className="text-sm text-apex-muted mt-1">
            Connect to Team Server
          </p>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="apex-card p-6 space-y-4">
          <div>
            <label className="block text-xs font-medium text-apex-muted mb-1.5 uppercase tracking-wider">
              Server Address
            </label>
            <input
              type="text"
              value={serverAddr}
              onChange={(e) => setServerAddr(e.target.value)}
              className="apex-input"
              placeholder="localhost:8443"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-apex-muted mb-1.5 uppercase tracking-wider">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="apex-input"
              placeholder="operator"
              autoFocus
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-apex-muted mb-1.5 uppercase tracking-wider">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="apex-input"
              placeholder="&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;&#9679;"
            />
          </div>

          {error && (
            <div className="flex items-start gap-2 px-3 py-2 rounded bg-apex-danger/10 border border-apex-danger/20 text-apex-danger text-xs">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full apex-btn-primary py-2.5 flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              "Connect"
            )}
          </button>
        </form>

        <p className="text-center text-[11px] text-apex-muted mt-6 font-mono">
          Apex C2 Framework
        </p>
      </div>
    </div>
  );
}

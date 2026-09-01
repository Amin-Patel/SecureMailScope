import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Layout } from './components/Layout';
import { Landing } from './pages/Landing';
import { Login } from './pages/Login';
import { ForgotPassword } from './pages/ForgotPassword';
import { ResetPassword } from './pages/ResetPassword';
import { NewAnalysis } from './pages/NewAnalysis';
import { Dashboard } from './pages/Dashboard';
import { Analysis } from './pages/Analysis';
import { History } from './pages/History';
import { Help } from './pages/Help';
import { Settings } from './pages/Settings';
import { checkBackendHealth } from './utils/api';

// Protected Route wrapper: Redirects unauthenticated users to /login
function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: '#0a0a12',
          color: '#a5b4fc',
          fontSize: '15px',
          fontWeight: 600,
          gap: '12px',
          fontFamily: 'var(--font-sans)',
        }}
      >
        <i className="fa-solid fa-circle-notch fa-spin" style={{ fontSize: '22px' }} />
        <span>Authenticating session...</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Layout>{children}</Layout>;
}

export default function App() {
  const [backendOffline, setBackendOffline] = React.useState(false);

  React.useEffect(() => {
    const verifyHealth = async () => {
      try {
        await checkBackendHealth();
        setBackendOffline(false);
      } catch (err) {
        setBackendOffline(true);
      }
    };

    verifyHealth();
    const interval = setInterval(verifyHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <AuthProvider>
      <BrowserRouter>
        {backendOffline && (
          <div
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              backgroundColor: '#ef4444',
              color: '#ffffff',
              textAlign: 'center',
              padding: '10px 20px',
              fontWeight: 'bold',
              fontSize: '14px',
              zIndex: 99999,
              boxShadow: '0 4px 6px rgba(0,0,0,0.15)',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <i className="fa-solid fa-triangle-exclamation" />
            <span>Backend disconnected. Ensure FastAPI is running on port 8001.</span>
          </div>
        )}
        <Routes>
          {/* Public Landing Page */}
          <Route path="/" element={<Landing />} />

          {/* Public Authentication Pages */}
          <Route path="/login" element={<Login />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />

          {/* Authenticated Application Routes */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/dashboard/:captureId"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/analysis"
            element={
              <ProtectedRoute>
                <Analysis />
              </ProtectedRoute>
            }
          />
          <Route
            path="/workspace"
            element={
              <ProtectedRoute>
                <NewAnalysis />
              </ProtectedRoute>
            }
          />
          <Route
            path="/history"
            element={
              <ProtectedRoute>
                <History />
              </ProtectedRoute>
            }
          />
          <Route
            path="/help"
            element={
              <ProtectedRoute>
                <Help />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Settings />
              </ProtectedRoute>
            }
          />

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}


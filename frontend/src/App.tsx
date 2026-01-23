import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import { BackendStatusProvider, useBackendStatus } from '@/contexts/BackendStatusContext';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { BackendUnavailable } from '@/components/layout/BackendUnavailable';
import { LoginPage } from '@/pages/LoginPage';
import { SetupPage } from '@/pages/SetupPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { PrintersPage } from '@/pages/PrintersPage';
import { PrinterDetailPage } from '@/pages/PrinterDetailPage';
import { RedirectsPage } from '@/pages/RedirectsPage';
import { GroupsPage } from '@/pages/GroupsPage';
import { WorkflowsPage } from '@/pages/WorkflowsPage';
import { WorkflowEditorPage } from '@/pages/WorkflowEditorPage';
import { UsersPage } from '@/pages/UsersPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { AdminGeneralPage } from '@/pages/AdminGeneralPage';
import { AdminNotificationsPage } from '@/pages/AdminNotificationsPage';
import { AdminIntegrationsPage } from '@/pages/AdminIntegrationsPage';
import { AuditLogPage } from '@/pages/AuditLogPage';
import { NotificationsPage } from '@/pages/NotificationsPage';
import NetworkingPage from '@/pages/NetworkingPage';
import { Toaster } from '@/components/ui/sonner';
import { useNotificationStream } from '@/hooks/useNotifications';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60, // 1 minute
      retry: 1,
    },
  },
});

// Component to initialize notification stream for authenticated users
function NotificationStreamProvider({ children }: { children: React.ReactNode }) {
  useNotificationStream();
  return <>{children}</>;
}

// Wrapper that checks backend status before rendering children
function BackendStatusGate({ children }: { children: React.ReactNode }) {
  const { isBackendAvailable, isChecking } = useBackendStatus();

  // Show loading state during initial check
  if (isChecking && !isBackendAvailable) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-emerald-500" />
      </div>
    );
  }

  // Show backend unavailable page if backend is down
  if (!isBackendAvailable) {
    return <BackendUnavailable />;
  }

  return <>{children}</>;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BackendStatusProvider>
        <BackendStatusGate>
          <AuthProvider>
        <NotificationStreamProvider>
          <BrowserRouter>
            <Routes>
              {/* Public routes */}
              <Route path="/login" element={<LoginPage />} />
              <Route path="/setup" element={<SetupPage />} />

              {/* Protected routes */}
              <Route
                element={
                  <ProtectedRoute>
                    <DashboardLayout />
                  </ProtectedRoute>
                }
              >
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/printers" element={<PrintersPage />} />
                <Route path="/printers/:id" element={<PrinterDetailPage />} />
                <Route path="/groups" element={<GroupsPage />} />
                <Route path="/workflows" element={<WorkflowsPage />} />
                <Route path="/workflows/:id" element={<WorkflowEditorPage />} />
                <Route path="/networking" element={<NetworkingPage />} />
                <Route path="/notifications" element={<NotificationsPage />} />
                <Route
                  path="/redirects"
                  element={
                    <ProtectedRoute requiredRoles={['admin', 'operator']}>
                      <RedirectsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/users"
                  element={
                    <ProtectedRoute requiredRoles={['admin']}>
                      <UsersPage />
                    </ProtectedRoute>
                  }
                />
                <Route path="/settings" element={<SettingsPage />} />
                <Route
                  path="/admin/general"
                  element={
                    <ProtectedRoute requiredRoles={['admin']}>
                      <AdminGeneralPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/admin/notifications"
                  element={
                    <ProtectedRoute requiredRoles={['admin']}>
                      <AdminNotificationsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/admin/integrations"
                  element={
                    <ProtectedRoute requiredRoles={['admin']}>
                      <AdminIntegrationsPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/audit-logs"
                  element={
                    <ProtectedRoute requiredRoles={['admin']}>
                      <AuditLogPage />
                    </ProtectedRoute>
                  }
                />
              </Route>

              {/* Default redirect */}
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
          </BrowserRouter>
          <Toaster />
        </NotificationStreamProvider>
      </AuthProvider>
        </BackendStatusGate>
      </BackendStatusProvider>
    </QueryClientProvider>
  );
}

export default App;

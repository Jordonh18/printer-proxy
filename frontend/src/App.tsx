import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
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
import { AdminSettingsPage } from '@/pages/AdminSettingsPage';
import { AuditLogPage } from '@/pages/AuditLogPage';
import { NotificationsPage } from '@/pages/NotificationsPage';
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

function App() {
  return (
    <QueryClientProvider client={queryClient}>
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
                  path="/admin/settings"
                  element={
                    <ProtectedRoute requiredRoles={['admin']}>
                      <AdminSettingsPage />
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
    </QueryClientProvider>
  );
}

export default App;

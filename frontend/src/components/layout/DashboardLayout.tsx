import { Link, useLocation, Outlet } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import {
  LayoutDashboard,
  Printer,
  ArrowRightLeft,
  ClipboardList,
  Users,
  Settings,
  LogOut,
  ArrowLeft,
  User,
  Shield,
  Bell,
  KeyRound,
  Plug,
  ChevronUp,
  Server,
} from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { AnimatePresence, motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
} from '@/components/ui/sidebar';
import { NotificationBell } from './NotificationBell';

const navigationGroups = [
  {
    label: 'Overview',
    items: [
      { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
    ],
  },
  {
    label: 'Fleet',
    items: [
      { name: 'Printers', href: '/printers', icon: Printer },
      { name: 'Redirects', href: '/redirects', icon: ArrowRightLeft, roles: ['admin', 'operator'] },
    ],
  },
  {
    label: 'Administration',
    items: [
      { name: 'Audit Log', href: '/audit-logs', icon: ClipboardList, roles: ['admin'] },
      { name: 'Users', href: '/users', icon: Users, roles: ['admin'] },
    ],
  },
];

export function DashboardLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const { t } = useTranslation();
  const isSettingsRoute = location.pathname.startsWith('/settings');
  const isAdminSettingsRoute = location.pathname.startsWith('/admin/settings');
  const activeSettingsTab = new URLSearchParams(location.search).get('tab') || 'account';
  const activeAdminTab = new URLSearchParams(location.search).get('tab') || 'general';

  const filteredNavigationGroups = navigationGroups.map(group => ({
    ...group,
    items: group.items.filter(
      (item) => !item.roles || (user && item.roles.includes(user.role))
    ),
  })).filter(group => group.items.length > 0);

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <div className="flex items-center gap-2 px-2 py-2">
            <Link to="/dashboard" className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <Printer className="h-5 w-5" />
              </div>
              <span className="text-base font-semibold">Printer Proxy</span>
            </Link>
          </div>
        </SidebarHeader>

        <SidebarContent>
          <AnimatePresence mode="wait" initial={false}>
            {isAdminSettingsRoute ? (
              <motion.div
                key="admin-settings-sidebar"
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 8 }}
                transition={{ duration: 0.2, ease: 'easeOut' }}
                className="space-y-4"
              >
                <SidebarGroup>
                  <SidebarGroupLabel>Admin Settings</SidebarGroupLabel>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild tooltip="Back to Dashboard">
                          <Link to="/dashboard">
                            <ArrowLeft />
                            <span>Back to Dashboard</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    </SidebarMenu>
                  </SidebarGroupContent>
                </SidebarGroup>

                <SidebarGroup>
                  <SidebarGroupLabel>Application</SidebarGroupLabel>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeAdminTab === 'general'}>
                          <Link to="/admin/settings?tab=general">
                            <Settings />
                            <span>General</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeAdminTab === 'notifications'}>
                          <Link to="/admin/settings?tab=notifications">
                            <Bell />
                            <span>Notifications</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeAdminTab === 'integrations'}>
                          <Link to="/admin/settings?tab=integrations">
                            <Plug />
                            <span>Integrations</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    </SidebarMenu>
                  </SidebarGroupContent>
                </SidebarGroup>
              </motion.div>
            ) : isSettingsRoute ? (
              <motion.div
                key="settings-sidebar"
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 8 }}
                transition={{ duration: 0.2, ease: 'easeOut' }}
                className="space-y-4"
              >
                <SidebarGroup>
                  <SidebarGroupLabel>{t('settingsNav')}</SidebarGroupLabel>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild tooltip={t('settingsBack')}>
                          <Link to="/dashboard">
                            <ArrowLeft />
                            <span>{t('settingsBack')}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    </SidebarMenu>
                  </SidebarGroupContent>
                </SidebarGroup>

                <SidebarGroup>
                  <SidebarGroupLabel>{t('general')}</SidebarGroupLabel>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeSettingsTab === 'account'}>
                          <Link to="/settings?tab=account">
                            <User />
                            <span>{t('accountInfo')}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeSettingsTab === 'security'}>
                          <Link to="/settings?tab=security">
                            <Shield />
                            <span>{t('security')}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeSettingsTab === 'notifications'}>
                          <Link to="/settings?tab=notifications">
                            <Bell />
                            <span>{t('notifications')}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeSettingsTab === 'api-tokens'}>
                          <Link to="/settings?tab=api-tokens">
                            <KeyRound />
                            <span>{t('apiTokens')}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    </SidebarMenu>
                  </SidebarGroupContent>
                </SidebarGroup>
              </motion.div>
            ) : (
              <motion.div
                key="main-sidebar"
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 8 }}
                transition={{ duration: 0.2, ease: 'easeOut' }}
              >
                {filteredNavigationGroups.map((group) => (
                  <SidebarGroup key={group.label}>
                    <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
                    <SidebarGroupContent>
                      <SidebarMenu>
                        {group.items.map((item) => {
                          const isActive =
                            location.pathname === item.href ||
                            (item.href !== '/dashboard' && location.pathname.startsWith(item.href));

                          return (
                            <SidebarMenuItem key={item.name}>
                              <SidebarMenuButton asChild isActive={isActive} tooltip={item.name}>
                                <Link to={item.href}>
                                  <item.icon />
                                  <span>{item.name}</span>
                                </Link>
                              </SidebarMenuButton>
                            </SidebarMenuItem>
                          );
                        })}
                      </SidebarMenu>
                    </SidebarGroupContent>
                  </SidebarGroup>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </SidebarContent>

        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>
              <NotificationBell />
            </SidebarMenuItem>
            <SidebarMenuItem>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <SidebarMenuButton
                    size="lg"
                    className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
                  >
                    <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10 text-primary">
                      {user?.username.charAt(0).toUpperCase()}
                    </div>
                    <div className="min-w-0 flex-1 text-left">
                      <p className="text-sm font-medium truncate">{user?.username}</p>
                      <p className="text-xs text-muted-foreground capitalize">{user?.role}</p>
                    </div>
                    <ChevronUp className="ml-auto" />
                  </SidebarMenuButton>
                </DropdownMenuTrigger>
                <DropdownMenuContent
                  side="top"
                  align="end"
                  className="w-[--radix-dropdown-menu-trigger-width]"
                >
                  <DropdownMenuItem asChild>
                    <Link to="/settings" className="cursor-pointer">
                      <User className="mr-2 h-4 w-4" />
                      <span>User Settings</span>
                    </Link>
                  </DropdownMenuItem>
                  {user?.role === 'admin' && (
                    <DropdownMenuItem asChild>
                      <Link to="/admin/settings" className="cursor-pointer">
                        <Server className="mr-2 h-4 w-4" />
                        <span>Admin Settings</span>
                      </Link>
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={logout} className="cursor-pointer">
                    <LogOut className="mr-2 h-4 w-4" />
                    <span>Sign out</span>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
      </Sidebar>

      <SidebarRail />

      <SidebarInset>
        <div className="flex items-center gap-2 px-4 pt-4 md:hidden">
          <SidebarTrigger />
          <span className="text-sm font-medium text-muted-foreground">Menu</span>
        </div>
        <div className="p-4 lg:p-8">
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}

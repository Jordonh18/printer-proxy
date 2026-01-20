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
} from 'lucide-react';
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
  SidebarSeparator,
  SidebarTrigger,
} from '@/components/ui/sidebar';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Printers', href: '/printers', icon: Printer },
  { name: 'Redirects', href: '/redirects', icon: ArrowRightLeft, roles: ['admin', 'operator'] },
  { name: 'Audit Log', href: '/audit-logs', icon: ClipboardList, roles: ['admin'] },
  { name: 'Users', href: '/users', icon: Users, roles: ['admin'] },
  { name: 'Settings', href: '/settings', icon: Settings, roles: ['admin'] },
];

export function DashboardLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const { t } = useTranslation();
  const isSettingsRoute = location.pathname.startsWith('/settings');
  const activeSettingsTab = new URLSearchParams(location.search).get('tab') || 'account';

  const filteredNavigation = navigation.filter(
    (item) => !item.roles || (user && item.roles.includes(user.role))
  );

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

        <SidebarSeparator />

        <SidebarContent>
          <AnimatePresence mode="wait" initial={false}>
            {isSettingsRoute ? (
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
                  <SidebarGroupLabel>{t('account')}</SidebarGroupLabel>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeSettingsTab === 'general'}>
                          <Link to="/settings?tab=general">
                            <Settings />
                            <span>{t('general')}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
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
                    </SidebarMenu>
                  </SidebarGroupContent>
                </SidebarGroup>

                <SidebarGroup>
                  <SidebarGroupLabel>{t('developer')}</SidebarGroupLabel>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeSettingsTab === 'api-tokens'}>
                          <Link to="/settings?tab=api-tokens">
                            <KeyRound />
                            <span>{t('apiTokens')}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeSettingsTab === 'personal-tokens'}>
                          <Link to="/settings?tab=personal-tokens">
                            <KeyRound />
                            <span>{t('personalTokens')}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                      <SidebarMenuItem>
                        <SidebarMenuButton asChild isActive={activeSettingsTab === 'integrations'}>
                          <Link to="/settings?tab=integrations">
                            <Plug />
                            <span>{t('integrations')}</span>
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
                <SidebarGroup>
                  <SidebarGroupLabel>Navigation</SidebarGroupLabel>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      {filteredNavigation.map((item) => {
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
              </motion.div>
            )}
          </AnimatePresence>
        </SidebarContent>

        <SidebarSeparator />

        <SidebarFooter>
          <div className="flex items-center gap-3 rounded-md px-2 py-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10 text-primary">
              {user?.username.charAt(0).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium truncate">{user?.username}</p>
              <p className="text-xs text-muted-foreground capitalize">{user?.role}</p>
            </div>
          </div>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton onClick={logout} tooltip="Sign out">
                <LogOut />
                <span>Sign out</span>
              </SidebarMenuButton>
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

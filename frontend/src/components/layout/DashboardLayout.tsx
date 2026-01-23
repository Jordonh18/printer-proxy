import * as React from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import {
  LayoutDashboard,
  Printer,
  Layers,
  ArrowRightLeft,
  GitBranch,
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
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
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
  SidebarMenuAction,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
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
      { name: 'Groups', href: '/groups', icon: Layers },
      { name: 'Redirects', href: '/redirects', icon: ArrowRightLeft, roles: ['admin', 'operator'] },
      { name: 'Workflows', href: '/workflows', icon: GitBranch },
    ],
  },
  {
    label: 'Administration',
    items: [
      { name: 'General', href: '/admin/general', icon: Settings, roles: ['admin'] },
      { name: 'Notifications', href: '/admin/notifications', icon: Bell, roles: ['admin'] },
      { name: 'Integrations', href: '/admin/integrations', icon: Plug, roles: ['admin'] },
      { name: 'Networking', href: '/networking', icon: Server, roles: ['admin', 'operator'] },
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
  const isWorkflowEditorRoute = location.pathname.match(/^\/workflows\/\d+$/);
  const activeSettingsTab = new URLSearchParams(location.search).get('tab') || 'account';

  const filteredNavigationGroups = navigationGroups.map(group => ({
    ...group,
    items: group.items.filter(
      (item) => !item.roles || (user && item.roles.includes(user.role))
    ),
  })).filter(group => group.items.length > 0);

  return (
    <SidebarProvider>
      <AppSidebar
        user={user}
        logout={logout}
        location={location}
        isSettingsRoute={isSettingsRoute}
        filteredNavigationGroups={filteredNavigationGroups}
        activeSettingsTab={activeSettingsTab}
        t={t}
      />

      <SidebarInset>
        <div className="flex items-center gap-2 px-4 pt-4 md:hidden">
          <SidebarTrigger />
          <span className="text-sm font-medium text-muted-foreground">Menu</span>
        </div>
        <div className={isWorkflowEditorRoute ? 'h-screen' : 'p-4 lg:p-8'}>
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}

function AppSidebar({
  user,
  logout,
  location,
  isSettingsRoute,
  filteredNavigationGroups,
  activeSettingsTab,
  t,
}: {
  user: any;
  logout: () => void;
  location: any;
  isSettingsRoute: boolean;
  filteredNavigationGroups: any[];
  activeSettingsTab: string;
  t: any;
}) {
  const { state, toggleSidebar } = useSidebar();
  const [isHovering, setIsHovering] = React.useState(false);
  const isCollapsed = state === 'collapsed';

  return (
    <Sidebar 
      collapsible="icon"
      onMouseEnter={() => setIsHovering(true)}
      onMouseLeave={() => setIsHovering(false)}
    >
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground">
              <Link to="/dashboard">
                <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                  <AnimatePresence mode="wait">
                    {isCollapsed && isHovering ? (
                      <motion.div
                        key="expand-icon"
                        initial={{ opacity: 0, scale: 0.8 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.8 }}
                        transition={{ duration: 0.15 }}
                        onClick={(e) => {
                          e.preventDefault();
                          toggleSidebar();
                        }}
                        className="cursor-pointer flex items-center justify-center"
                      >
                        <PanelLeftOpen className="size-4" />
                      </motion.div>
                    ) : (
                      <motion.div
                        key="printer-icon"
                        initial={{ opacity: 0, scale: 0.8 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.8 }}
                        transition={{ duration: 0.15 }}
                      >
                        <Printer className="size-4" />
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-semibold">Continuum</span>
                  <span className="truncate text-xs">Fleet Management</span>
                </div>
              </Link>
            </SidebarMenuButton>
            <SidebarMenuAction className="h-8 w-8" onClick={toggleSidebar}>
              <PanelLeftClose />
              <span className="sr-only">Collapse Sidebar</span>
            </SidebarMenuAction>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

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
                    <Avatar className="h-8 w-8">
                      <AvatarFallback className="bg-primary/10 text-primary font-medium">
                        {user?.username.charAt(0).toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                    <div className="grid flex-1 text-left text-sm leading-tight">
                      <span className="truncate font-semibold">{user?.username}</span>
                      <span className="truncate text-xs capitalize">{user?.role}</span>
                    </div>
                    <ChevronUp className="ml-auto size-4" />
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
    );
}

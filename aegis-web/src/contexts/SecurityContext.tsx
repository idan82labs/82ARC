/**
 * SecurityContext - Enterprise-grade authentication and authorization context
 *
 * Security Features:
 * - Authentication state management
 * - Role-based access control (RBAC)
 * - Permission checking
 * - Session timeout handling
 * - CSRF token management
 * - Security event emission
 *
 * SOC2/ISO 27001 Compliance:
 * - Audit logging integration
 * - Session management
 * - Access control patterns
 */

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { v4 as uuidv4 } from 'uuid';

// ==================== TYPES ====================

export type Role = 'guest' | 'user' | 'analyst' | 'admin' | 'superadmin';

export type Permission =
  | 'simulation:view'
  | 'simulation:execute'
  | 'simulation:export'
  | 'reports:view'
  | 'reports:generate'
  | 'reports:export'
  | 'settings:view'
  | 'settings:modify'
  | 'users:view'
  | 'users:manage'
  | 'audit:view'
  | 'audit:export';

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  permissions: Permission[];
  sessionId: string;
  lastActivity: number;
  mfaEnabled: boolean;
}

export interface SecurityState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  sessionExpiry: number | null;
  csrfToken: string;
  correlationId: string;
}

export interface SecurityContextType extends SecurityState {
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  hasPermission: (permission: Permission) => boolean;
  hasRole: (role: Role) => boolean;
  hasAnyRole: (roles: Role[]) => boolean;
  refreshSession: () => void;
  getCsrfToken: () => string;
  getCorrelationId: () => string;
  updateLastActivity: () => void;
}

// ==================== CONSTANTS ====================

const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const SESSION_WARNING_MS = 5 * 60 * 1000; // 5 minutes before expiry
const ACTIVITY_CHECK_INTERVAL_MS = 60 * 1000; // Check every minute

// Role hierarchy for permission inheritance
const ROLE_HIERARCHY: Record<Role, Role[]> = {
  guest: [],
  user: ['guest'],
  analyst: ['guest', 'user'],
  admin: ['guest', 'user', 'analyst'],
  superadmin: ['guest', 'user', 'analyst', 'admin']
};

// Default permissions per role
const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  guest: ['simulation:view'],
  user: ['simulation:view', 'simulation:execute', 'reports:view'],
  analyst: ['simulation:view', 'simulation:execute', 'simulation:export', 'reports:view', 'reports:generate', 'reports:export'],
  admin: ['simulation:view', 'simulation:execute', 'simulation:export', 'reports:view', 'reports:generate', 'reports:export', 'settings:view', 'settings:modify', 'users:view', 'audit:view'],
  superadmin: ['simulation:view', 'simulation:execute', 'simulation:export', 'reports:view', 'reports:generate', 'reports:export', 'settings:view', 'settings:modify', 'users:view', 'users:manage', 'audit:view', 'audit:export']
};

// ==================== CONTEXT ====================

const SecurityContext = createContext<SecurityContextType | undefined>(undefined);

// ==================== PROVIDER ====================

interface SecurityProviderProps {
  children: ReactNode;
  onSecurityEvent?: (event: SecurityEvent) => void;
}

export interface SecurityEvent {
  type: 'LOGIN' | 'LOGOUT' | 'SESSION_EXPIRED' | 'SESSION_REFRESHED' | 'PERMISSION_DENIED' | 'CSRF_VALIDATION' | 'SUSPICIOUS_ACTIVITY';
  userId?: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
  correlationId: string;
}

export const SecurityProvider: React.FC<SecurityProviderProps> = ({ children, onSecurityEvent }) => {
  // Generate stable CSRF token and correlation ID
  const [csrfToken] = useState(() => uuidv4());
  const [correlationId] = useState(() => uuidv4());

  const [state, setState] = useState<SecurityState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    sessionExpiry: null,
    csrfToken,
    correlationId
  });

  // Emit security event
  const emitSecurityEvent = useCallback((event: Omit<SecurityEvent, 'timestamp' | 'correlationId'>) => {
    const fullEvent: SecurityEvent = {
      ...event,
      timestamp: Date.now(),
      correlationId: state.correlationId
    };
    onSecurityEvent?.(fullEvent);
  }, [onSecurityEvent, state.correlationId]);

  // Check if user has specific role (including inherited roles)
  const hasRole = useCallback((role: Role): boolean => {
    if (!state.user) return false;
    if (state.user.role === role) return true;
    const inheritedRoles = ROLE_HIERARCHY[state.user.role];
    return inheritedRoles.includes(role);
  }, [state.user]);

  // Check if user has any of the specified roles
  const hasAnyRole = useCallback((roles: Role[]): boolean => {
    return roles.some(role => hasRole(role));
  }, [hasRole]);

  // Check if user has specific permission
  const hasPermission = useCallback((permission: Permission): boolean => {
    if (!state.user) return false;
    // Check direct permissions
    if (state.user.permissions.includes(permission)) return true;
    // Check role-based permissions
    return ROLE_PERMISSIONS[state.user.role]?.includes(permission) ?? false;
  }, [state.user]);

  // Update last activity timestamp
  const updateLastActivity = useCallback(() => {
    if (state.user) {
      setState(prev => ({
        ...prev,
        user: prev.user ? { ...prev.user, lastActivity: Date.now() } : null,
        sessionExpiry: Date.now() + SESSION_TIMEOUT_MS
      }));
    }
  }, [state.user]);

  // Login function (placeholder for actual API integration)
  const login = useCallback(async (email: string, password: string): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true }));

    try {
      // In production, this would call an authentication API
      // For demo purposes, we simulate authentication
      await new Promise(resolve => setTimeout(resolve, 500));

      // Validate inputs
      if (!email || !password) {
        throw new Error('Invalid credentials');
      }

      // Demo user (in production, this comes from API)
      const user: User = {
        id: uuidv4(),
        email: email.toLowerCase(),
        name: email.split('@')[0],
        role: email.includes('admin') ? 'admin' : 'analyst',
        permissions: [],
        sessionId: uuidv4(),
        lastActivity: Date.now(),
        mfaEnabled: false
      };

      // Set role-based permissions
      user.permissions = ROLE_PERMISSIONS[user.role];

      setState(prev => ({
        ...prev,
        user,
        isAuthenticated: true,
        isLoading: false,
        sessionExpiry: Date.now() + SESSION_TIMEOUT_MS
      }));

      emitSecurityEvent({
        type: 'LOGIN',
        userId: user.id,
        metadata: { email: user.email, role: user.role }
      });

    } catch (error) {
      setState(prev => ({ ...prev, isLoading: false }));
      emitSecurityEvent({
        type: 'SUSPICIOUS_ACTIVITY',
        metadata: { reason: 'Failed login attempt', email }
      });
      throw error;
    }
  }, [emitSecurityEvent]);

  // Logout function
  const logout = useCallback(() => {
    const userId = state.user?.id;

    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      sessionExpiry: null,
      csrfToken: uuidv4(), // Generate new CSRF token
      correlationId: uuidv4() // Generate new correlation ID
    });

    emitSecurityEvent({
      type: 'LOGOUT',
      userId,
      metadata: { reason: 'User initiated logout' }
    });

    // Clear any stored session data
    try {
      sessionStorage.removeItem('aegis_session');
    } catch {
      // Ignore storage errors
    }
  }, [state.user, emitSecurityEvent]);

  // Refresh session
  const refreshSession = useCallback(() => {
    if (state.isAuthenticated) {
      setState(prev => ({
        ...prev,
        sessionExpiry: Date.now() + SESSION_TIMEOUT_MS
      }));

      emitSecurityEvent({
        type: 'SESSION_REFRESHED',
        userId: state.user?.id
      });
    }
  }, [state.isAuthenticated, state.user, emitSecurityEvent]);

  // Get CSRF token
  const getCsrfToken = useCallback(() => state.csrfToken, [state.csrfToken]);

  // Get correlation ID
  const getCorrelationId = useCallback(() => state.correlationId, [state.correlationId]);

  // Session timeout check
  useEffect(() => {
    if (!state.isAuthenticated || !state.sessionExpiry) return;

    const checkSession = () => {
      const now = Date.now();
      const timeLeft = state.sessionExpiry! - now;

      if (timeLeft <= 0) {
        // Session expired
        emitSecurityEvent({
          type: 'SESSION_EXPIRED',
          userId: state.user?.id
        });
        logout();
      } else if (timeLeft <= SESSION_WARNING_MS) {
        // Session expiring soon - could show warning
        // For now, we just refresh on activity
      }
    };

    const interval = setInterval(checkSession, ACTIVITY_CHECK_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [state.isAuthenticated, state.sessionExpiry, state.user, logout, emitSecurityEvent]);

  // Activity listener for session refresh
  useEffect(() => {
    if (!state.isAuthenticated) return;

    const handleActivity = () => {
      updateLastActivity();
    };

    // Track user activity
    window.addEventListener('mousemove', handleActivity, { passive: true });
    window.addEventListener('keydown', handleActivity, { passive: true });
    window.addEventListener('click', handleActivity, { passive: true });
    window.addEventListener('scroll', handleActivity, { passive: true });

    return () => {
      window.removeEventListener('mousemove', handleActivity);
      window.removeEventListener('keydown', handleActivity);
      window.removeEventListener('click', handleActivity);
      window.removeEventListener('scroll', handleActivity);
    };
  }, [state.isAuthenticated, updateLastActivity]);

  // Initial load - check for existing session
  useEffect(() => {
    const checkExistingSession = async () => {
      try {
        // In production, validate session token with backend
        const storedSession = sessionStorage.getItem('aegis_session');
        if (storedSession) {
          // Validate and restore session
          // For demo, we just mark as not authenticated
        }
      } catch {
        // Ignore errors
      }
      setState(prev => ({ ...prev, isLoading: false }));
    };

    checkExistingSession();
  }, []);

  const contextValue: SecurityContextType = {
    ...state,
    login,
    logout,
    hasPermission,
    hasRole,
    hasAnyRole,
    refreshSession,
    getCsrfToken,
    getCorrelationId,
    updateLastActivity
  };

  return (
    <SecurityContext.Provider value={contextValue}>
      {children}
    </SecurityContext.Provider>
  );
};

// ==================== HOOKS ====================

export const useSecurity = (): SecurityContextType => {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return context;
};

// Convenience hooks
export const useAuth = () => {
  const { user, isAuthenticated, isLoading, login, logout } = useSecurity();
  return { user, isAuthenticated, isLoading, login, logout };
};

export const usePermissions = () => {
  const { hasPermission, hasRole, hasAnyRole } = useSecurity();
  return { hasPermission, hasRole, hasAnyRole };
};

export const useCsrf = () => {
  const { getCsrfToken } = useSecurity();
  return { csrfToken: getCsrfToken() };
};

// ==================== COMPONENTS ====================

interface ProtectedRouteProps {
  children: ReactNode;
  requiredPermission?: Permission;
  requiredRole?: Role;
  fallback?: ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredPermission,
  requiredRole,
  fallback = null
}) => {
  const { isAuthenticated, isLoading, hasPermission, hasRole } = useSecurity();

  if (isLoading) {
    return <div className="flex items-center justify-center min-h-screen">Loading...</div>;
  }

  if (!isAuthenticated) {
    return <>{fallback}</>;
  }

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return <>{fallback}</>;
  }

  if (requiredRole && !hasRole(requiredRole)) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
};

interface RoleGateProps {
  children: ReactNode;
  allowedRoles: Role[];
  fallback?: ReactNode;
}

export const RoleGate: React.FC<RoleGateProps> = ({ children, allowedRoles, fallback = null }) => {
  const { hasAnyRole } = useSecurity();

  if (!hasAnyRole(allowedRoles)) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
};

export default SecurityContext;

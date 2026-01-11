import AegisApp from './components/AegisApp'
import { SecurityProvider, SecurityEvent } from './contexts/SecurityContext'
import { auditLogger } from './services/AuditLogger'

// Security event handler for audit logging
const handleSecurityEvent = (event: SecurityEvent) => {
  // Map security events to audit logger
  switch (event.type) {
    case 'LOGIN':
      auditLogger.log('AUTH_LOGIN_SUCCESS', 'auth', 'success', event.metadata || {});
      if (event.userId) {
        auditLogger.setUserContext(event.userId, event.metadata?.email as string);
      }
      break;
    case 'LOGOUT':
      auditLogger.log('AUTH_LOGOUT', 'auth', 'success', event.metadata || {});
      auditLogger.clearUserContext();
      break;
    case 'SESSION_EXPIRED':
      auditLogger.log('AUTH_SESSION_EXPIRED', 'auth', 'failure', event.metadata || {});
      auditLogger.clearUserContext();
      break;
    case 'SESSION_REFRESHED':
      auditLogger.log('AUTH_SESSION_REFRESHED', 'auth', 'success', event.metadata || {});
      break;
    case 'PERMISSION_DENIED':
      auditLogger.log('AUTHZ_PERMISSION_DENIED', 'auth', 'failure', event.metadata || {}, { severity: 'high' });
      break;
    case 'CSRF_VALIDATION':
      auditLogger.log('SECURITY_CSRF_VALIDATION_FAILED', 'security', 'failure', event.metadata || {}, { severity: 'high' });
      break;
    case 'SUSPICIOUS_ACTIVITY':
      auditLogger.log('SECURITY_SUSPICIOUS_ACTIVITY', 'security', 'failure', event.metadata || {}, { severity: 'critical' });
      break;
  }
};

function App() {
  return (
    <SecurityProvider onSecurityEvent={handleSecurityEvent}>
      <AegisApp />
    </SecurityProvider>
  )
}

export default App

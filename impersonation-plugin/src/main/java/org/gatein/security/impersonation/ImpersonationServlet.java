package org.gatein.security.impersonation;

import org.exoplatform.container.web.AbstractHttpServlet;
import org.exoplatform.portal.application.PortalRequestContext;
import org.exoplatform.portal.config.UserACL;
import org.exoplatform.portal.webui.util.Util;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.ConversationRegistry;
import org.exoplatform.services.security.ConversationState;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.StateKey;
import org.exoplatform.services.security.web.HttpSessionStateKey;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Enumeration;

/**
 * Servlet, which handles impersonation and impersonalization (de-impersonation) of users
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ImpersonationServlet extends AbstractHttpServlet
{
   public static final String PARAM_ACTION = "_impersonationAction";
   public static final String PARAM_ACTION_START_IMPERSONATION = "startImpersonation";
   public static final String PARAM_ACTION_STOP_IMPERSONATION = "stopImpersonation";

   public static final String PARAM_USERNAME = "_impersonationUsername";

   private static final String BACKUP_ATTR_PREFIX = "_bck.";

   private static final Logger log = LoggerFactory.getLogger(ImpersonationServlet.class);

   @Override
   protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
   {
      String action = req.getParameter(PARAM_ACTION);
      if (action == null)
      {
         log.error("Parameter '" + PARAM_ACTION + "' not provided");
         resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
      }
      else if (PARAM_ACTION_START_IMPERSONATION.equals(action))
      {
         startImpersonation(req, resp);
      }
      else if (PARAM_ACTION_STOP_IMPERSONATION.equals(action))
      {
         stopImpersonation(req, resp);
      }
      else
      {
         log.error("Unknown impersonation action: " + action);
         resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
      }
   }

   protected void startImpersonation(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
   {
      // Obtain username
      String usernameToImpersonate = req.getParameter(PARAM_USERNAME);
      if (usernameToImpersonate == null)
      {
         log.error("Parameter '" + PARAM_USERNAME + "' not provided");
         resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
         return;
      }

      // Find user to impersonate
      OrganizationService orgService = (OrganizationService)getContainer().getComponentInstanceOfType(OrganizationService.class);
      User userToImpersonate;
      try
      {
         userToImpersonate = orgService.getUserHandler().findUserByName(usernameToImpersonate);
      }
      catch (Exception e)
      {
         throw new ServletException(e);
      }

      if (userToImpersonate == null)
      {
         log.error("User '" + usernameToImpersonate + "' not found!");
         resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
         return;
      }

      log.debug("Going to impersonate as user: " + usernameToImpersonate);

      ConversationState currentConversationState = ConversationState.getCurrent();
      Identity currentIdentity = currentConversationState.getIdentity();
      if (currentIdentity instanceof ImpersonatedIdentity)
      {
         log.error("Already impersonated as identity: " + currentIdentity);
         resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
         return;
      }

      if (!checkPermission(currentIdentity, userToImpersonate))
      {
         log.error("Current user represented by identity " + currentIdentity.getUserId() + " doesn't have permission to impersonate as " + userToImpersonate);
         resp.sendError(HttpServletResponse.SC_FORBIDDEN);
         return;
      }

      // Backup and clear current HTTP session
      backupAndClearCurrentSession(req);

      // Real impersonation done here
      boolean success = impersonate(req, currentConversationState, usernameToImpersonate);
      if (success)
      {
         // Redirect to portal for now
         resp.sendRedirect(req.getContextPath());
      }
      else
      {
         resp.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
      }
   }

   protected void stopImpersonation(HttpServletRequest req, HttpServletResponse resp)
   {

   }

   /**
    * Check if current user has permission to impersonate as user 'userToImpersonate'
    *
    * @param currentIdentity Identity of current user
    * @param userToImpersonate user to check
    * @return true if current user has permission to impersonate as user 'userToImpersonate'
    */
   protected boolean checkPermission(Identity currentIdentity, User userToImpersonate)
   {
      UserACL userACL = (UserACL)getContainer().getComponentInstanceOfType(UserACL.class);

      // For now hardcode permission here and allow manager:/platform/administrators to impersonate
      return userACL.hasPermission(currentIdentity, "manager:/platform/administrators");
   }

   /**
    * Backup all session attributes of admin user as we will have new session for "impersonated" user
    *
    * @param req http servlet request
    */
   protected void backupAndClearCurrentSession(HttpServletRequest req)
   {
      HttpSession session = req.getSession(false);
      if (session != null)
      {
         Enumeration attrNames = session.getAttributeNames();
         while (attrNames.hasMoreElements())
         {
            String attrName = (String)attrNames.nextElement();
            Object attrValue = session.getAttribute(attrName);

            // Backup attribute and clear old
            String backupAttrName =  BACKUP_ATTR_PREFIX + attrName;
            session.setAttribute(backupAttrName, attrValue);
            session.removeAttribute(attrName);

            if (log.isTraceEnabled())
            {
               log.trace("Finished backup of attribute: " + attrName);
            }
         }
      }

      // TODO: save URL to redirect after impersonation will be finished
   }

   protected boolean impersonate(HttpServletRequest req, ConversationState currentConvState, String usernameToImpersonate)
   {
      // Create new identity for user, who will be impersonated
      Authenticator authenticator = (Authenticator) getContainer().getComponentInstanceOfType(Authenticator.class);
      Identity newIdentity = null;
      try
      {
         newIdentity = authenticator.createIdentity(usernameToImpersonate);
      }
      catch (Exception e)
      {
         log.error("New identity for user: " + usernameToImpersonate + " not created.\n", e);
         return false;
      }

      ImpersonatedIdentity impersonatedIdentity = new ImpersonatedIdentity(newIdentity, currentConvState);

      // Create new entry to ConversationState
      log.debug("Set ConversationState with current session. Admin user "
            + impersonatedIdentity.getParentConversationState().getIdentity().getUserId()
            + " will use identity of user " + impersonatedIdentity.getUserId());

      ConversationState impersonatedConversationState = new ConversationState(impersonatedIdentity);

      // Obtain stateKey of current HttpSession
      HttpSession httpSession = req.getSession();
      StateKey stateKey = new HttpSessionStateKey(httpSession);

      // Update conversationRegistry with new ImpersonatedIdentity
      ConversationRegistry conversationRegistry = (ConversationRegistry)getContainer().getComponentInstanceOfType(ConversationRegistry.class);
      conversationRegistry.register(stateKey, impersonatedConversationState);

      return true;
   }
}

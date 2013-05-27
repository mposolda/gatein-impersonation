package org.gatein.security.impersonation;

import org.exoplatform.container.web.AbstractHttpServlet;
import org.exoplatform.portal.config.UserACL;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.security.ConversationState;
import org.exoplatform.services.security.Identity;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
         resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
         return;
      }

      // Backup and clear current HTTP session
      backupAndClearCurrentSession(req);

      // Impersonate
      // TODO:
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

   protected void backupAndClearCurrentSession(HttpServletRequest req)
   {
      // TODO:
   }
}

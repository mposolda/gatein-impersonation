/******************************************************************************
 * JBoss, a division of Red Hat                                               *
 * Copyright 2008, Red Hat Middleware, LLC, and individual                    *
 * contributors as indicated by the @authors tag. See the                     *
 * copyright.txt in the distribution for a full listing of                    *
 * individual contributors.                                                   *
 *                                                                            *
 * This is free software; you can redistribute it and/or modify it            *
 * under the terms of the GNU Lesser General Public License as                *
 * published by the Free Software Foundation; either version 2.1 of           *
 * the License, or (at your option) any later version.                        *
 *                                                                            *
 * This software is distributed in the hope that it will be useful,           *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU           *
 * Lesser General Public License for more details.                            *
 *                                                                            *
 * You should have received a copy of the GNU Lesser General Public           *
 * License along with this software; if not, write to the Free                *
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA         *
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.                   *
 ******************************************************************************/
package nl.travelcard.login;

import java.io.IOException;

import javax.portlet.ActionRequest;
import javax.portlet.ActionResponse;
import javax.portlet.GenericPortlet;
import javax.portlet.PortletException;
import javax.portlet.PortletRequestDispatcher;
import javax.portlet.RenderRequest;
import javax.portlet.RenderResponse;
import javax.portlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.portal.webui.util.Util;
import org.exoplatform.portal.application.PortalRequestContext;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.ConversationRegistry;
import org.exoplatform.services.security.ConversationState;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.IdentityRegistry;
import org.exoplatform.services.security.StateKey;
import org.exoplatform.services.security.web.HttpSessionStateKey;
import org.gatein.security.impersonalization.ImpersonalizationState;
import org.gatein.security.impersonalization.ImpersonatedIdentity;
import org.gatein.security.impersonalization.ImpersonatedStateManager;

/**
 *
 * @author ocarr
 *
 */
public class HelpDeskLoginPortlet extends GenericPortlet {

   /** Logger. */
   private static final Log log = ExoLogger.getLogger(HelpDeskLoginPortlet.class);

   public void doView(RenderRequest request, RenderResponse response) throws PortletException, IOException {
      response.setContentType("text/html");
      PortletRequestDispatcher prd = getPortletContext().getRequestDispatcher("/jsp/helpdesklogin.jsp");
      prd.include(request, response);
   }

   public void processAction(ActionRequest request, ActionResponse response)
         throws PortletException, IOException, UnavailableException {

      final String username = (String) request.getParameter("username");
      PortalRequestContext prContext = Util.getPortalRequestContext();

      //LogoutControl.wantLogout();
      createUserLogin(username);

      //
      //prContext.setResponseComplete(true);
      prContext.getResponse().sendRedirect("/portal/classic");
   }

   private void createUserLogin(final String username) {
      ExoContainer container = ExoContainerContext.getContainerByName(PortalContainer.DEFAULT_PORTAL_CONTAINER_NAME);
      if (container == null) {
         log.info("Container " + PortalContainer.DEFAULT_PORTAL_CONTAINER_NAME + " not found.");
         container = ExoContainerContext.getTopContainer();
      }

      ConversationRegistry conversationRegistry =
            (ConversationRegistry)container.getComponentInstanceOfType(ConversationRegistry.class);
      log.info("ConversationRegistry NULL test: " +  (conversationRegistry == null));

      IdentityRegistry identityRegistry = (IdentityRegistry) container.getComponentInstanceOfType(IdentityRegistry.class);
      log.info("IdentityRegistry NULL test: " + (identityRegistry == null));

      Authenticator authenticator = (Authenticator) container.getComponentInstanceOfType(Authenticator.class);
      Identity newIdentity = null;
      try {
         newIdentity = authenticator.createIdentity(username);
      } catch (Exception e) {
         log.error("New identity for user: " + username + " not created.\n" + e);
         return;
      }
      log.info("New ID for user: " + username + " id obj: " + newIdentity);

      Identity currentUserIdentity = ConversationState.getCurrent().getIdentity();
      ImpersonatedIdentity impersonatedIdentity = new ImpersonatedIdentity(newIdentity, currentUserIdentity);

      // Skip registration to IdentityRegistry for now
//      log.info("Add new ID to IdentityRegistry");
//      identityRegistry.register(newIdentity);
//
//      log.info("Finding new identity in registry");
//      Identity testIdentityAdd = identityRegistry.getIdentity(username);
//      log.info("Test new identity found: " + testIdentityAdd);
//      log.info("Test new identity found groups: " + testIdentityAdd.getGroups());
//      log.info("Test new identity found roles: " + testIdentityAdd.getRoles());
//      log.info("Test new identity found memberships: " + testIdentityAdd.getMemberships());

      // Create new entry to ConversationState
      log.info("Set ConversationState with current session. Admin user " + impersonatedIdentity.getParentIdentity().getUserId() + " " +
            "will use identity of user " + impersonatedIdentity.getUserId());
      ConversationState impersonatedConversationState = new ConversationState(impersonatedIdentity);

      // Obtain stateKey of current HttpSession
      HttpServletRequest httpRequest = Util.getPortalRequestContext().getRequest();
      HttpSession httpSession = httpRequest.getSession();
      StateKey stateKey = new HttpSessionStateKey(httpSession);

      // Update conversationRegistry with new ImpersonatedIdentity
      conversationRegistry.register(stateKey, impersonatedConversationState);

      // Add flag to ConversationState that webui state needs to be updated
      httpSession.setAttribute(ImpersonatedStateManager.ATTR_IMPERSONALIZATION_STATE, ImpersonalizationState.IMPERSONALIZATION_STARTED);

//      log.info("Test ConversationState.getCurrent().getIdentity():UserId " + ConversationState.getCurrent().getIdentity().getUserId());
//      log.info("Test ConversationState.getCurrent().getIdentity():Groups " + ConversationState.getCurrent().getIdentity().getGroups());
//      log.info("Test ConversationState.getCurrent().getIdentity():Roles " + ConversationState.getCurrent().getIdentity().getRoles());
//      log.info("Test ConversationState.getCurrent().getIdentity():Memberships " + ConversationState.getCurrent().getIdentity().getMemberships());
   }

}

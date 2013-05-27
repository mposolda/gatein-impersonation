/*
 * JBoss, a division of Red Hat
 * Copyright 2012, Red Hat Middleware, LLC, and individual
 * contributors as indicated by the @authors tag. See the
 * copyright.txt in the distribution for a full listing of
 * individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.gatein.impersonalization;

import java.io.IOException;
import java.util.Collection;

import javax.portlet.ActionRequest;
import javax.portlet.PortletPreferences;
import javax.portlet.RenderRequest;
import javax.portlet.RenderResponse;
import javax.servlet.http.HttpSession;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.portal.application.PortalRequestContext;
import org.exoplatform.portal.webui.util.Util;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.ConversationRegistry;
import org.exoplatform.services.security.ConversationState;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.StateKey;
import org.exoplatform.services.security.web.HttpSessionStateKey;

import org.gatein.security.impersonation.ImpersonationState;
import org.gatein.security.impersonation.ImpersonatedIdentity;
import org.gatein.security.impersonation.ImpersonatedStateManager;


/**
 * User Impersonation Controller for checking user requesting an impersonation action and
 * defining the role for which it is allowed and the URL to redirect to.
 *    
 * @author <a href="mailto:ocarr@redhat.com">Oliver Carr</a>
 *
 */
public class UserImpersonationController
{
    /** Logger. */
    private static final Log log = ExoLogger.getLogger(UserImpersonationController.class);

    /** default role for impersonation. */
    private static final String DEFAULT_IMPERSONATE_ROLE = "administrators";

    /** default redirect URL after user impersonation. */
    private static final String DEFAULT_IMPERSONATE_REDIRECT_URL = "/portal/classic";

    /**
     * Default constructor.
     */
    public UserImpersonationController() 
    {
    }
    
    /**
     * Impersonate User Login, checking current user can impersonate and if so storing the current
     * {@link ConversationState} 
     * 
     * @param request the {@link ActionRequest} to use.
     * 
     * @return boolean True if successful, False otherwise.
     */
    public boolean impersonateUserLogin(ActionRequest request) throws IOException
    {
       final String username = (String) request.getParameter("username");
       Identity currentUserIdentity = ConversationState.getCurrent().getIdentity();
       if (!checkUserAndRole(username, request, currentUserIdentity)) {
          return false;
       }

 	   ExoContainer container = ExoContainerContext.getContainerByName(PortalContainer.DEFAULT_PORTAL_CONTAINER_NAME);
       if (container == null) 
       {
          log.warn("Container " + PortalContainer.DEFAULT_PORTAL_CONTAINER_NAME + " not found.");
          container = ExoContainerContext.getTopContainer();
       }

       Authenticator authenticator = (Authenticator) container.getComponentInstanceOfType(Authenticator.class);
       Identity newIdentity = null;
       try 
       {
          newIdentity = authenticator.createIdentity(username);
       } catch (Exception e) 
       {
          log.error("New identity for user: " + username + " not created.\n" + e);
          return false;
       }
       log.info("New ID for user: " + username + " id obj: " + newIdentity);

       ImpersonatedIdentity impersonatedIdentity = new ImpersonatedIdentity(newIdentity, ConversationState.getCurrent());

       // Create new entry to ConversationState
       log.info("Set ConversationState with current session. Admin user " 
                    + impersonatedIdentity.getParentConversationState().getIdentity().getUserId() 
     		       + " will use identity of user " + impersonatedIdentity.getUserId());
       ConversationState impersonatedConversationState = new ConversationState(impersonatedIdentity);

       // Obtain stateKey of current HttpSession
       PortalRequestContext prContext = Util.getPortalRequestContext();
       HttpSession httpSession = prContext.getRequest().getSession();
       StateKey stateKey = new HttpSessionStateKey(httpSession);

       // Update conversationRegistry with new ImpersonatedIdentity
       ConversationRegistry conversationRegistry =
               (ConversationRegistry)container.getComponentInstanceOfType(ConversationRegistry.class);
       conversationRegistry.register(stateKey, impersonatedConversationState);

       // Add flag to ConversationState that webui state needs to be updated
       httpSession.setAttribute(ImpersonatedStateManager.ATTR_IMPERSONATION_STATE, ImpersonationState.IMPERSONATION_STARTED);

       prContext.getResponse().sendRedirect(request.getPreferences().getValue("impersonateRedirectUrl", DEFAULT_IMPERSONATE_REDIRECT_URL));       
       return true;
    }
    
    /**
     * Create the HTML for the Edit portlet mode using the given {@link RenderRequest} and {@link RenderResponse}
     * 
     * @param request the {@link RenderRequest} to use
     * @param response the {@link RenderResponse} to use
     * 
     * @return {@link String} containing the HTML for the Edit Portlet mode.
     */
    public String getEditViewHTML(RenderRequest request, RenderResponse response) 
    {
        PortletPreferences prefs = request.getPreferences();
        StringBuffer sb = new StringBuffer();
        sb.append("<form method=\"post\" action=\"").append(response.createActionURL()).append("\">");
        sb.append("<table>\n<tr class=\"portlet-section-body\">\n<td>Impersonate URL Redirect</td>");
        sb.append("<td><input type=\"text\" name=\"impersonateRedirectUrl\" value=\"");
        final String redirectUrl = prefs.getValue("impersonateRedirectUrl", DEFAULT_IMPERSONATE_REDIRECT_URL);
        log.info("Redirect URL: " + redirectUrl);
        sb.append(redirectUrl).append("\"/></td>\n</tr>");
        sb.append("<tr class=\"portlet-section-body\">\n<td>Available Roles</td>");

        final String currentImpersonateRole = prefs.getValue("impersonateRole", DEFAULT_IMPERSONATE_ROLE);
        Collection<String> availableRoles = ConversationState.getCurrent().getIdentity().getRoles();
        sb.append("<td><select name=\"impersonateRole\"").append(" id=\"impersonateRoleId\">\n");
        for (String role : availableRoles) 
        {
            sb.append("<option").append(role.equals(currentImpersonateRole) ? " selected" : " ");
            sb.append(" value=\"").append(role).append("\">").append(role).append("</option>\n");
        }
        sb.append("</select>\n</td></tr>\n");

        sb.append("<tr class=\"portlet-section-body\">\n");
        sb.append("<td align=\"right\"><input type=\"submit\" name=\"action\" value=\"Update\"/></td>\n");
        sb.append("<td align=\"left\"><input type=\"submit\" name=\"action\" value=\"Cancel\"/></td>\n</tr>\n");
        
        sb.append("</table>\n</form>\n");
        return sb.toString();
    }
    
    /**
     * Check the given username using the given request and identity.
     * 
     * @param username the username to use
     * @param request the {@link ActionRequest} to use
     * @param request the {@link Identity} to use
     * 
     * @return True if the username given is not null, not equal to current user identity and has the correct role.
     */
    private boolean checkUserAndRole(final String username, ActionRequest request, Identity currentUserIdentity) 
    {
        if (username == null || username == "") 
        {
           log.info("Username for impersonation entered is empty. Impersonation process stopping.");
           return false;
        } 
        else if (currentUserIdentity.getUserId().equals(username)) 
        {
            log.info("User to be impersonated is same as user logged in (" + username + ". Impersonation process stopping.");
        	return false;
        }
        
        final String impersonateRole = request.getPreferences().getValue("impersonateRole", DEFAULT_IMPERSONATE_ROLE);

        if (!currentUserIdentity.getRoles().contains(impersonateRole)) 
        {
        	log.info("Current user: " + currentUserIdentity.getUserId() + " does not have impersonate role: " + impersonateRole);
        	return false;
        }
        return true;
    }

}

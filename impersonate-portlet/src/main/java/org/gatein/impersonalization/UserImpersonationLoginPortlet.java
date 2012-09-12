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

import javax.portlet.ActionRequest;
import javax.portlet.ActionResponse;
import javax.portlet.GenericPortlet;
import javax.portlet.PortletException;
import javax.portlet.PortletMode;
import javax.portlet.PortletPreferences;
import javax.portlet.PortletRequestDispatcher;
import javax.portlet.RenderRequest;
import javax.portlet.RenderResponse;
import javax.portlet.UnavailableException;

import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

/**
 * User Impersonation Login Portlet
 *    - Currently logged in user is provided a form 
 *    - Enters name of user to impersonate and clicks Impersonate
 *    - User is now redirected to given page 
 *    
 * @author <a href="mailto:ocarr@redhat.com">Oliver Carr</a>
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 *
 */
public class UserImpersonationLoginPortlet extends GenericPortlet 
{
   /** Logger. */
   private static final Log log = ExoLogger.getLogger(UserImpersonationLoginPortlet.class);

   /** User Impersonation Workflow. */
   private UserImpersonationController userImpersonationController = new UserImpersonationController();
   
   /**
    * {@inheritDoc}
    */
   public void doEdit(RenderRequest request, RenderResponse response) throws IOException, PortletException 
   {
      response.setContentType("text/html");
      response.setTitle("Edit");
      response.getWriter().print(userImpersonationController.getEditViewHTML(request, response));
   }
   
   /**
    * {@inheritDoc}
    */
   public void doView(RenderRequest request, RenderResponse response) throws PortletException, IOException 
   {
      response.setContentType("text/html");
      PortletRequestDispatcher prd = getPortletContext().getRequestDispatcher("/jsp/userimpersonatelogin.jsp");
      prd.include(request, response);
   }

   /**
    * Process actions for edit and view portlet modes. In view mode it is for impersonating a user and
    * the edit mode is setting the role needed for impersonation and redirect URL.
    * 
    * {@inheritDoc}
    */
   public void processAction(ActionRequest request, ActionResponse response)
         throws PortletException, IOException, UnavailableException 
   {
      PortletPreferences prefs = request.getPreferences();
      final String action = request.getParameter("action");
      if (action.startsWith("Impersontate") && !userImpersonationController.impersonateUserLogin(request))
      {
         response.setPortletMode(PortletMode.VIEW);
         return;
      } else if (action.startsWith("Cancel")) {
         response.setPortletMode(PortletMode.VIEW);
         return;
      } else if (action.startsWith("Update")) {
         final String impersonateRole = request.getParameter("impersonateRole");
         prefs.setValue("impersonateRole", impersonateRole);
         log.info("Updated Impersonate Role: " + impersonateRole);
         final String impersonateRedirectUrl = request.getParameter("impersonateRedirectUrl");         
         prefs.setValue("impersonateRedirectUrl", impersonateRedirectUrl);
         log.info("Updated Impersonate Redirect URL: " + impersonateRedirectUrl);
         prefs.store();
      }
   }
   
}

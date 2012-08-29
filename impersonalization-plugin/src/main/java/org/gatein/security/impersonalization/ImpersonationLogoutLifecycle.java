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

package org.gatein.security.impersonalization;

import org.exoplatform.portal.application.PortalLogoutLifecycle;
import org.exoplatform.portal.application.PortalRequestContext;
import org.exoplatform.web.application.Application;
import org.exoplatform.web.login.LogoutControl;
import org.exoplatform.webui.application.WebuiRequestContext;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


/**
 * Updated version of {@link PortalLogoutLifecycle} which performs some tasks during impersonalization
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:ocarr@redhat.com">Oliver Carr</a>
 */
public class ImpersonationLogoutLifecycle extends PortalLogoutLifecycle
{
   private static final Logger log = LoggerFactory.getLogger(ImpersonationLogoutLifecycle.class);

   public void onEndRequest(Application app, WebuiRequestContext context) throws Exception
   {
      HttpSession currentSession = getSession(context);
      ImpersonalizationState impState = (ImpersonalizationState)currentSession.getAttribute(ImpersonatedStateManager.ATTR_IMPERSONALIZATION_STATE);      
      if (impState == ImpersonalizationState.IMPERSONALIZATION_STARTED)
      {
         log.info("Impersonalization state changed to state " + ImpersonalizationState.IMPERSONALIZATION_START_IN_PROGRESS);
         currentSession.setAttribute(ImpersonatedStateManager.ATTR_IMPERSONALIZATION_STATE, ImpersonalizationState.IMPERSONALIZATION_START_IN_PROGRESS);
      }
      else if (impState == ImpersonalizationState.IMPERSONALIZATION_START_IN_PROGRESS)
      {
         log.info("Impersonalization state changed to state " + ImpersonalizationState.IMPERSONALIZATION_IN_PROGRESS);
         currentSession.setAttribute(ImpersonatedStateManager.ATTR_IMPERSONALIZATION_STATE, ImpersonalizationState.IMPERSONALIZATION_IN_PROGRESS);
      }
      else if (impState == ImpersonalizationState.IMPERSONALIZATION_IN_PROGRESS && LogoutControl.isLogoutRequired())
      {
         LogoutControl.cancelLogout();  // Cancel Logout will handle ourselves.
         log.info("Impersonalization state changed to state " + ImpersonalizationState.IMPERSONALIZATION_FINISHED);
         currentSession.setAttribute(ImpersonatedStateManager.ATTR_IMPERSONALIZATION_STATE, ImpersonalizationState.IMPERSONALIZATION_FINISHED);
      }
     
      super.onEndRequest(app, context);
   }

   private HttpSession getSession(WebuiRequestContext context)
   {
      HttpServletRequest req = ((PortalRequestContext)context).getRequest();
      return req.getSession(false);
   }
}

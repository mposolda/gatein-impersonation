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

package org.gatein.security.impersonation;

import org.exoplatform.portal.application.PortalLogoutLifecycle;
import org.exoplatform.portal.application.PortalRequestContext;
import org.exoplatform.portal.webui.util.Util;
import org.exoplatform.services.security.ConversationState;
import org.exoplatform.services.security.Identity;
import org.exoplatform.web.application.Application;
import org.exoplatform.web.login.LogoutControl;
import org.exoplatform.webui.application.WebuiRequestContext;

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;


/**
 * Updated version of {@link PortalLogoutLifecycle} which performs some tasks during impersonation
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:ocarr@redhat.com">Oliver Carr</a>
 */
public class ImpersonationLogoutLifecycle extends PortalLogoutLifecycle
{
   private static final Logger log = LoggerFactory.getLogger(ImpersonationLogoutLifecycle.class);

   public void onEndRequest(Application app, WebuiRequestContext context) throws Exception
   {
      if (LogoutControl.isLogoutRequired())
      {
         Identity currentIdentity = ConversationState.getCurrent().getIdentity();

         if (currentIdentity instanceof ImpersonatedIdentity)
         {
            PortalRequestContext prContext = Util.getPortalRequestContext();

            // Saved flag to session. It will be processed by CancelImpersonationFilter in next request
            prContext.getRequest().getSession().setAttribute(CancelImpersonationFilter.ATTR_CANCEL_IMPERSONATION, true);

            if (log.isTraceEnabled())
            {
               log.trace("Triggered cancel of impersonation session. Saved flag " + CancelImpersonationFilter.ATTR_CANCEL_IMPERSONATION);
            }
         }
         else
         {
            // If we are not in the middle of impersonation, simply delegate to PortalLogoutLifecycle
            super.onEndRequest(app, context);
         }
      }
   }

}

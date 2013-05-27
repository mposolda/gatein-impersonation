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

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.portal.application.PortalApplication;
import org.exoplatform.portal.application.PortalRequestContext;
import org.exoplatform.portal.application.PortalStateManager;
import org.exoplatform.services.security.ConversationState;
import org.exoplatform.services.security.ConversationRegistry;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.StateKey;
import org.exoplatform.services.security.web.HttpSessionStateKey;
import org.exoplatform.webui.application.WebuiApplication;
import org.exoplatform.webui.application.WebuiRequestContext;
import org.exoplatform.webui.application.portlet.PortletRequestContext;
import org.exoplatform.webui.core.UIApplication;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


/**
 * State manager, which is able to detect impersonation and maintains webui state of impersonator and new (impersonated) user
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:ocarr@redhat.com">Oliver Carr</a>
 */
public class ImpersonatedStateManager extends PortalStateManager
{
   public static final String ATTR_IMPERSONATION_STATE = "ATTR_IMPERSONATION_STATE";

   private static final Logger log = LoggerFactory.getLogger(ImpersonatedStateManager.class);

   @Override
   public void storeUIRootComponent(WebuiRequestContext context) throws Exception
   {
      super.storeUIRootComponent(context);
   }

   @Override
   public void expire(String sessionId, WebuiApplication app)
   {
      // For now do nothing....
   }
   
   @Override
   public UIApplication restoreUIRootComponent(WebuiRequestContext context) throws Exception
   {
      ConversationState convState = ConversationState.getCurrent();
      ImpersonationState impersonationState = (ImpersonationState)getSession(context).getAttribute(ATTR_IMPERSONATION_STATE);
      
      if (impersonationState == null ||
          impersonationState == ImpersonationState.IMPERSONATION_STARTED ||
         impersonationState == ImpersonationState.IMPERSONATION_IN_PROGRESS)
      {
         return super.restoreUIRootComponent(context);
      }
      else if (impersonationState == ImpersonationState.IMPERSONATION_START_IN_PROGRESS)
      {
         backupParentStateAndClearIt(context, convState, impersonationState);
      }
      else if (impersonationState == ImpersonationState.IMPERSONATION_FINISHED)
      {
         restoreParentState(context, convState, impersonationState);
      }

      return super.restoreUIRootComponent(context);
   }

   protected void backupParentStateAndClearIt(WebuiRequestContext context, ConversationState convState, ImpersonationState impersonationState)
   {
      Identity identity = convState.getIdentity();
      if (!(identity instanceof ImpersonatedIdentity))
      {
         throw new IllegalStateException("We are in state " + impersonationState + " but we have invalid identity " + identity);
      }
      ImpersonatedIdentity impersonatedIdentity = (ImpersonatedIdentity)identity;
      log.info("Going to backup current WebUI state of user " + impersonatedIdentity.getParentConversationState().getIdentity().getUserId() 
    		  + ". Creating new state for impersonated user " + impersonatedIdentity.getUserId());
      
      backupOldState(context);  // Now we need to backup old state and clear it
   }

   protected void restoreParentState(WebuiRequestContext context, ConversationState convState, ImpersonationState impersonationState)
   {
      // Obtain stateKey of current HttpSession
      HttpSession httpSession = getSession(context);

      final String keyBackup = getKeyForStateBackup(context);
      Object previousStateObj = httpSession.getAttribute(keyBackup);
      httpSession.setAttribute(getKey(context), previousStateObj);
      httpSession.removeAttribute(keyBackup);

      Identity currentIdentity = ConversationState.getCurrent().getIdentity();
      ImpersonatedIdentity impersonatedIdentity = null;
      if (currentIdentity instanceof ImpersonatedIdentity) 
      {
    	  impersonatedIdentity = (ImpersonatedIdentity) currentIdentity;
      } else 
      {
          throw new IllegalStateException("We are in state " + impersonationState + " but we have invalid identity " + currentIdentity);
      }

      log.info("Restoring WebUI state of user " + impersonatedIdentity.getParentConversationState().getIdentity().getUserId() 
    		  + ". Ending impersonation for user " + impersonatedIdentity.getUserId());
      
      ExoContainer container = ExoContainerContext.getContainerByName(PortalContainer.DEFAULT_PORTAL_CONTAINER_NAME);
      if (container == null) 
      {
         log.warn("Container " + PortalContainer.DEFAULT_PORTAL_CONTAINER_NAME + " not found.");
         container = ExoContainerContext.getTopContainer();
      }
    
      ConversationRegistry conversationRegistry =
           (ConversationRegistry)container.getComponentInstanceOfType(ConversationRegistry.class);

      StateKey stateKey = new HttpSessionStateKey(httpSession);
      conversationRegistry.register(stateKey, impersonatedIdentity.getParentConversationState());
      
      ConversationState.setCurrent(impersonatedIdentity.getParentConversationState());

      httpSession.setAttribute(ImpersonatedStateManager.ATTR_IMPERSONATION_STATE, null);
   }

   // TODO: Change parent method to be protected to avoid this duplication
   protected String getKey(WebuiRequestContext webuiRC)
   {
      if (webuiRC instanceof PortletRequestContext)
      {
         PortletRequestContext portletRC = (PortletRequestContext)webuiRC;
         return portletRC.getApplication().getApplicationId() + "/" + portletRC.getWindowId();
      }
      else
      {
         return PortalApplication.PORTAL_APPLICATION_ID;
      }
   }

   protected String getKeyForStateBackup(WebuiRequestContext webuiRC)
   {
      return getKey(webuiRC) + ".backup";
   }

   // TODO: Change parent method to be protected to avoid this duplication
   protected HttpSession getSession(WebuiRequestContext webuiRC)
   {
      PortalRequestContext portalRC;
      if (webuiRC instanceof PortletRequestContext)
      {
         PortletRequestContext portletRC = (PortletRequestContext)webuiRC;
         portalRC = (PortalRequestContext) portletRC.getParentAppRequestContext();
      }
      else
      {
         portalRC = (PortalRequestContext)webuiRC;
      }
      HttpServletRequest req = portalRC.getRequest();
      return req.getSession(false);
   }

   private void backupOldState(WebuiRequestContext context)
   {
      final String keyBackup = getKeyForStateBackup(context);

      HttpSession session = getSession(context);

      // Now we need to backup old state and clear it
      final String key = getKey(context);
      Object currentState = session.getAttribute(key);
      session.setAttribute(keyBackup, currentState);
      session.removeAttribute(key);
   }

}

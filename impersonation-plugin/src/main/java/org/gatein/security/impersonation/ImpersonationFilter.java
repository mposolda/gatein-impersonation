package org.gatein.security.impersonation;

import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.services.security.ConversationState;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.jaas.UserPrincipal;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.security.Principal;
import java.util.Collection;

/**
 * Filter to wrap real {@link HttpServletRequest} into wrapper, which will be treated as request of impersonated user
 *
 * It should be in filter chain after {@link org.exoplatform.services.security.web.SetCurrentIdentityFilter}
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ImpersonationFilter extends AbstractFilter
{
   private static final Logger log = LoggerFactory.getLogger(ImpersonationFilter.class);

   @Override
   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
   {
      HttpServletRequest httpRequest = (HttpServletRequest)request;

      Identity currentIdentity = ConversationState.getCurrent().getIdentity();
      if (currentIdentity instanceof ImpersonatedIdentity)
      {
         ImpersonatedIdentity impersonatedIdentity = (ImpersonatedIdentity)currentIdentity;

         String remoteUser = httpRequest.getRemoteUser();
         String impersonatedUser = impersonatedIdentity.getUserId();
         String parentImpersonatedUser = impersonatedIdentity.getParentConversationState().getIdentity().getUserId();

         // Skip impersonation if impersonatedUser is same as remoteUser. This could theoretically happen during http request re-entrance
         if (remoteUser.equals(impersonatedUser))
         {
            if (log.isTraceEnabled())
            {
               log.trace("Reentrance detected. Impersonation will be skipped. User: " + remoteUser +
                     ", parentImpersonatedUser: " + parentImpersonatedUser + ", impersonatedUser: " + impersonatedUser);
            }
         }
         else
         {
            if (log.isTraceEnabled())
            {
               log.trace("Impersonating current HttpServletRequest. User: " + remoteUser +
                     ", parentImpersonatedUser: " + parentImpersonatedUser + ", impersonatedUser: " + impersonatedUser);
            }

            // Impersonate current http request
            httpRequest = new ImpersonatedHttpServletRequestWrapper(httpRequest, impersonatedIdentity);
         }
      }

      // Continue with request in all cases
      chain.doFilter(httpRequest, response);
   }

   @Override
   public void destroy()
   {
   }

   public static class ImpersonatedHttpServletRequestWrapper extends HttpServletRequestWrapper
   {
      private final ImpersonatedIdentity identity;

      public ImpersonatedHttpServletRequestWrapper(HttpServletRequest request, ImpersonatedIdentity identity)
      {
         super(request);
         this.identity = identity;
      }

      @Override
      public String getRemoteUser()
      {
         return this.identity.getUserId();
      }

      @Override
      public boolean isUserInRole(String role)
      {
         Collection<String> roles = this.identity.getRoles();
         return roles.contains(role);
      }

      @Override
      public Principal getUserPrincipal()
      {
         return new UserPrincipal(this.identity.getUserId());
      }
   }
}

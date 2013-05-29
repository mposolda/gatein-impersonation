GateIn Impersonation
--------------------

This feature is useful for administrator, so he has possibility to login as different user. It might be useful for example
to check privileges or verify content of dashboard of particular user (For example user "root" wants to check if "mary"
really can't see page "xy", which should be visible only by administrators).

To setup impersonation with GateIn 3.6.0.Beta01 (assumption is that you have GateIn on JBoss AS7) you will need to:

1) Clone latest stuff from https://github.com/mposolda/gatein-impersonation and build it with "mvn clean install"


2) Copy and setup plugin into GateIn libraries

2.a) Copy file impersonation-plugin/target/impersonation-plugin.jar to GATEIN_HOME/modules/org/gatein/lib/main/

2.b) Edit file GATEIN_HOME/modules/org/gatein/lib/main/module.xml and add following line resources section like:

 <resource-root path="impersonation-plugin.jar"/>


3) Deploy impersonate-portlet. Copy file impersonate-portlet/target/impersonate-portlet.war into GATEIN_HOME/standalone/deployments/


4) Setup web.xml. In file GATEIN_HOME/gatein/gatein.ear/portal.war/WEB-INF/web.xml you need to:

4.a) Add those 2 filters in section with filters:

  <filter>
    <filter-name>ImpersonationFilter</filter-name>
    <filter-class>org.gatein.web.security.impersonation.ImpersonationFilter</filter-class>
  </filter>
  <filter>
    <filter-name>CancelImpersonationFilter</filter-name>
    <filter-class>org.gatein.web.security.impersonation.CancelImpersonationFilter</filter-class>
  </filter>

4.b) Add those 2 filters in section with filter-mapping.
IMPORTANT: You need to add them *after* filter-mapping of SetCurrentIdentityFilter!!!

  <filter-mapping>
    <filter-name>CancelImpersonationFilter</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
  <filter-mapping>
    <filter-name>ImpersonationFilter</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>

4.c) Add this servlet into servlet section:

  <servlet>
    <servlet-name>ImpersonationServlet</servlet-name>
    <servlet-class>org.gatein.web.security.impersonation.ImpersonationServlet</servlet-class>
  </servlet>

4.d) Add this servlet-mapping into section with servlet mapping

  <servlet-mapping>
    <servlet-name>ImpersonationServlet</servlet-name>
    <url-pattern>/impersonate</url-pattern>
  </servlet-mapping>


5) Setup lifecycle. In file GATEIN_HOME/gatein/gatein.ear/portal.war/WEB-INF/webui-configuration.xml you need to comment/delete
PortalLogoutLifecycle and add ImpersonationLogoutLifecycle instead of it:

  <!--<listener>org.exoplatform.portal.application.PortalLogoutLifecycle</listener>-->
  <listener>org.gatein.web.security.impersonation.ImpersonationLogoutLifecycle</listener>

6) Execute portal and add impersonate-portlet to some page via GateIn UI.

Then you can login as root (For now only users with membership "manager:/platform/administrators" have privilege to impersonate).
Then in portlet you can fill some name of user to impersonate (for example "mary"). After that you will be impersonated
as user "mary" and GateIn UI will treat you as mary. Once you click "SignOut" you won't be really signed-out, but you
will be de-impersonalized back in GateIn as user root.

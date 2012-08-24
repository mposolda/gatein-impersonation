<%@ taglib uri="http://java.sun.com/portlet_2_0" prefix="portlet" %>

<div class="portlet-section-header">Welcome !</div>

<br/>

<div class="portlet-font">Helpdesk User Login Form<br/>

	<portlet:actionURL var="loginActionURL"/>
	<form action="<%= loginActionURL %>" method="POST">
         <span class="portlet-form-field-label">User name:</span>
         <input class="portlet-form-input-field" type="text" name="username"/>
         <input class="portlet-form-button" type="Submit" name="Login"/>
	</form>

</div>

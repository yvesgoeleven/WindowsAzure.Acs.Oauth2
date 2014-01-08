using System;
using System.Net;
using System.Web.Mvc;
using Newtonsoft.Json;

namespace WindowsAzure.Acs.Oauth2
{
    internal class EnsureOAuthMessageInterceptedAttribute
        : AuthorizeAttribute
    {
        public EnsureOAuthMessageInterceptedAttribute()
        {
            Order = -1;
        }

        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            try
            {
                var authorizationServer = filterContext.Controller as AuthorizationServerBase;
                if (authorizationServer != null)
                {
                    authorizationServer.StoreIncomingRequest(filterContext.HttpContext);
                }
            }
            catch (Exception ex)
            {
                var twolegged = filterContext.Controller as TwoLeggedAuthorizationServer;

                if (twolegged != null)
                {
                    filterContext.HttpContext.Items["SuppressRedirect"] = HttpStatusCode.InternalServerError;
                    filterContext.HttpContext.Items["SuppressRedirect.Result"] = JsonConvert.SerializeObject(new {message = ex.Message});
                }

                throw;
            }
            
        }
    }
}
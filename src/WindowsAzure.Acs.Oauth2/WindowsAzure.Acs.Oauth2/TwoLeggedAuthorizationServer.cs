using System;
using System.Configuration;
using System.IO;
using System.Net;
using System.Security.Authentication;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using WindowsAzure.Acs.Oauth2.Protocol;
using Newtonsoft.Json;

namespace WindowsAzure.Acs.Oauth2
{
    /// <summary>
    /// Two legged AuthorizationServer class.
    /// </summary>
    public class TwoLeggedAuthorizationServer : AuthorizationServerBase
    {
        private Uri AccessTokenUri;

        /// <summary>
        /// Initializes a new instance of the <see cref="TwoLeggedAuthorizationServer"/> class.
        /// The parameters are read from the application configuration's appSettings keys 'WindowsAzure.OAuth.ServiceNamespace', 'WindowsAzure.OAuth.ServiceNamespaceManagementUserName', 'WindowsAzure.OAuth.ServiceNamespaceManagementUserKey' and 'WindowsAzure.OAuth.RelyingPartyName'.
        /// </summary>
        public TwoLeggedAuthorizationServer()
            : this(ConfigurationManager.AppSettings["WindowsAzure.OAuth.RelyingPartyName"], new Uri(string.Format("https://{0}.accesscontrol.windows.net/v2/OAuth2-13/", ConfigurationManager.AppSettings["WindowsAzure.OAuth.ServiceNamespace"])), new ApplicationRegistrationService())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TwoLeggedAuthorizationServer"/> class.
        /// The relying party name is read from the application configuration's appSettings key 'WindowsAzure.OAuth.RelyingPartyName'.
        /// </summary>
        /// <param name="applicationRegistrationService">The application registration service.</param>
        public TwoLeggedAuthorizationServer(IApplicationRegistrationService applicationRegistrationService)
            : this(ConfigurationManager.AppSettings["WindowsAzure.OAuth.RelyingPartyName"], new Uri(string.Format("https://{0}.accesscontrol.windows.net/v2/OAuth2-13/", ConfigurationManager.AppSettings["WindowsAzure.OAuth.ServiceNamespace"])), applicationRegistrationService)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TwoLeggedAuthorizationServer"/> class.
        /// </summary>
        /// <param name="relyingPartyName">The relying party name.</param>
        public TwoLeggedAuthorizationServer(string relyingPartyName, Uri accessTokenUri, IApplicationRegistrationService applicationRegistrationService)
        {
            AccessTokenUri = accessTokenUri;
            RelyingPartyName = relyingPartyName;
            ApplicationRegistrationService = applicationRegistrationService;
        }

        /// <summary>
        /// Gets the delegated identity. Override this if you require specifying the IdentityProvider for the delegated identity.
        /// </summary>
        /// <returns>An <see cref="AuthorizationServerIdentity"/>.</returns>
        protected override AuthorizationServerIdentity GetDelegatedIdentity()
        {
            var message = TempData[OauthMessageKey] as OAuthMessage;
            if (message != null &&
                message.Parameters[OAuthConstants.GrantType] == OAuthConstants.AccessGrantType.ClientCredentials)
            {
                return new AuthorizationServerIdentity()
                    {
                        NameIdentifier = message.Parameters[OAuthConstants.ClientId],
                        IdentityProvider = ""
                    };
            }
            
            return null;
        }

        /// <summary>
        /// Index action method.
        /// </summary>
        /// <param name="model">The AuthorizationServerViewModel model.</param>
        /// <returns>A <see cref="RedirectResult"/>.</returns>
        [HttpPost, ActionName("Index")]
        public virtual ActionResult Index_Post(AuthorizationServerViewModel model)
        {
            var message = StoreIncomingRequest(HttpContext);

            if (message != null && (
                message.Parameters[OAuthConstants.GrantType] == OAuthConstants.AccessGrantType.ClientCredentials
                || message.Parameters[OAuthConstants.GrantType] == OAuthConstants.AccessGrantType.RefreshToken))
            {
                var clientId = message.Parameters[OAuthConstants.ClientId];
                var secret = message.Parameters[OAuthConstants.ClientSecret];
                var scope = message.Parameters[OAuthConstants.Scope];
                var grantType = message.Parameters[OAuthConstants.GrantType];
                
                string token = null;

                if (grantType == OAuthConstants.AccessGrantType.ClientCredentials)
                {
                    try
                    {
                        token = ApplicationRegistrationService.GetAuthorizationCode(clientId, GetDelegatedIdentity(), scope);
                    }
                    catch (OAuthMessageException ex)
                    {
                        //this doesn't work mvc still replaces everything with 302
                        //HttpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        //HttpContext.Response.SuppressFormsAuthenticationRedirect = true;
                        HttpContext.Items["SuppressRedirect"] = HttpStatusCode.Unauthorized;
                        HttpContext.Items["SuppressRedirect.Result"] = JsonConvert.SerializeObject(new { message = ex.Message });
                        return null;
                    }
                    catch (Exception ex)
                    {
                        HttpContext.Items["SuppressRedirect"] = HttpStatusCode.InternalServerError;
                        HttpContext.Items["SuppressRedirect.Result"] = JsonConvert.SerializeObject(new { message = ex.Message });
                        return null;
                    }
                    if (token == null)
                    {
                        HttpContext.Items["SuppressRedirect"] = HttpStatusCode.Unauthorized;
                        HttpContext.Items["SuppressRedirect.Result"] = JsonConvert.SerializeObject(new { message = "Error generating authorization code, ensure that a valid client_id, client_code and scope has been specified." });
                        return null;
                    }
                }

                 if (grantType == OAuthConstants.AccessGrantType.RefreshToken)
                    token = message.Parameters[OAuthConstants.RefreshToken];
                
                try
                {
                    var response = AuthorizeWithACS(grantType, token, clientId, secret, scope);

                    return Json(new
                    {
                        token_type = response.TokenType,
                        access_token = response.AccessToken,
                        scope = response.Scope,
                        expires_in = response.ExpiresIn,
                        refresh_token = response.RefreshToken
                    });
                }
                catch (AuthenticationException ex)
                {
                    HttpContext.Items["SuppressRedirect"] = HttpStatusCode.Forbidden;
                    HttpContext.Items["SuppressRedirect.Result"] = JsonConvert.SerializeObject(new { message = ex.Message });
                    return null;
                }
                catch (Exception ex)
                {
                    HttpContext.Items["SuppressRedirect"] = HttpStatusCode.InternalServerError;
                    HttpContext.Items["SuppressRedirect.Result"] = JsonConvert.SerializeObject(new { message = ex.Message });
                    return null;
                }
                
            }
            else
            {
                HttpContext.Items["SuppressRedirect"] = HttpStatusCode.Unauthorized;
                HttpContext.Items["SuppressRedirect.Result"] = JsonConvert.SerializeObject(new { message = "The provided grant type is not supported by this endpoint" });
                return null;
            }
        }

        private AccessTokenResponse AuthorizeWithACS(string grantType, string code, string clientId, string secret, string scope)
        {
            var authorizeRequest = BuildAccessTokenRequest(grantType, code, clientId, secret, scope);

            var serializer = new OAuthMessageSerializer();
            var encodedQueryFormat = serializer.GetFormEncodedQueryFormat(authorizeRequest);

            var httpWebRequest = WebRequest.Create(authorizeRequest.BaseUri);
            httpWebRequest.Method = "POST";
            httpWebRequest.ContentType = "application/x-www-form-urlencoded";
            var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream());
            streamWriter.Write(encodedQueryFormat);
            streamWriter.Close();

            try
            {
                return serializer.Read((HttpWebResponse)httpWebRequest.GetResponse()) as AccessTokenResponse;
            }
            catch (WebException webex)
            {
                var message = serializer.Read((HttpWebResponse)webex.Response);

                var endUserAuthorizationFailedResponse = message as EndUserAuthorizationFailedResponse;
                if (endUserAuthorizationFailedResponse != null)
                {
                    throw new AuthenticationException(endUserAuthorizationFailedResponse.ErrorDescription);
                }

                var userAuthorizationFailedResponse = message as ResourceAccessFailureResponse;
                if (userAuthorizationFailedResponse != null)
                {
                    throw new AuthenticationException(userAuthorizationFailedResponse.ErrorDescription);
                }

                throw;
            }
        }

        private AccessTokenRequest BuildAccessTokenRequest(string grantType, string code, string clientId, string secret, string scope)
        {
            if (grantType == OAuthConstants.AccessGrantType.ClientCredentials)
            {
                return new AccessTokenRequestWithAuthorizationCode(AccessTokenUri)
                {
                    ClientId = clientId,
                    ClientSecret = secret,
                    Scope = scope,
                    GrantType = OAuthConstants.AccessGrantType.AuthorizationCode,
                    Code = code,
                    RedirectUri = new Uri("http://" + clientId)
                };
            }
            if (grantType == OAuthConstants.AccessGrantType.RefreshToken)
            {
                return new AccessTokenRequestWithRefreshToken(AccessTokenUri)
                {
                    ClientId = clientId,
                    ClientSecret = secret,
                    Scope = scope,
                    GrantType = OAuthConstants.AccessGrantType.RefreshToken,
                    RefreshToken = code,
                    RedirectUri = new Uri("http://" + clientId)
                };
            }
            return null;
        }
    }
}
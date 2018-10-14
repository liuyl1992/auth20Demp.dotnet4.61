using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace auth20Demp.App_Start
{
    /// <summary>
    /// 过滤器方式授权
    /// 过滤器方式和委托方式只能保留一种
    /// </summary>
    public class AuthorizationFilter : AuthorizationFilterAttribute
    {
        public override void OnAuthorization(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            try
            {
                if (actionContext.Request.Headers.Authorization == null)
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                }
                else
                {
                    string token;
                    if (!TryRetrieveToken(actionContext.Request, out token))
                    {
                        actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                    }
                    else
                    {
                        try
                        {
                            const string sec = "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1";
                            var now = DateTime.UtcNow;
                            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(sec));


                            SecurityToken securityToken;
                            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                            TokenValidationParameters validationParameters = new TokenValidationParameters()
                            {
                                ValidAudience = "http://localhost:50066/",
                                ValidIssuer = "http://localhost:50066/",
                                ValidateLifetime = true,
                                ValidateIssuerSigningKey = true,
                                LifetimeValidator = this.LifetimeValidator,
                                IssuerSigningKey = securityKey
                            };
                            Thread.CurrentPrincipal = handler.ValidateToken(token, validationParameters, out securityToken);
                            HttpContext.Current.User = handler.ValidateToken(token, validationParameters, out securityToken);

                        }
                        catch (SecurityTokenValidationException e)
                        {
                            actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                        }
                        catch (Exception ex)
                        {
                            actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.InternalServerError);
                        }
                        base.OnAuthorization(actionContext);
                    }

                }
            }
            catch (Exception e)
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
            }
        }

        /// <summary>
        /// 提取token
        /// </summary>
        /// <param name="request"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        private static bool TryRetrieveToken(HttpRequestMessage request, out string token)
        {
            token = null;
            IEnumerable<string> authzHeaders;
            if (!request.Headers.TryGetValues("Authorization", out authzHeaders) || authzHeaders.Count() > 1)
            {
                return false;
            }
            var bearerToken = authzHeaders.ElementAt(0);
            token = bearerToken.StartsWith("Bearer ") ? bearerToken.Substring(7) : bearerToken;
            return true;
        }

        public bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (expires != null)
            {
                if (DateTime.UtcNow < expires) return true;
            }
            return false;
        }
    }
}
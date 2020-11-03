using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Auth.Fast.Core
{
    public class AuthHandler : AuthorizationHandler<AuthRequirement>
    {
        public IAuthenticationSchemeProvider _schemes;
        SecretKeyHelper _secretKey;
        IHttpContextAccessor _httpContext;
        IConfiguration _config;
        public AuthHandler(SecretKeyHelper secretKey, IAuthenticationSchemeProvider schemes, IHttpContextAccessor httpContext, IConfiguration config)
        {
            _secretKey = secretKey;
            _schemes = schemes;
            _httpContext = httpContext;
            _config = config;
        }

        /// <summary>
        /// 认证
        /// </summary>
        /// <param name="context"></param>
        /// <param name="requirement"></param>
        /// <returns></returns>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AuthRequirement requirement)
        {

            //从AuthorizationHandlerContext转成HttpContext，以便取出表求信息
            //AuthorizationFilterContext filterContext = context.Resource as AuthorizationFilterContext;
            //HttpContext httpContext = filterContext.HttpContext;
            HttpContext httpContext = _httpContext.HttpContext;
            //var name = await _schemes.GetDefaultAuthenticateSchemeAsync();
            //AuthenticateResult result = await httpContext.AuthenticateAsync(name.Name);
            string _ticket = _config.GetSection("Auth").GetValue<string>("Ticket") ?? "naUAk2KXMfzK5JEN";
            var auth = httpContext.Request.Headers.FirstOrDefault(p => p.Key == "Authorization");
            if (auth.Key != null && !string.IsNullOrEmpty(auth.Value))
            {
                var token = auth.Value.ToString().Replace("Auth ", "").Replace(" ", "").Replace("\r\n", "");
                string key = _secretKey.DecryptByPublicKey(_ticket, token);
                if (key.Trim().Equals(_ticket))
                    context.Succeed(requirement);
                else
                    context.Fail();
            }
            else
                context.Fail();
            return Task.CompletedTask;
        }
    }

    public class AuthRequirement : IAuthorizationRequirement
    {

    }
}

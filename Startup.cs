using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Auth.Fast.Core;
using IdentityModel;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Fast
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
                .AddJwtBearer(option =>//Jwt Token
                {
                    option.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters()
                    {
                         NameClaimType= JwtClaimTypes.Name,
                         RoleClaimType=JwtClaimTypes.Role,
                          
                         ValidIssuer="http://localhost:5000",
                         ValidAudience="api",
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration.GetSection("").GetValue<string>(""))),

                        /***********************************TokenValidationParameters�Ĳ���Ĭ��ֵ***********************************/
                        // RequireSignedTokens = true,
                        // SaveSigninToken = false,
                        // ValidateActor = false,
                        // ������������������Ϊfalse�����Բ���֤Issuer��Audience�����ǲ�������������
                        // ValidateAudience = true,
                        // ValidateIssuer = true, 
                        // ValidateIssuerSigningKey = false,
                        // �Ƿ�Ҫ��Token��Claims�б������Expires
                        // RequireExpirationTime = true,
                        // ����ķ�����ʱ��ƫ����
                        // ClockSkew = TimeSpan.FromSeconds(300),
                        // �Ƿ���֤Token��Ч�ڣ�ʹ�õ�ǰʱ����Token��Claims�е�NotBefore��Expires�Ա�
                        // ValidateLifetime = true
                    };
                });
              //.AddIdentityServerAuthentication(options =>
              //{
              //    options.Authority = "api1";
              //    options.ApiName = "OpenApi";
              //    options.ApiSecret = "native_api_secret";
              //    options.RequireHttpsMetadata = true;
                  
              //});

            //HttpContextAccessor
            services.AddScoped<SecretKeyHelper>();
            services.AddHttpContextAccessor();
            services.AddAuthorization(option =>
            {
                option.AddPolicy("Auth", policy => policy.Requirements.Add(new AuthRequirement()));
            });
            services.AddTransient<IAuthorizationHandler, AuthHandler>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseAuthorization();

            app.UseAuthentication();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

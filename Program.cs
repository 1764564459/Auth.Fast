using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Auth.Fast.Core;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Auth.Fast
{
    public class Program
    {
        public static void Main(string[] args)
        {
            SecretKeyHelper secret = new SecretKeyHelper();
            var key = secret.GetKey();
            var p = secret.EncryptByPrivateKey("naUAk2KXMfzK5JEN", key.PrivateKey);
            var d = secret.DecryptByPublicKey(p, "MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCg6YUB4EuUyVQ3IokQBHOiLKrah9Jo1A57TbU1DDnCcqiBa7ziC+NP2GZEjssrAnhQfVuMstICH1QlMS3CH07gSD5e+AtAyzaBEP1gbGqO7mtHQ0fs+rxwNN8Z+cAUeoItjd6FNBidJKKTIHG5Leo69+UGLnfCAg97e/qyQ+m9twIBAw==");
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Auth.Fast.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        [HttpPost]
        public IActionResult Receive([FromBody]Temp data)
        {
            Console.WriteLine(JsonConvert.SerializeObject(data)); 
            return Ok();
        }


        
    }

    public class Temp
    {
        public string number { get; set; }

        public DateTime costdate { get; set; }

        public decimal? unitquantity { get; set; }

        public decimal? amount { get; set; }

        public string pwrno { get; set; }

    }
}

using System;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Configuration;
using HashingProject.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using Microsoft.Extensions.Primitives;

namespace HashingProject.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        //использование кортежа
        //static (string, string) ParseHashValue(string eventSignature)
        //{
        //    //var lastSignature = eventSignature.Split(",").LastOrDefault().Replace(" ", string.Empty);
        //    var parcedEvenSignature = eventSignature.Split("/SHA256/");
        //    var keyId = parcedEvenSignature.FirstOrDefault();
        //    //var keyId = parcedEvenSignature[0];
        //    var signature = parcedEvenSignature.LastOrDefault();
        //    //return lastSignature.Split("/SHA256/").LastOrDefault();
        //    return (keyId, signature);
        //}
        static string ParseHashValue(string eventSignature)
        {
            var lastSignature = eventSignature.Replace(" ", string.Empty);
            return lastSignature.Split("/SHA256/").LastOrDefault();
        }

        public string GetSignatureById(string eventSignatures)
        {
            var configKeyId = ConfigurationManager.AppSettings.Get("keyId");
            var signature = eventSignatures.Split(",").Where(x => x.Split("/")[0] == configKeyId).FirstOrDefault();
            return ParseHashValue(signature);
        }

        [HttpPost("/api")]
        public IActionResult IsHashConfirm([FromBody] RequestModel request)
        {
            Request.Headers.TryGetValue("Event-Signature", out StringValues values);
            var signature = GetSignatureById(values);
            var secretKey = ConfigurationManager.AppSettings.Get("secretKey");
            string s;

            var serializeModel = JsonConvert.SerializeObject(request);

            using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
            {
                byte[] computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(serializeModel));
                s = BitConverter.ToString(computedHash).Replace("-", string.Empty).ToLowerInvariant();
            }

            if (s == signature)
            {
                return StatusCode(200);
            }
            else
            {
                return StatusCode(400);
            }
        }

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}

using HashingProject.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HashingProject.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        static string ParseHashValue(string eventSignature)
        {
            var lastSignature = eventSignature.Split(",").LastOrDefault().Replace(" ", string.Empty);
            return lastSignature.Split("/SHA256/").LastOrDefault();
        }

        [HttpPost("/api")]
        public IActionResult IsHashConfirm([FromBody] RequestModel request)
        {
            var message = request.Message;
            Request.Headers.TryGetValue("Event-Signature", out StringValues values);
            var signature = ParseHashValue(values.LastOrDefault());
            var secretKey = ConfigurationManager.AppSettings.Get("secretKey");
            string s;

            using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
            {
                byte[] computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
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

using Newtonsoft.Json;

namespace HashingProject.Models
{
    public class RequestModel
    {
        [JsonProperty("message")]
        public string Message { get; set; }
    }
}

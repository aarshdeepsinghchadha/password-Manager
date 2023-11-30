namespace PasswordManager.Common
{
    public class ReturnResponse
    {
        public bool Status { get; set; }
        public int StatusCode { get; set; }
        public string? Message { get; set; }
    }
    public class ReturnResponse<T> : ReturnResponse
    {
        public T? Data { get; set; }
    }
}

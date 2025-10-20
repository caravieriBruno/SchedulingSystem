namespace Auth.API.Models;

public class AuthResponseDto
{
    public string UserId { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public string Token { get; set; }
}
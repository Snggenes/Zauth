using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Zauth_net.Data;
using Zauth_net.Dtos;
using Zauth_net.Models;
using Zauth_net.Services;

using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2;

namespace Zauth_net.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class Client : ControllerBase
    {
        private readonly AppDbContext _dbContext;
        private readonly EmailService _emailService;
        private readonly TokenService _tokenService;
        private readonly IConfiguration _configuration;
        private readonly GoogleOAuthService _googleOAuthService;

        public Client(AppDbContext dbContext, EmailService emailService, TokenService tokenService, IConfiguration configuration, GoogleOAuthService googleOAuthService)
        {
            _dbContext = dbContext;
            _emailService = emailService;
            _tokenService = tokenService;
            _configuration = configuration;
            _googleOAuthService = googleOAuthService;
        }

        [HttpGet("google")]
        public IActionResult GoogleLogin()
        {
            var googleAuthUrl = _googleOAuthService.GetGoogleAuthUrl();
            return Redirect(googleAuthUrl);
        }



        [HttpGet("google/callback")]
        public async Task<IActionResult> GoogleCallback([FromQuery] string code)
        {
            try
            {
                if(string.IsNullOrEmpty(code))
                {
                    return BadRequest(new { message = "Code is missing" });
                }
                var googleClientId = _configuration["Google:ClientId"];
                if(string.IsNullOrEmpty(googleClientId))
                {
                    return BadRequest(new { message = "Google client id is missing" });
                }
                var googleClientSecret = _configuration["Google:ClientSecret"];
                if(string.IsNullOrEmpty(googleClientSecret))
                {
                    return BadRequest(new { message = "Google client secret is missing" });
                }
                var redirectUri = $"{_configuration["AppSettings:BackendBaseUrl"]}/api/client/google/callback";
                if(string.IsNullOrEmpty(redirectUri))
                {
                    return BadRequest(new { message = "Redirect uri is missing" });
                }

                var flow = new GoogleAuthorizationCodeFlow(new GoogleAuthorizationCodeFlow.Initializer
                {
                    ClientSecrets = new ClientSecrets
                    {
                        ClientId = googleClientId,
                        ClientSecret = googleClientSecret
                    },
                    Scopes = new[] { "profile", "email" }
                });
                

                var token = await flow.ExchangeCodeForTokenAsync("", code, redirectUri, CancellationToken.None);

                if (token == null || string.IsNullOrEmpty(token.IdToken))
                {
                    return BadRequest(new { message = "Failed to exchange code for token" });
                }

                var payload = await _googleOAuthService.VerifyGoogleIdToken(token.IdToken);
                if (payload == null || string.IsNullOrEmpty(payload.Email))
                {
                    return BadRequest(new { message = "Failed to verify user. Payload is null." });
                }

                var email = payload.Email;

                var existingClient = await _dbContext.Clients.FirstOrDefaultAsync(c => c.Email == email);
                if(existingClient == null)
                {
                    var newClient = new Models.Client
                    {
                        ClientId = Guid.NewGuid(),
                        FirstName = payload.GivenName,
                        LastName = payload.FamilyName,
                        Email = email,
                        IsEmailVerified = true
                    };

                    await _dbContext.Clients.AddAsync(newClient);
                    await _dbContext.SaveChangesAsync();

                    var accessToken = _tokenService.GenerateAccessToken(newClient.ClientId.ToString());
                    var refreshToken = _tokenService.GenerateRefreshToken();

                    var newRefreshToken = new RefreshTokenClient
                    {
                        RefreshTokenClientId = Guid.NewGuid(),
                        Token = refreshToken,
                        ExpiresAt = DateTime.UtcNow.AddDays(7),
                        CreatedByIp = HttpContext.Connection.RemoteIpAddress.ToString(),
                        ClientId = newClient.ClientId
                    };

                    await _dbContext.RefreshTokenClients.AddAsync(newRefreshToken);
                    await _dbContext.SaveChangesAsync();

                    Response.Cookies.Append("srt", refreshToken, new CookieOptions
                    {
                        HttpOnly = true,
                        MaxAge = TimeSpan.FromDays(7),
                    });

                    Response.Cookies.Append("sat", accessToken, new CookieOptions
                    {
                        HttpOnly = true,
                        MaxAge = TimeSpan.FromMinutes(15),
                    });

                    return Redirect(_configuration["AppSettings:FrontendBaseUrl"]);
                }

                var accessTokenExisting = _tokenService.GenerateAccessToken(existingClient.ClientId.ToString());
                var refreshTokenExisting = _tokenService.GenerateRefreshToken();

                var refreshTokens = await _dbContext.RefreshTokenClients.Where(rt => rt.ClientId == existingClient.ClientId).ToListAsync();

                _dbContext.RefreshTokenClients.RemoveRange(refreshTokens);
                await _dbContext.SaveChangesAsync();

                var newRefreshTokenExisting = new RefreshTokenClient
                {
                    RefreshTokenClientId = Guid.NewGuid(),
                    Token = refreshTokenExisting,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    CreatedByIp = HttpContext.Connection.RemoteIpAddress.ToString(),
                    ClientId = existingClient.ClientId
                };

                await _dbContext.RefreshTokenClients.AddAsync(newRefreshTokenExisting);
                await _dbContext.SaveChangesAsync();

                Response.Cookies.Append("srt", refreshTokenExisting, new CookieOptions
                {
                    HttpOnly = true,
                    MaxAge = TimeSpan.FromDays(7),
                });

                Response.Cookies.Append("sat", accessTokenExisting, new CookieOptions
                {
                    HttpOnly = true,
                    MaxAge = TimeSpan.FromMinutes(15),
                });

                return Redirect(_configuration["AppSettings:FrontendBaseUrl"]);
                

                

            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred", error = ex.Message });
            }
        }






        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto request)
        {
            try
            {
                var existingClient = await _dbContext.Clients.FirstOrDefaultAsync(c => c.Email == request.Email);
                if (existingClient != null)
                {
                    return BadRequest(new { message = "Email already in use" });
                }

                var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

                var emailVerificationToken = _tokenService.GenerateEmailVerificationToken();

                var newClient = new Models.Client
                {
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    Email = request.Email,
                    PasswordHash = passwordHash,
                    EmailVerificationToken = emailVerificationToken,
                    EmailVerificationTokenExpiresAt = DateTime.UtcNow.AddHours(24),
                    IsEmailVerified = false
                };

                await _dbContext.Clients.AddAsync(newClient);
                await _dbContext.SaveChangesAsync();

                var emailVerificationLink = _emailService.GenerateEmailVerificationLink(emailVerificationToken);
                var emailSendResult = await _emailService.SendEmailAsync(
                    request.Email,
                    "Email Verification",
                    $"Click the link to verify your email: {emailVerificationLink}"
                );

                if (!emailSendResult)
                {
                    return StatusCode(500, new { message = "Failed to send email" });
                }

                return Ok(new { message = "Client registered successfully" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = ex.Message });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
        {
            var client = await _dbContext.Clients.FirstOrDefaultAsync(c => c.Email == request.Email);
            if (client == null)
            {
                return BadRequest(new { message = "Client not found" });
            }

            var isPasswordValid = BCrypt.Net.BCrypt.Verify(request.Password, client.PasswordHash);
            if (!isPasswordValid)
            {
                return BadRequest(new { message = "Invalid password" });
            }

            // if (!client.IsEmailVerified)
            // {
            //     return BadRequest(new { message = "Email not verified" });
            // }

            var accessToken = _tokenService.GenerateAccessToken(client.ClientId.ToString());
            var refreshToken = _tokenService.GenerateRefreshToken();

            var refreshTokens = await _dbContext.RefreshTokenClients.Where(rt => rt.ClientId == client.ClientId).ToListAsync();
            _dbContext.RefreshTokenClients.RemoveRange(refreshTokens);

            await _dbContext.SaveChangesAsync();

            var newRefreshToken = new RefreshTokenClient
            {
                RefreshTokenClientId = Guid.NewGuid(),
                Token = refreshToken,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                CreatedByIp = HttpContext.Connection.RemoteIpAddress.ToString(),
                ClientId = client.ClientId
            };

            await _dbContext.RefreshTokenClients.AddAsync(newRefreshToken);
            await _dbContext.SaveChangesAsync();

            Response.Cookies.Append("srt", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                MaxAge = TimeSpan.FromDays(7),
            });

            Response.Cookies.Append("sat", accessToken, new CookieOptions
            {
                HttpOnly = true,
                MaxAge = TimeSpan.FromMinutes(15),
            });

            return Ok(new { message = "Client logged in successfully" });

        }

        [HttpGet("profile")]
        public async Task<IActionResult> Profile()
        {
            var accessToken = Request.Cookies["sat"];
            var refreshToken = Request.Cookies["srt"];
            if (!string.IsNullOrEmpty(accessToken))
            {
                var payload = _tokenService.VerifyAccessToken(accessToken);
                if (payload == null)
                {
                    return Unauthorized(new { message = "Unauthorized" });
                }

                var userIdClaim = payload?.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userIdClaim))
                {
                    return Unauthorized(new { message = "Unauthorized" });
                }

                var client = await _dbContext.Clients.FirstOrDefaultAsync(c => c.ClientId.ToString() == userIdClaim);
                if (client == null)
                {
                    return Unauthorized(new { message = "Unauthorized" });
                }


                var refreshTokenClient = await _dbContext.RefreshTokenClients.FirstOrDefaultAsync(rt => rt.Token == refreshToken);
                if (refreshTokenClient == null)
                {
                    return Unauthorized(new { message = "Unauthorized" });
                }

                if (refreshTokenClient.ExpiresAt < DateTime.UtcNow)
                {
                    return Unauthorized(new { message = "Unauthorized" });
                }

                var clientWithoutPassword = new
                {
                    client.ClientId,
                    client.FirstName,
                    client.LastName,
                    client.Email,
                    client.IsEmailVerified
                };

                return Ok(clientWithoutPassword);
            }



            if (string.IsNullOrEmpty(refreshToken))
            {
                return Unauthorized(new { message = "Unauthorized" });
            }

            var refreshTokenDoc = await _dbContext.RefreshTokenClients.FirstOrDefaultAsync(rt => rt.Token == refreshToken);

            if (refreshTokenDoc == null || refreshTokenDoc.ExpiresAt < DateTime.UtcNow)
            {
                if (refreshTokenDoc != null)
                {
                    _dbContext.RefreshTokenClients.Remove(refreshTokenDoc);
                    await _dbContext.SaveChangesAsync();
                }
                return Unauthorized(new { message = "Unauthorized" });
            }

            var clientFromRefresh = await _dbContext.Clients.FirstOrDefaultAsync(c => c.ClientId == refreshTokenDoc.ClientId);
            if (clientFromRefresh == null)
            {
                return Unauthorized(new { message = "Unauthorized" });
            }

            var newAccessToken = _tokenService.GenerateAccessToken(clientFromRefresh.ClientId.ToString());

            Response.Cookies.Append("sat", newAccessToken, new CookieOptions
            {
                HttpOnly = true,
                MaxAge = TimeSpan.FromMinutes(15),
            });

            var clientWithoutPasswordFromRefresh = new
            {
                clientFromRefresh.ClientId,
                clientFromRefresh.FirstName,
                clientFromRefresh.LastName,
                clientFromRefresh.Email,
                clientFromRefresh.IsEmailVerified
            };

            return Ok(clientWithoutPasswordFromRefresh);
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["srt"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                return Ok(new { message = "Client logged out successfully" });
            }

            var refreshTokenDoc = await _dbContext.RefreshTokenClients.FirstOrDefaultAsync(rt => rt.Token == refreshToken);
            if (refreshTokenDoc != null)
            {
                _dbContext.RefreshTokenClients.Remove(refreshTokenDoc);
                await _dbContext.SaveChangesAsync();
            }

            Response.Cookies.Delete("sat");
            Response.Cookies.Delete("srt");

            return Ok(new { message = "Client logged out successfully" });
        }

        [HttpGet("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromQuery] string token)
        {
            try
            {

                if (string.IsNullOrEmpty(token))
                {
                    return BadRequest(new { message = "Invalid token" });
                }


                var client = await _dbContext.Clients.FirstOrDefaultAsync(c => c.EmailVerificationToken == token);
                if (client == null)
                {
                    return BadRequest(new { message = "Invalid token" });
                }

                if (client.EmailVerificationTokenExpiresAt < DateTime.UtcNow)
                {
                    return BadRequest(new { message = "Token expired" });
                }

                client.IsEmailVerified = true;
                client.EmailVerificationToken = null;
                client.EmailVerificationTokenExpiresAt = null;

                await _dbContext.SaveChangesAsync();

                var accessToken = _tokenService.GenerateAccessToken(client.ClientId.ToString());
                var refreshToken = _tokenService.GenerateRefreshToken();

                var refreshTokens = await _dbContext.RefreshTokenClients.Where(rt => rt.ClientId == client.ClientId).ToListAsync();
                _dbContext.RefreshTokenClients.RemoveRange(refreshTokens);

                await _dbContext.SaveChangesAsync();

                var newRefreshToken = new RefreshTokenClient
                {
                    RefreshTokenClientId = Guid.NewGuid(),
                    Token = refreshToken,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    CreatedByIp = HttpContext.Connection.RemoteIpAddress.ToString(),
                    ClientId = client.ClientId
                };

                await _dbContext.RefreshTokenClients.AddAsync(newRefreshToken);
                await _dbContext.SaveChangesAsync();

                Response.Cookies.Append("srt", refreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    MaxAge = TimeSpan.FromDays(7),
                });

                Response.Cookies.Append("sat", accessToken, new CookieOptions
                {
                    HttpOnly = true,
                    MaxAge = TimeSpan.FromMinutes(15),
                });

                var frontendUrl = _configuration["AppSettings:FrontendBaseUrl"];
                return Redirect(frontendUrl);
            }
            catch (Exception ex)
            {

                return StatusCode(500, new { message = "An error occurred", error = ex.Message });
            }
        }
    }
}
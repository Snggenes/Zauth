using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;

namespace Zauth_net.Services
{
    public class GoogleOAuthService
    {
        private readonly IConfiguration _configuration;

        public GoogleOAuthService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GetGoogleAuthUrl()
        {
            var googleClientId = _configuration["Google:ClientId"];
            var googleClientSecret = _configuration["Google:ClientSecret"];
            var redirectUrl = $"{_configuration["AppSettings:BackendBaseUrl"]}/api/client/google/callback";

            var clientSecrets = new ClientSecrets
            {
                ClientId = googleClientId,
                ClientSecret = googleClientSecret
            };

            var flow = new GoogleAuthorizationCodeFlow(new GoogleAuthorizationCodeFlow.Initializer
            {
                ClientSecrets = clientSecrets,
                Scopes = new[] { "profile", "email" }
            });

            var authorizationUrl = flow.CreateAuthorizationCodeRequest(redirectUrl).Build().AbsoluteUri;
            return authorizationUrl;
        }

        public async Task<GoogleJsonWebSignature.Payload> VerifyGoogleIdToken(string idToken)
        {
            try
            {
                var googleClientId = _configuration["Google:ClientId"];
                var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = new[] { googleClientId }
                });

                return payload;
            }
            catch
            {
                return null;
            }
        }
    }
}
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Threading.Tasks;

namespace LAC.DCFS.MFA.PACKAGE
{
    public class MFA
    {
        public string GetOAuthSignInUrl(AuthorizationModel authorizationModel)
        {
            var oauth2SignInUrl = "https://login.microsoftonline.com/" + authorizationModel.tenant +
                                     "/oauth2/authorize?" +
                                     "client_id=" + authorizationModel.client_id +
                                     "&response_type=" + authorizationModel.response_type +
                                     "&redirect_uri=" + authorizationModel.redirect_uri +
                                     "&response_mode=" + authorizationModel.response_mode +
                                     "&scope=" + authorizationModel.scope +
                                     "&state=" + authorizationModel.state;
            return oauth2SignInUrl;
        }

        public string GetOAuthSignOutUrl(string logoutRedirectUri)
        {
            var oauth2SignOutUrl =
                "https://login.microsoftonline.com/07597248-ea38-451b-8abe-a638eddbac81/oauth2/v2.0/logout?post_logout_redirect_uri=" +
                logoutRedirectUri;

            return oauth2SignOutUrl;
        }

        public async Task<TokenModel> GetAuthResponse(AuthorizationModel authorizationModel)
        {

            var client = new HttpClient();
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("cache-control", "no-cache");

            var parameter = new Dictionary<string, string>()
            {
                {"client_id", authorizationModel.client_id},
                {"redirect_uri", authorizationModel.redirect_uri},
                {"grant_type", authorizationModel.grant_type},
                {"client_secret", authorizationModel.client_secret},
                {"scope", authorizationModel.scope},
                {"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
                {"code", authorizationModel.code}
            };

            try
            {
                
                var responseMessage = await client.PostAsync("https://login.microsoftonline.com/" + authorizationModel.tenant + "/oauth2/token", new FormUrlEncodedContent(parameter));
                var tokenModel = new TokenModel
                {
                    IsSuccessStatusCode = responseMessage.IsSuccessStatusCode,
                    error_message = responseMessage.ReasonPhrase
                };

                if (responseMessage.IsSuccessStatusCode)
                {
                    var jsonContent = await responseMessage.Content.ReadAsStringAsync();
                    tokenModel = JsonConvert.DeserializeObject<TokenModel>(jsonContent);

                    if (tokenModel != null)
                    {
                        tokenModel.IsSuccessStatusCode = responseMessage.IsSuccessStatusCode;
                        return tokenModel;
                    }
                }

                return tokenModel;

            }
            catch (Exception e)
            {
                var tokenModel = new TokenModel
                {
                    IsSuccessStatusCode = false,
                    error_message = e.Message
                };

                return tokenModel;

            }

        }

        public async Task<UserModel> GetLoginEmployeeProfile(string accessToken)
        {

            var client = new HttpClient();
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(accessToken);
            string audValue = null;
            string uri;

            foreach (var claim in jwtSecurityToken.Claims)
            {
                if (claim.Type == "aud") audValue = claim.Value;
            }

            switch (audValue ?? "")
            {
                case "00000002-0000-0000-c000-000000000000":
                    {
                        uri = "https://graph.windows.net/me?api-version=1.6";
                        break;
                    }
                case "00000003-0000-0000-c000-000000000000":
                    {
                        uri = "https://graph.microsoft.com/beta/me/";
                        break;
                    }

                default:
                    {
                        uri = "https://graph.microsoft.com/beta/me/";
                        break;
                    }
            }

            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + accessToken);
            client.DefaultRequestHeaders.Add("Accept", "application/json");

            try
            {
                var users = await client.GetAsync(uri);
                var userModel = new UserModel
                {
                    IsSuccessStatusCode = users.IsSuccessStatusCode,
                    errorMessage = users.ReasonPhrase
                };

                if (users.IsSuccessStatusCode)
                {
                    var jsonContent = await users.Content.ReadAsStringAsync();
                    userModel = JsonConvert.DeserializeObject<UserModel>(jsonContent);

                    if (userModel != null)
                    {
                        userModel.IsSuccessStatusCode = users.IsSuccessStatusCode;
                        return userModel;
                    }
                }

                return userModel;
            }
            catch (Exception e)
            {
                var userModel = new UserModel
                {
                    IsSuccessStatusCode = false,
                    errorMessage = e.Message
                };
                return userModel;
            }



        }
    }




    public class AuthorizationModel
    {
        public string tenant { get; set; }
        public string client_id { get; set; }
        public string response_type { get; set; }
        public string redirect_uri { get; set; }
        public string scope { get; set; }
        public string response_mode { get; set; }
        public string state { get; set; }
        public string prompt { get; set; }
        public string login_hint { get; set; }
        public string domain_hint { get; set; }
        public string code_challenge { get; set; }
        public string code_challenge_method { get; set; }
        public string grant_type { get; set; }
        public string code_verifier { get; set; }
        public string client_secret { get; set; }
        public string code { get; set; }

    }

    public class AuthorizationModel_
    {
        public string tenant { get; set; }
        public string client_id { get; set; }
        public string scope { get; set; }
        public string code { get; set; }
        public string redirect_uri { get; set; }
        public string grant_type { get; set; }
        public string code_verifier { get; set; }
        public string client_secret { get; set; }


    }

    public class TokenModel
    {

        public string token_type { get; set; }
        public string expires_in { get; set; }
        public string ext_expires_in { get; set; }
        public string expires_on { get; set; }
        public string scope { get; set; }
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public string id_token { get; set; }
        public bool IsSuccessStatusCode { get; set; }
        public string error_message { get; set; }

    }


    public class JWTModel
    {
        public string aud { get; set; }
        public string appid { get; set; }
        public string family_name { get; set; }
        public string given_name { get; set; }
        public string ipaddr { get; set; }
        public string name { get; set; }
        public string scp { get; set; }
        public string tid { get; set; }
        public string upn { get; set; }

    }

    public class UserModel
    {
        public string employeeId { get; set; }
        public string givenName { get; set; }
        public string surname { get; set; }
        public string jobTitle { get; set; }
        public string mail { get; set; }
        public string mailNickname { get; set; }
        public string userType { get; set; }
        public string displayName { get; set; }
        public string officeLocation { get; set; }
        public string errorMessage { get; set; }
        public bool IsSuccessStatusCode { get; set; }
    }
}

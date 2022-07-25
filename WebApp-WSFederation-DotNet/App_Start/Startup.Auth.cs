//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

// The following using statements were added for this sample.
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.WsFederation;
using System.Configuration;
using System.Globalization;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Extensions;
using Microsoft.IdentityModel.Protocols;
using System.IdentityModel.Selectors;
using System.IdentityModel.Services.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace WebApp_WSFederation_DotNet
{
    public partial class Startup
    {
        //
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        // The Metadata Address is used by the application to retrieve the signing keys used by Azure AD.
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Authority is the sign-in URL of the tenant.
        // The Post Logout Redirect Uri is the URL where the user will be redirected after they sign out.
        //
        private static string realm = ConfigurationManager.AppSettings["ida:Wtrealm"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string metadata = string.Format("{0}/{1}/federationmetadata/2007-06/federationmetadata.xml", aadInstance, tenant);
       

        string authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        public void ConfigureAuth(IAppBuilder app)
        {
            //app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType); //org
            app.SetDefaultSignInAsAuthenticationType(WsFederationAuthenticationDefaults.AuthenticationType);

            //app.UseCookieAuthentication(new CookieAuthenticationOptions()); //org
            app.UseCookieAuthentication(new CookieAuthenticationOptions { AuthenticationType = WsFederationAuthenticationDefaults.AuthenticationType });

            app.UseWsFederationAuthentication(GetWsFederationOptions());
        }

        private WsFederationAuthenticationOptions GetWsFederationOptions()
        {
            var wsFederationConfiguration = new WsFederationConfiguration
            {
                Issuer = "",
                TokenEndpoint = ""
            };
            
            var options = new WsFederationAuthenticationOptions
            {
                MetadataAddress = metadata,
                Wtrealm = realm,
                SignOutWreply = "https://wsfedpoc.azurewebsites.net/",
                SignInAsAuthenticationType = WsFederationAuthenticationDefaults.AuthenticationType,
                SecurityTokenHandlers = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers(),
                //Configuration = wsFederationConfiguration,

                TokenValidationParameters = new TokenValidationParameters
                {
                    AuthenticationType = WsFederationAuthenticationDefaults.AuthenticationType,
                    CertificateValidator = X509CertificateValidator.None,
                    RequireSignedTokens = false,
                    SaveSigninToken = true,
                    ValidateIssuerSigningKey = false
                },
                Notifications = new WsFederationAuthenticationNotifications()
                {
                    AuthenticationFailed = context =>
                    {
                        context.HandleResponse();
                        context.Response.Redirect("Home/Error?message=" + context.Exception.Message);
                        return Task.FromResult(0);
                    }
                }
            };

            options.SecurityTokenHandlers.Remove(options.SecurityTokenHandlers[typeof(SessionSecurityTokenHandler)]);
            options.SecurityTokenHandlers.Add(new MachineKeySessionSecurityTokenHandler());

            return options;
        }

        private static X509Certificate2 GetX590Certificate(string certThumbprint)
        {
            if (string.IsNullOrWhiteSpace(certThumbprint))
            {
                throw new ArgumentException("certThumbprint");
            }

            // Retrieve the Local Machine certificate store and load the x.509 client certificate, using the certificate's thumbprint to identify and retrieve it from the store.
            X509Store x509Store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);

            // Get certificate by thumbprint
            x509Store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection x509Collection = x509Store.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, true);
            x509Store.Close();

            switch (x509Collection.Count)
            {
                case 1:
                    return x509Collection[0];
                default:
                    throw new NullReferenceException(string.Format("STS trusted issuer certificate was not found! Certificate Thumbprint: {0}", certThumbprint));
            }
        }
    }
}
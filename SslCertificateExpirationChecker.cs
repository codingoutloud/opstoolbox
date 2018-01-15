// https://github.com/codingoutloud/opstoolbox

using System;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

// Code started from these posts (as of Jan 2018)
// https://msdn.microsoft.com/en-us/library/system.net.security.sslstream(v=vs.110).aspx
// https://msdn.microsoft.com/en-us/library/system.net.security.remotecertificatevalidationcallback(v=vs.110).aspx

namespace opstoolbox
{
    public class SslCertificateExpirationChecker
    {
        public int GetDaysUntilExpiration(string domain)
        {
            var certFetcher = new SslCertificateFetcher();
            TcpClient tcpClient = null;
            try
            {
                tcpClient = new TcpClient(domain, 443);
                SslStream sslStream = new SslStream(
                    tcpClient.GetStream(),
                    false,
                    new RemoteCertificateValidationCallback(certFetcher.ValidateServerCertificate),
                    null);

                // This call results in the above RemoteCertificateValidationCallback 
                // delegate being called, passing it the SSL certificate
                sslStream.AuthenticateAsClient(domain);
            }
            catch (AuthenticationException ex)
            {
                return certFetcher.DaysRemaining.HasValue ? certFetcher.DaysRemaining.Value : throw new ArgumentException($"problem accessing SSL certificate for {domain} [{ex.GetBaseException().Message}]", "domain", ex);
            }
            catch (Exception ex)
            {
                return certFetcher.DaysRemaining.HasValue ? certFetcher.DaysRemaining.Value : throw new ArgumentException($"problem accessing SSL certificate for {domain} [{ex.GetBaseException().Message}]", "domain", ex);
            }
            finally
            {
                if (tcpClient != null)
                    tcpClient.Close();
            }

            return certFetcher.DaysRemaining.HasValue ? certFetcher.DaysRemaining.Value : throw new Exception($"problem accessing SSL certificate for {domain}");
        }

        private class SslCertificateFetcher
        {
            public int? DaysRemaining { get; set; }
            public SslPolicyErrors SslPolicyErrors { get; set; }

            public bool ValidateServerCertificate(
                object sender,
                X509Certificate certificate, // really will be X509Certificate2
                X509Chain chain,
                SslPolicyErrors sslPolicyErrors) // does machinename match
            {
                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    var notAfter = ((X509Certificate2)certificate).NotAfter;
                    int daysRemaining = (int)Math.Floor((notAfter - DateTime.UtcNow).TotalDays);

                    DaysRemaining = daysRemaining;

                    return true;
                }
                else
                {
                    SslPolicyErrors = sslPolicyErrors;

                    return false;
                }
            }
        }
    }
}

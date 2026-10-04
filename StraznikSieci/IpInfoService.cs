using System;
using System.IO;
using System.Net;
using System.Text;

namespace StraznikSieci
{
    public class IpInfo
    {
        public string Query { get; set; }
        public string Country { get; set; }
        public string City { get; set; }
        public string Isp { get; set; }
        public string Org { get; set; }
        public string AsInfo { get; set; }
        public string ReverseDns { get; set; }
        public bool Proxy { get; set; }
        public bool Hosting { get; set; }
        public bool Mobile { get; set; }
        public string Error { get; set; }
    }

    /// <summary>
    /// Pobiera publicznie dostepne informacje o adresie IP z darmowego API ip-api.com.
    /// Tylko dane jawne (kraj, operator, czy adres nalezy do hostingu/proxy) - nic o osobie.
    /// Limit darmowego API: ok. 45 zapytan na minute.
    /// </summary>
    public static class IpInfoService
    {
        private const string Endpoint =
            "http://ip-api.com/json/{0}?fields=status,message,country,city,isp,org,as,proxy,hosting,mobile,query";

        static IpInfoService()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }

        public static IpInfo Lookup(string ip)
        {
            var info = new IpInfo { Query = ip };

            if (NetUtil.IsPrivate(ip))
            {
                info.Error = "Adres lokalny / prywatny - brak danych publicznych.";
                return info;
            }

            try
            {
                var req = (HttpWebRequest)WebRequest.Create(string.Format(Endpoint, ip));
                req.Timeout = 8000;
                req.UserAgent = "StraznikSieci/1.0";

                string json;
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    json = sr.ReadToEnd();

                if (Field(json, "status") != "success")
                {
                    info.Error = Field(json, "message");
                    if (string.IsNullOrEmpty(info.Error)) info.Error = "Brak danych dla tego adresu.";
                    return info;
                }

                info.Country = Field(json, "country");
                info.City = Field(json, "city");
                info.Isp = Field(json, "isp");
                info.Org = Field(json, "org");
                info.AsInfo = Field(json, "as");
                info.Proxy = Flag(json, "proxy");
                info.Hosting = Flag(json, "hosting");
                info.Mobile = Flag(json, "mobile");
            }
            catch (Exception ex)
            {
                info.Error = "Blad polaczenia z usluga informacyjną: " + ex.Message;
            }

            try
            {
                IPAddress a;
                if (IPAddress.TryParse(ip, out a))
                    info.ReverseDns = Dns.GetHostEntry(a).HostName;
            }
            catch { info.ReverseDns = "(brak wpisu odwrotnego DNS)"; }

            return info;
        }

        // Prosty parser JSON - wystarczajacy dla plaskiej odpowiedzi ip-api,
        // dzieki czemu projekt nie wymaga zadnych pakietow NuGet.
        private static string Field(string json, string name)
        {
            string key = "\"" + name + "\"";
            int i = json.IndexOf(key, StringComparison.Ordinal);
            if (i < 0) return null;
            i = json.IndexOf(':', i + key.Length);
            if (i < 0) return null;
            i++;
            while (i < json.Length && char.IsWhiteSpace(json[i])) i++;
            if (i >= json.Length || json[i] != '"') return null;
            i++;
            var sb = new StringBuilder();
            while (i < json.Length && json[i] != '"')
            {
                if (json[i] == '\\' && i + 1 < json.Length) i++;
                sb.Append(json[i]);
                i++;
            }
            return sb.ToString();
        }

        private static bool Flag(string json, string name)
        {
            string key = "\"" + name + "\"";
            int i = json.IndexOf(key, StringComparison.Ordinal);
            if (i < 0) return false;
            i = json.IndexOf(':', i + key.Length);
            if (i < 0) return false;
            return json.Substring(i + 1, Math.Min(6, json.Length - i - 1)).Contains("true");
        }
    }
}

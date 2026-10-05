using System.Diagnostics;
using System.Net;

namespace StraznikSieci
{
    /// <summary>Dzialania obronne na WLASNYM komputerze: blokada adresu w zaporze i zgloszenie do CERT.</summary>
    public static class Defense
    {
        public const string CertUrl = "https://incydent.cert.pl/";

        /// <summary>Dodaje regule zapory Windows blokujaca ruch z/do adresu. Wymaga zgody UAC.</summary>
        public static bool BlockIp(string ip)
        {
            IPAddress parsed;
            if (!IPAddress.TryParse(ip, out parsed)) return false;   // walidacja - nic innego do netsh nie trafi
            string safe = parsed.ToString();
            string args = "advfirewall firewall add rule name=\"StraznikSieci blokada " + safe + "\" dir=in action=block remoteip=" + safe +
                          " & netsh advfirewall firewall add rule name=\"StraznikSieci blokada " + safe + " out\" dir=out action=block remoteip=" + safe;
            var psi = new ProcessStartInfo("cmd.exe", "/c netsh " + args)
            {
                Verb = "runas",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            try
            {
                using (var p = Process.Start(psi))
                {
                    p.WaitForExit(15000);
                    return true;
                }
            }
            catch (System.ComponentModel.Win32Exception) { return false; } // uzytkownik odmowil UAC
        }

        public static void OpenCert()
        {
            Process.Start(new ProcessStartInfo(CertUrl) { UseShellExecute = true });
        }
    }
}

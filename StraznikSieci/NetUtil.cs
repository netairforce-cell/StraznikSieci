using System.Net;
using System.Net.Sockets;

namespace StraznikSieci
{
    public static class NetUtil
    {
        /// <summary>True, jesli adres NIE jest publiczny (LAN, loopback, link-local, CGNAT itp.).</summary>
        public static bool IsPrivate(IPAddress ip)
        {
            if (ip == null) return true;
            if (IPAddress.IsLoopback(ip)) return true;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;

            byte[] b = ip.GetAddressBytes();
            if (b[0] == 0) return true;                               // 0.0.0.0/8
            if (b[0] == 10) return true;                              // 10/8
            if (b[0] == 127) return true;                             // loopback
            if (b[0] == 169 && b[1] == 254) return true;              // link-local
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16/12
            if (b[0] == 192 && b[1] == 168) return true;              // 192.168/16
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;// CGNAT 100.64/10
            if (b[0] >= 224) return true;                             // multicast/zarezerwowane
            return false;
        }

        public static bool IsPrivate(string ip)
        {
            IPAddress a;
            return !IPAddress.TryParse(ip, out a) || IsPrivate(a);
        }
    }
}

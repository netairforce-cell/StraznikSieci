using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace StraznikSieci
{
    public class HopInfo
    {
        public int Ttl { get; set; }
        public string Address { get; set; }
        public string HostName { get; set; }
        public long RoundtripMs { get; set; }
        public string Status { get; set; }

        public string Czas { get { return RoundtripMs < 0 ? "-" : RoundtripMs + " ms"; } }
    }

    /// <summary>Traceroute oparty o ICMP Echo z rosnacym TTL (odpowiednik polecenia tracert).</summary>
    public static class TraceRoute
    {
        public static IEnumerable<HopInfo> Trace(string host, int maxHops = 30, int timeoutMs = 2000,
                                                 bool resolveNames = true)
        {
            IPAddress target;
            if (!IPAddress.TryParse(host, out target))
            {
                var entries = Dns.GetHostAddresses(host);
                if (entries.Length == 0) throw new Exception("Nie udalo sie rozwiazac nazwy: " + host);
                target = entries[0];
            }

            byte[] payload = Encoding.ASCII.GetBytes("StraznikSieci-traceroute");

            using (var ping = new Ping())
            {
                for (int ttl = 1; ttl <= maxHops; ttl++)
                {
                    var options = new PingOptions(ttl, true);
                    var sw = Stopwatch.StartNew();
                    PingReply reply;
                    HopInfo errorInfo = null;
                    try
                    {
                        reply = ping.Send(target, timeoutMs, payload, options);
                    }
                    catch (Exception ex)
                    {
                        errorInfo = new HopInfo { Ttl = ttl, Address = "-", HostName = "", RoundtripMs = -1, Status = "Blad: " + ex.Message };
                        reply = null;
                    }
                    sw.Stop();

                    if (errorInfo != null)
                    {
                        yield return errorInfo;
                        yield break;
                    }

                    if (reply == null || reply.Status == IPStatus.TimedOut)
                    {
                        yield return new HopInfo { Ttl = ttl, Address = "*", HostName = "", RoundtripMs = -1, Status = "brak odpowiedzi" };
                        continue;
                    }

                    string addr = reply.Address != null ? reply.Address.ToString() : "*";
                    string name = "";
                    if (resolveNames && reply.Address != null)
                    {
                        try { name = Dns.GetHostEntry(reply.Address).HostName; }
                        catch { name = ""; }
                    }

                    yield return new HopInfo
                    {
                        Ttl = ttl,
                        Address = addr,
                        HostName = name,
                        RoundtripMs = reply.RoundtripTime > 0 ? reply.RoundtripTime : sw.ElapsedMilliseconds,
                        Status = reply.Status == IPStatus.Success ? "CEL" :
                                 reply.Status == IPStatus.TtlExpired ? "przeskok" : reply.Status.ToString()
                    };

                    if (reply.Status == IPStatus.Success) yield break;
                }
            }
        }
    }
}

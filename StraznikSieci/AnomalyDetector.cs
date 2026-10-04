using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace StraznikSieci
{
    public class AlertInfo
    {
        public DateTime Time { get; set; }
        public string Level { get; set; }      // WYSOKI / SREDNI / INFO
        public string Title { get; set; }
        public string Details { get; set; }
        public string Ip { get; set; }
        public string Evidence { get; set; }   // wynik sprawdzenia IP + traceroute (uzupelniany w tle)
        public string TimeText { get { return Time.ToString("HH:mm:ss"); } }
    }

    /// <summary>Pasywne reguly wykrywania anomalii - tylko analiza danych, ktore system sam pokazuje.</summary>
    public class AnomalyDetector
    {
        private static readonly HashSet<int> RiskyPorts = new HashSet<int> { 21, 22, 23, 135, 139, 445, 3389, 5900, 5985, 5986 };
        private readonly HashSet<string> _reported = new HashSet<string>();

        private AlertInfo Make(string key, string level, string title, string details, string ip)
        {
            if (!_reported.Add(key)) return null;
            return new AlertInfo { Time = DateTime.Now, Level = level, Title = title, Details = details, Ip = ip, Evidence = "" };
        }

        public List<AlertInfo> Analyze(List<ConnectionInfo> conns, List<SessionInfo> sessions)
        {
            var result = new List<AlertInfo>();
            Action<AlertInfo> add = a => { if (a != null) result.Add(a); };

            // 1. Zdalna sesja uzytkownika
            foreach (var s in sessions.Where(x => x.IsRemote))
            {
                string ip = s.ClientAddress;
                add(Make("sess|" + s.SessionId + "|" + s.User + "|" + ip, "WYSOKI",
                    "Zdalna sesja uzytkownika: " + s.User,
                    string.Format("Sesja #{0} ({1}), stan: {2}, komputer zdalny: {3}, adres: {4}",
                        s.SessionId, s.StationName, s.State, s.ClientName, ip.Length > 0 ? ip : "nieznany"),
                    ip));
            }

            // 2. Polaczenia PRZYCHODZACE z Internetu na porty, na ktorych nasluchuje ten komputer
            var listening = new HashSet<int>(conns.Where(c => c.State == "NASLUCH").Select(c => c.LocalPort));
            foreach (var c in conns.Where(x => x.IsExternal && x.State == "NAWIAZANE" && listening.Contains(x.LocalPort)))
            {
                bool risky = RiskyPorts.Contains(c.LocalPort);
                add(Make("in|" + c.RemoteAddress + "|" + c.LocalPort, risky ? "WYSOKI" : "SREDNI",
                    "Polaczenie przychodzace z Internetu na port " + c.LocalPort,
                    string.Format("Proces {0} (PID {1}) przyjal polaczenie od {2}", c.ProcessName, c.Pid, c.Remote),
                    c.RemoteAddress));
            }

            // 3. Nasluchiwanie na wszystkich interfejsach na ryzykownych portach
            foreach (var c in conns.Where(x => x.State == "NASLUCH" && x.LocalAddress == "0.0.0.0" && RiskyPorts.Contains(x.LocalPort)))
            {
                add(Make("listen|" + c.LocalPort, "SREDNI",
                    "Otwarta furtka: port " + c.LocalPort + " nasluchuje na wszystkich interfejsach",
                    string.Format("Proces {0} (PID {1}). Jesli nie korzystasz z tej uslugi - wylacz ja.", c.ProcessName, c.Pid),
                    ""));
            }

            // 4. Jeden proces laczy sie z bardzo wieloma roznymi adresami z Internetu
            foreach (var g in conns.Where(x => x.IsExternal).GroupBy(x => x.ProcessName))
            {
                int n = g.Select(x => x.RemoteAddress).Distinct().Count();
                if (n >= 25 && g.Key != "(nieznany)")
                    add(Make("many|" + g.Key, "INFO", "Proces " + g.Key + " laczy sie z " + n + " roznymi adresami",
                        "To moze byc przegladarka (normalne) albo program skanujacy / rozsylajacy dane.", ""));
            }

            return result;
        }

        public static string BuildReport(AlertInfo a, List<ConnectionInfo> conns, List<SessionInfo> sessions)
        {
            var sb = new StringBuilder();
            sb.AppendLine("ZGLOSZENIE INCYDENTU - Straznik Sieci - " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("Komputer: " + Environment.MachineName + ", uzytkownik: " + Environment.UserName);
            sb.AppendLine();
            sb.AppendLine("Zdarzenie [" + a.Level + "] " + a.Title);
            sb.AppendLine("Czas: " + a.Time.ToString("yyyy-MM-dd HH:mm:ss") + " (czas lokalny)");
            sb.AppendLine("Opis: " + a.Details);
            if (!string.IsNullOrEmpty(a.Ip)) sb.AppendLine("Adres IP zrodlowy: " + a.Ip);
            sb.AppendLine();
            if (!string.IsNullOrEmpty(a.Evidence))
            {
                sb.AppendLine("=== Dane o adresie i trasa pakietow ===");
                sb.AppendLine(a.Evidence);
            }
            sb.AppendLine("=== Sesje uzytkownikow ===");
            foreach (var s in sessions.Where(x => x.IsActiveUser))
                sb.AppendLine(string.Format("#{0} {1} {2} stan: {3} klient: {4} {5}", s.SessionId, s.User, s.StationName, s.State, s.ClientName, s.ClientAddress));
            sb.AppendLine();
            sb.AppendLine("=== Polaczenia z Internetem ===");
            foreach (var c in conns.Where(x => x.IsExternal))
                sb.AppendLine(string.Format("{0} (PID {1}) {2} -> {3} {4}", c.ProcessName, c.Pid, c.Local, c.Remote, c.State));
            return sb.ToString();
        }
    }
}

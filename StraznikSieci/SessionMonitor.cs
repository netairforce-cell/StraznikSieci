using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace StraznikSieci
{
    /// <summary>Sesja uzytkownika zalogowanego w systemie (konsola, RDP, ...).</summary>
    public class SessionInfo
    {
        public int SessionId { get; set; }
        public string StationName { get; set; }
        public string User { get; set; }
        public string State { get; set; }
        public string ClientName { get; set; }
        public string ClientAddress { get; set; }
        public bool IsRemote { get; set; }
        public bool IsActiveUser { get; set; }

        public string Verdict
        {
            get
            {
                if (!IsActiveUser) return "usluga / wolna";
                if (IsRemote) return "GOSC ZDALNY!";
                return "lokalna";
            }
        }
    }

    /// <summary>Odczyt sesji przez WTS API (tylko odczyt + opcjonalnie komunikat / rozlaczenie na zyczenie uzytkownika).</summary>
    public static class SessionMonitor
    {
        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSEnumerateSessions(IntPtr hServer, int reserved, int version,
            out IntPtr ppSessionInfo, out int pCount);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, int infoClass,
            out IntPtr ppBuffer, out int pBytesReturned);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pointer);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WTSSendMessage(IntPtr hServer, int sessionId, string title, int titleLength,
            string message, int messageLength, int style, int timeout, out int response, bool wait);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSLogoffSession(IntPtr hServer, int sessionId, bool wait);

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public int SessionId;
            public IntPtr pWinStationName;
            public int State;
        }

        private const int WTSUserName = 5;
        private const int WTSClientName = 10;
        private const int WTSClientAddress = 14;

        private static readonly string[] States =
        {
            "Aktywna", "Polaczona", "Pytanie o polaczenie", "Cienia", "Rozlaczona",
            "Bezczynna", "Nasluchuje", "Resetowana", "Zamykana", "Inicjowana"
        };

        private static string QueryString(int id, int cls)
        {
            IntPtr buf;
            int len;
            if (!WTSQuerySessionInformation(IntPtr.Zero, id, cls, out buf, out len)) return "";
            try { return Marshal.PtrToStringUni(buf) ?? ""; }
            finally { WTSFreeMemory(buf); }
        }

        private static string QueryClientAddress(int id)
        {
            IntPtr buf;
            int len;
            if (!WTSQuerySessionInformation(IntPtr.Zero, id, WTSClientAddress, out buf, out len)) return "";
            try
            {
                int family = Marshal.ReadInt32(buf);
                if (family != 2) return "";   // tylko IPv4
                int a = Marshal.ReadByte(buf, 6);
                int b = Marshal.ReadByte(buf, 7);
                int c = Marshal.ReadByte(buf, 8);
                int d = Marshal.ReadByte(buf, 9);
                if (a == 0 && b == 0 && c == 0 && d == 0) return "";
                return a + "." + b + "." + c + "." + d;
            }
            finally { WTSFreeMemory(buf); }
        }

        public static List<SessionInfo> GetSessions()
        {
            var list = new List<SessionInfo>();
            IntPtr buf;
            int count;
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out buf, out count)) return list;
            try
            {
                int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                for (int i = 0; i < count; i++)
                {
                    IntPtr p = (IntPtr)((long)buf + (long)i * size);
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure(p, typeof(WTS_SESSION_INFO));
                    string station = Marshal.PtrToStringUni(si.pWinStationName) ?? "";
                    string user = QueryString(si.SessionId, WTSUserName);
                    string client = QueryString(si.SessionId, WTSClientName);
                    string addr = QueryClientAddress(si.SessionId);

                    bool hasUser = user.Length > 0;
                    bool remote = hasUser &&
                                  (station.StartsWith("RDP-", StringComparison.OrdinalIgnoreCase) ||
                                   addr.Length > 0 || client.Length > 0) &&
                                  !station.Equals("Console", StringComparison.OrdinalIgnoreCase);

                    list.Add(new SessionInfo
                    {
                        SessionId = si.SessionId,
                        StationName = station,
                        User = user,
                        State = (si.State >= 0 && si.State < States.Length) ? States[si.State] : si.State.ToString(),
                        ClientName = client,
                        ClientAddress = addr,
                        IsRemote = remote,
                        IsActiveUser = hasUser
                    });
                }
            }
            finally { WTSFreeMemory(buf); }
            return list;
        }

        public static bool SendMessage(int sessionId, string title, string message)
        {
            int resp;
            return WTSSendMessage(IntPtr.Zero, sessionId, title, title.Length * 2,
                message, message.Length * 2, 0x40 /* MB_ICONINFORMATION */, 0, out resp, false);
        }

        public static bool Logoff(int sessionId)
        {
            return WTSLogoffSession(IntPtr.Zero, sessionId, false);
        }
    }
}

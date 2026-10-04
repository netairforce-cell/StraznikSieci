using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace StraznikSieci
{
    /// <summary>
    /// Odczyt tablicy polaczen TCP z systemu Windows (iphlpapi.dll / GetExtendedTcpTable),
    /// czyli to samo zrodlo danych co polecenie "netstat -ano", tylko bez uruchamiania procesu.
    /// </summary>
    public static class TcpTable
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
            bool sort, int ipVersion, int tblClass, int reserved);

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;   // port w network byte order, tylko 2 mlodsze bajty
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        private static readonly string[] StateNames =
        {
            "?", "ZAMKNIETE", "NASLUCH", "SYN_SENT", "SYN_RCVD",
            "NAWIAZANE", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
            "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
        };

        private static int ToPort(uint raw)
        {
            return ((int)(raw & 0xFF) << 8) | (int)((raw >> 8) & 0xFF);
        }

        public static List<ConnectionInfo> GetTcpConnections()
        {
            var list = new List<ConnectionInfo>();
            int bufLen = 0;

            GetExtendedTcpTable(IntPtr.Zero, ref bufLen, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr buf = Marshal.AllocHGlobal(bufLen);
            try
            {
                uint ret = GetExtendedTcpTable(buf, ref bufLen, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) throw new Exception("GetExtendedTcpTable zwrocilo blad " + ret);

                int rows = Marshal.ReadInt32(buf);
                IntPtr ptr = (IntPtr)((long)buf + 4);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));

                var procCache = BuildProcessCache();

                for (int i = 0; i < rows; i++)
                {
                    var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(ptr, typeof(MIB_TCPROW_OWNER_PID));
                    ptr = (IntPtr)((long)ptr + rowSize);

                    string remote = new IPAddress(row.remoteAddr).ToString();
                    int state = (int)row.state;

                    string procName;
                    if (!procCache.TryGetValue((int)row.owningPid, out procName))
                        procName = "(nieznany)";

                    list.Add(new ConnectionInfo
                    {
                        Protocol = "TCP",
                        LocalAddress = new IPAddress(row.localAddr).ToString(),
                        LocalPort = ToPort(row.localPort),
                        RemoteAddress = remote,
                        RemotePort = state == 2 ? 0 : ToPort(row.remotePort),
                        State = (state >= 0 && state < StateNames.Length) ? StateNames[state] : state.ToString(),
                        Pid = (int)row.owningPid,
                        ProcessName = procName,
                        IsExternal = state != 2 && !NetUtil.IsPrivate(remote)
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }

            return list;
        }

        private static Dictionary<int, string> BuildProcessCache()
        {
            var d = new Dictionary<int, string>();
            foreach (var p in Process.GetProcesses())
            {
                try { if (!d.ContainsKey(p.Id)) d[p.Id] = p.ProcessName; }
                catch { }
            }
            return d;
        }
    }
}

namespace StraznikSieci
{
    /// <summary>Jedno polaczenie TCP widoczne w systemie.</summary>
    public class ConnectionInfo
    {
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public int Pid { get; set; }
        public string ProcessName { get; set; }
        public bool IsExternal { get; set; }

        public string Local { get { return LocalAddress + ":" + LocalPort; } }
        public string Remote { get { return RemoteAddress + ":" + RemotePort; } }
        public string Kind { get { return IsExternal ? "INTERNET" : "lokalne"; } }
    }
}

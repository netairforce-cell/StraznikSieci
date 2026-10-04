using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace StraznikSieci
{
    public partial class MainWindow : Window
    {
        private readonly DispatcherTimer _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        private readonly HashSet<string> _seenRemotes = new HashSet<string>();
        private readonly ObservableCollection<HopInfo> _hops = new ObservableCollection<HopInfo>();
        private readonly string _logDir;
        private List<ConnectionInfo> _all = new List<ConnectionInfo>();
        private string _lastInfoText = "";
        private bool _busy;

        public MainWindow()
        {
            InitializeComponent();

            _logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "StraznikSieci");
            Directory.CreateDirectory(_logDir);

            GridHops.ItemsSource = _hops;
            _timer.Tick += (s, e) => RefreshConnections();
            Loaded += (s, e) => RefreshConnections();
            InitGuard();
        }

        // ---------- Polaczenia ----------

        private void RefreshConnections()
        {
            try
            {
                _all = TcpTable.GetTcpConnections();
                LogNewRemotes(_all);
                ApplyFilter();
                TxtStatus.Text = string.Format("Odswiezono {0:HH:mm:ss}. Polaczen: {1}, z Internetu: {2}.",
                    DateTime.Now, _all.Count, _all.Count(c => c.IsExternal));
            }
            catch (Exception ex)
            {
                TxtStatus.Text = "Blad odczytu polaczen: " + ex.Message;
            }
        }

        private void ApplyFilter()
        {
            if (GridConnections == null) return;
            IEnumerable<ConnectionInfo> q = _all;
            if (ChkExternalOnly.IsChecked == true) q = q.Where(c => c.IsExternal);
            if (ChkHideListen.IsChecked == true) q = q.Where(c => c.State != "NASLUCH");
            GridConnections.ItemsSource = q.OrderBy(c => c.ProcessName).ThenBy(c => c.RemoteAddress).ToList();
        }

        private void LogNewRemotes(IEnumerable<ConnectionInfo> conns)
        {
            var lines = new StringBuilder();
            foreach (var c in conns.Where(x => x.IsExternal))
            {
                string key = c.ProcessName + "|" + c.RemoteAddress + ":" + c.RemotePort;
                if (_seenRemotes.Add(key))
                {
                    lines.AppendFormat("{0:yyyy-MM-dd HH:mm:ss};{1};{2};{3};{4};{5};{6}\r\n",
                        DateTime.Now, c.ProcessName, c.Pid, c.Local, c.RemoteAddress, c.RemotePort, c.State);
                }
            }

            if (lines.Length == 0 || ChkLog.IsChecked != true) return;

            string file = Path.Combine(_logDir, "polaczenia_" + DateTime.Now.ToString("yyyy-MM-dd") + ".csv");
            try
            {
                if (!File.Exists(file))
                    File.WriteAllText(file, "czas;proces;pid;lokalny;zdalny_ip;zdalny_port;stan\r\n", Encoding.UTF8);
                File.AppendAllText(file, lines.ToString(), Encoding.UTF8);
            }
            catch (Exception ex)
            {
                TxtStatus.Text = "Nie udalo sie zapisac dziennika: " + ex.Message;
            }
        }

        private void BtnRefresh_Click(object sender, RoutedEventArgs e) { RefreshConnections(); }

        private void ChkAuto_Changed(object sender, RoutedEventArgs e)
        {
            if (ChkAuto.IsChecked == true) _timer.Start(); else _timer.Stop();
        }

        private void Filter_Changed(object sender, RoutedEventArgs e) { ApplyFilter(); }

        private void GridConnections_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var c = GridConnections.SelectedItem as ConnectionInfo;
            if (c != null) TxtTarget.Text = c.RemoteAddress;
        }

        private void BtnOpenLog_Click(object sender, RoutedEventArgs e)
        {
            Process.Start("explorer.exe", _logDir);
        }

        // ---------- Informacje o IP ----------

        private async void BtnInfo_Click(object sender, RoutedEventArgs e)
        {
            string ip = TxtTarget.Text.Trim();
            if (ip.Length == 0 || _busy) return;
            SetBusy(true, "Pobieranie informacji o " + ip + "...");
            try
            {
                var info = await Task.Run(() => IpInfoService.Lookup(ip));
                ShowInfo(info);
            }
            finally { SetBusy(false, "Gotowe."); }
        }

        private void ShowInfo(IpInfo i)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Adres:      " + i.Query);
            if (!string.IsNullOrEmpty(i.Error))
            {
                sb.AppendLine(i.Error);
            }
            else
            {
                sb.AppendLine("Kraj:       " + i.Country);
                sb.AppendLine("Miasto:     " + i.City + "  (przyblizone!)");
                sb.AppendLine("Operator:   " + i.Isp);
                sb.AppendLine("Organizacja:" + " " + i.Org);
                sb.AppendLine("AS:         " + i.AsInfo);
                sb.AppendLine("Odwr. DNS:  " + i.ReverseDns);
                sb.AppendLine();
                sb.AppendLine("Serwerownia / chmura: " + (i.Hosting ? "TAK" : "nie"));
                sb.AppendLine("Znany VPN / proxy / Tor: " + (i.Proxy ? "TAK" : "nie"));
                sb.AppendLine("Siec komorkowa: " + (i.Mobile ? "TAK" : "nie"));
                sb.AppendLine();
                if (i.Hosting || i.Proxy)
                    sb.AppendLine("UWAGA: to prawdopodobnie posrednik (serwer, VPN, proxy), a nie komputer domowy osoby.");
                sb.AppendLine("Zglaszanie naduzyc: skontaktuj sie z operatorem (" + i.Isp +
                              ") przez adres abuse z bazy WHOIS lub zglos sprawe na Policji / CERT Polska (incydent.cert.pl).");
            }
            _lastInfoText = sb.ToString();
            TxtInfo.Text = _lastInfoText;
        }

        // ---------- Traceroute ----------

        private async void BtnTrace_Click(object sender, RoutedEventArgs e)
        {
            string target = TxtTarget.Text.Trim();
            if (target.Length == 0 || _busy) return;

            _hops.Clear();
            SetBusy(true, "Sledzenie trasy do " + target + "...");
            try
            {
                await Task.Run(() =>
                {
                    foreach (var hop in TraceRoute.Trace(target))
                    {
                        var h = hop;
                        Dispatcher.Invoke(() =>
                        {
                            _hops.Add(h);
                            TxtStatus.Text = "Przeskok " + h.Ttl + ": " + h.Address;
                        });
                    }
                });
                TxtStatus.Text = "Trasa zakonczona. Przeskokow: " + _hops.Count +
                                 ". Kliknij adres w tabeli trasy i uzyj 'Informacje o IP'.";
            }
            catch (Exception ex)
            {
                TxtStatus.Text = "Blad traceroute: " + ex.Message;
            }
            finally { _busy = false; ToggleButtons(true); }
        }

        private void GridHops_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var h = GridHops.SelectedItem as HopInfo;
            if (h != null && h.Address != "*" && h.Address != "-") TxtTarget.Text = h.Address;
        }

        // ---------- Raport ----------

        private void BtnSaveReport_Click(object sender, RoutedEventArgs e)
        {
            var sb = new StringBuilder();
            sb.AppendLine("RAPORT STRAZNIK SIECI - " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("Komputer: " + Environment.MachineName);
            sb.AppendLine("Cel: " + TxtTarget.Text);
            sb.AppendLine();
            sb.AppendLine("=== Informacje o adresie ===");
            sb.AppendLine(_lastInfoText);
            sb.AppendLine("=== Trasa pakietow ===");
            foreach (var h in _hops)
                sb.AppendLine(string.Format("{0,3}  {1,-16} {2,-8} {3,-12} {4}", h.Ttl, h.Address, h.Czas, h.Status, h.HostName));
            sb.AppendLine();
            sb.AppendLine("=== Polaczenia z Internetem w chwili zapisu ===");
            foreach (var c in _all.Where(x => x.IsExternal))
                sb.AppendLine(string.Format("{0,-22} PID {1,-6} {2,-22} -> {3,-22} {4}", c.ProcessName, c.Pid, c.Local, c.Remote, c.State));

            string file = Path.Combine(_logDir, "raport_" + DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss") + ".txt");
            File.WriteAllText(file, sb.ToString(), Encoding.UTF8);
            TxtStatus.Text = "Zapisano raport: " + file;
        }

        // ---------- Pomocnicze ----------

        private void SetBusy(bool busy, string status)
        {
            _busy = busy;
            ToggleButtons(!busy);
            TxtStatus.Text = status;
        }

        private void ToggleButtons(bool enabled)
        {
            BtnInfo.IsEnabled = enabled;
            BtnTrace.IsEnabled = enabled;
        }

        protected override void OnClosed(EventArgs e)
        {
            _timer.Stop();
            base.OnClosed(e);
        }
    }
}

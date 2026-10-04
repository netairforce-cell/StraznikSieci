using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Media;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace StraznikSieci
{
    public partial class MainWindow
    {
        private readonly DispatcherTimer _guardTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        private readonly AnomalyDetector _detector = new AnomalyDetector();
        private readonly ObservableCollection<AlertInfo> _alerts = new ObservableCollection<AlertInfo>();
        private List<SessionInfo> _sessions = new List<SessionInfo>();

        private void InitGuard()
        {
            GridAlerts.ItemsSource = _alerts;
            _guardTimer.Tick += (s, e) => GuardScan();
            _guardTimer.Start();
            Loaded += (s, e) => GuardScan();
        }

        private void GuardScan()
        {
            try
            {
                if (ChkGuard.IsChecked != true) return;
                _all = TcpTable.GetTcpConnections();
                _sessions = SessionMonitor.GetSessions();
                GridSessions.ItemsSource = _sessions.Where(x => x.IsActiveUser).ToList();

                foreach (var a in _detector.Analyze(_all, _sessions))
                {
                    _alerts.Insert(0, a);
                    if (a.Level == "WYSOKI") OnHighAlert(a);
                }
                TxtGuardStatus.Text = string.Format("Straz: {0:HH:mm:ss}, sesji: {1}, alertow: {2}",
                    DateTime.Now, _sessions.Count(x => x.IsActiveUser), _alerts.Count);
            }
            catch (Exception ex)
            {
                TxtGuardStatus.Text = "Blad strazy: " + ex.Message;
            }
        }

        private async void OnHighAlert(AlertInfo a)
        {
            SystemSounds.Hand.Play();
            TabMain.SelectedItem = TabAlerts;
            if (string.IsNullOrEmpty(a.Ip) || NetUtil.IsPrivate(a.Ip)) { SaveAlertReport(a); return; }

            // automatyczne zebranie dowodow: informacje o IP + trasa
            string evidence = await Task.Run(() =>
            {
                var sb = new StringBuilder();
                try
                {
                    var i = IpInfoService.Lookup(a.Ip);
                    sb.AppendLine("Kraj: " + i.Country + ", miasto: " + i.City + " (przyblizone)");
                    sb.AppendLine("Operator: " + i.Isp + ", organizacja: " + i.Org + ", AS: " + i.AsInfo);
                    sb.AppendLine("Serwerownia: " + (i.Hosting ? "TAK" : "nie") + ", VPN/proxy: " + (i.Proxy ? "TAK" : "nie"));
                    sb.AppendLine();
                    foreach (var h in TraceRoute.Trace(a.Ip, 20, 1500))
                        sb.AppendLine(string.Format("{0,3}  {1,-16} {2,-8} {3}", h.Ttl, h.Address, h.Czas, h.HostName));
                }
                catch (Exception ex) { sb.AppendLine("Blad zbierania danych: " + ex.Message); }
                return sb.ToString();
            });
            a.Evidence = evidence;
            SaveAlertReport(a);
        }

        private void SaveAlertReport(AlertInfo a)
        {
            try
            {
                string file = Path.Combine(_logDir, "incydent_" + a.Time.ToString("yyyy-MM-dd_HH-mm-ss") + ".txt");
                File.WriteAllText(file, AnomalyDetector.BuildReport(a, _all, _sessions), Encoding.UTF8);
                TxtGuardStatus.Text = "Automatycznie zapisano raport: " + file;
            }
            catch (Exception ex) { TxtGuardStatus.Text = "Nie zapisano raportu: " + ex.Message; }
        }

        private void BtnSessRefresh_Click(object sender, RoutedEventArgs e) { GuardScan(); }

        private void BtnSessMsg_Click(object sender, RoutedEventArgs e)
        {
            var s = GridSessions.SelectedItem as SessionInfo;
            if (s == null) { TxtGuardStatus.Text = "Zaznacz sesje."; return; }
            bool ok = SessionMonitor.SendMessage(s.SessionId, "Komunikat bezpieczenstwa",
                "Ta sesja jest monitorowana. Twoj adres i trasa polaczenia zostaly zapisane. " +
                "Nieautoryzowany dostep jest przestepstwem (art. 267 KK) i zostanie zgloszony do CERT Polska i Policji.");
            TxtGuardStatus.Text = ok ? "Wyslano komunikat do sesji #" + s.SessionId : "Nie udalo sie wyslac komunikatu (moze trzeba uruchomic jako administrator).";
        }

        private void BtnSessKick_Click(object sender, RoutedEventArgs e)
        {
            var s = GridSessions.SelectedItem as SessionInfo;
            if (s == null) { TxtGuardStatus.Text = "Zaznacz sesje."; return; }
            if (!s.IsRemote) { TxtGuardStatus.Text = "Rozlaczanie dozwolone tylko dla sesji zdalnych."; return; }
            if (MessageBox.Show("Wylogowac sesje #" + s.SessionId + " (" + s.User + ")? Niezapisane dane tej sesji przepadna.",
                    "Potwierdz", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            bool ok = SessionMonitor.Logoff(s.SessionId);
            TxtGuardStatus.Text = ok ? "Wylogowano sesje #" + s.SessionId : "Nie udalo sie (uruchom jako administrator).";
            GuardScan();
        }

        private void BtnCert_Click(object sender, RoutedEventArgs e)
        {
            var a = GridAlerts.SelectedItem as AlertInfo;
            if (a == null) { TxtGuardStatus.Text = "Zaznacz alert na liscie."; return; }
            string report = AnomalyDetector.BuildReport(a, _all, _sessions);
            Clipboard.SetText(report);
            SaveAlertReport(a);
            Defense.OpenCert();
            TxtGuardStatus.Text = "Raport skopiowany do schowka - wklej go (Ctrl+V) w formularzu CERT Polska.";
        }

        private void BtnBlock_Click(object sender, RoutedEventArgs e)
        {
            var a = GridAlerts.SelectedItem as AlertInfo;
            if (a == null || string.IsNullOrEmpty(a.Ip)) { TxtGuardStatus.Text = "Zaznacz alert z adresem IP."; return; }
            if (NetUtil.IsPrivate(a.Ip)) { TxtGuardStatus.Text = "Nie blokuje adresow lokalnych."; return; }
            if (MessageBox.Show("Dodac regule zapory blokujaca " + a.Ip + "?", "Potwierdz",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            TxtGuardStatus.Text = Defense.BlockIp(a.Ip) ? "Regula zapory dodana dla " + a.Ip : "Nie dodano reguly (odmowa UAC lub zly adres).";
        }
    }
}

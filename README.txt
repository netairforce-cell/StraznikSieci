STRAZNIK SIECI - aplikacja WPF (.NET Framework 4.8.1, C# 7.3)

URUCHOMIENIE
1. Otworz StraznikSieci.sln w Visual Studio (2019 lub 2022).
2. Jesli VS zglosi brak ".NET Framework 4.8.1 targeting pack":
   doinstaluj go w Visual Studio Installer ALBO w pliku StraznikSieci.csproj
   zmien v4.8.1 na v4.8 (kod dziala tak samo).
3. F5. Nie trzeba zadnych pakietow NuGet.
   Zeby widziec nazwy wszystkich procesow (takze systemowych), uruchom VS / program jako administrator.

CO ROBI
- Pokazuje wszystkie polaczenia TCP komputera (jak netstat -ano) z nazwa programu.
- Kazdy NOWY adres z Internetu dopisuje do dziennika:
  Dokumenty\StraznikSieci\polaczenia_RRRR-MM-DD.csv
- "Informacje o IP": kraj, operator, AS, odwrotny DNS, czy adres to serwerownia/VPN/proxy
  (publiczne dane z ip-api.com, limit ok. 45 zapytan/min).
- "Sledz trase": traceroute (ICMP z rosnacym TTL) - kliknij przeskok, zeby sprawdzic jego IP.
- "Zapisz raport": plik TXT z informacjami, trasa i polaczeniami - np. do zgloszenia na Policje / CERT Polska.

WAZNE OGRANICZENIA
- Program widzi tylko adres, z ktorym laczy sie TWOJ komputer. Jesli "gosc" uzywa VPN, proxy,
  Tora albo serwera w chmurze - zobaczysz posrednika, nie jego dom. Ustalic osobe moze tylko
  Policja (przez operatora). Program nic nie atakuje ani nie skanuje - tylko czyta i pyta publiczne bazy.
- Na maszynie wirtualnej (NAT) pierwszy przeskok to wirtualna brama hosta (np. 10.0.2.2 w VirtualBox).
- Wiele routerow nie odpowiada na ICMP - "brak odpowiedzi" w trasie jest normalne.
- Obsluguje IPv4 (wiekszosc polaczen).

NOWE W TEJ WERSJI
- Zakladka "Sesje uzytkownikow": lista zalogowanych (konsola / RDP), ocena "GOSC ZDALNY!",
  przyciski: komunikat do sesji, wylogowanie sesji zdalnej (za potwierdzeniem).
- Zakladka "Alerty": pasywne wykrywanie anomalii (zdalna sesja, polaczenie przychodzace z Internetu
  na port nasluchujacy, otwarte ryzykowne porty, proces laczacy sie z bardzo wieloma adresami).
  Alert WYSOKI = dzwiek + automatyczne zebranie danych o IP i traceroute + zapis raportu
  (Dokumenty\StraznikSieci\incydent_*.txt).
- "Zglos do CERT Polska": kopiuje raport do schowka i otwiera https://incydent.cert.pl/ (wklej Ctrl+V).
- "Zablokuj IP w zaporze": regula Zapory Windows (z potwierdzeniem i zgoda UAC).
- Do wylogowania sesji / komunikatu moze byc potrzebny administrator.

NIE ZROBIONE JESZCZE: poczekalnia / sekretariat / wirtualny system (plan w nastepnej kolejnosci).

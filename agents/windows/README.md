# Windows cihaz durum ajanı — pilot sürüm

Bu sürüm Windows 10/11, Windows PowerShell 5.1 ve etkileşimli kullanıcı oturumu
hedefler. Sunucu ve mevcut NetShield paneli aynı Linux makinesinde, aynı ayar
dosyasını kullanır. Windows üzerinde gerçek çalışma testi henüz yapılmamıştır;
önce aşağıdaki pilot kontrolleri tamamlayın. Bu bir Windows servisi veya hazır MSI değildir.

## Neler bildirilir?

- Windows'un bildirdiği son açılış zamanı (`Win32_OperatingSystem.LastBootUpTime`).
- Ajan başlama/durdurma, oturum kilidi/açılması, uyku/uyanma ve alınabilen oturum kapatma olayları.
- 30 saniyede bir durum mesajı; sunucunun kaydettiği son bağlantı zamanı.

90 saniye bildirim gelmezse panel **Bağlantı kesildi / kapanış bilinmiyor** gösterir.
Pencerenin kapanması **ajanın durmasıdır**, PC'nin kapanması değildir. Ani kapanış,
ağ kesintisi ve uyku birbirinden kesin ayrılmaz. Windows hızlı başlatma nedeniyle
son açılış zamanı fiziksel güç düğmesine basılma zamanı olmayabilir. İlk kilit
olayına kadar oturum durumu bilinmiyor kalır. Kilit açık olması kişinin çalıştığını
kanıtlamaz; mesai/üretkenlik ölçümü yapılmaz. RDP/çok kullanıcılı oturumlar pilotta
ayrıca değerlendirilmelidir; oturum bazlı kişi kimliği doğrulanmaz.

Uygulama listesi, ekran, klavye, dosya, tarayıcı geçmişi toplanmaz. Ad/bölüm
ajan yapılandırmasına konmaz. Cihaz kimliğiyle envantere bağlanır; IP değişimi ajan
eşleştirmesini bozmaz, ancak pasif paket filtresinin IP kaydı elle güncellenmelidir.

## 1. Panelde cihaz oluşturun

**Cihazlar ve bağlantılar → Çalışan / cihaz envanteri → Ekle** üzerinden kaydedin.
Ajan cihazı için IP isteğe bağlıdır; IP yalnız pasif paket eşleştirmesinde kullanılır.
Kaydetme sonrasında eşleştirme penceresi açılır: alıcı HTTPS adresini girin, yeni
yapılandırma dosyasını oluşturun ve Windows bilgisayara güvenli biçimde aktarın.
Dosya oluşturmak mevcut cihaz anahtarını yeniler. Var olan dosyanın üstüne yazılmaz.
Bu işlem GUI paket raporu dışa aktarımından ayrıdır; cihaz eşleştirme işlemidir.
**Windows cihaz durumu** sekmesinde kaydı seçince cihaz kimliği görünür. Ajan sekmesi
canlı/simülasyon paket filtrelerinden bağımsızdır; sahte demo ajan kaydı oluşturulmaz.

## 2. Alıcıyı hazırlayın (Linux)

GUI eşleştirme penceresinde dosya oluşturduysanız `enroll` komutunu tekrar
çalıştırmayın; yeni anahtar üretip önceki dosyayı geçersiz kılar. Aşağıdaki `enroll`
satırı komut satırı kullanımı için alternatiftir. `serve` adımı yine gereklidir.

Kurumsal CA veya güvenilen bir CA tarafından imzalanmış, sunucu DNS adını SAN
alanında içeren sertifika ve özel anahtar hazırlayın. Windows istemcisi bu CA'ya
güvenmelidir. Sertifika doğrulamasını devre dışı bırakmayın. Aşağıdaki adresler
örnektir; kuruluşunuzdaki gerçek adres/dosya yollarıyla değiştirin.

Proje dizininde önce `docs/RECEIVER_OPERATIONS.md` içindeki sanal ortam ve
`requirements-receiver.txt` kurulumunu tamamlayın. Ardından:

```bash
.venv/bin/python -m netshield.agent_receiver --settings /path/to/settings.json enroll \
  --device-id PANELDEKI_KIMLIK \
  --server https://netshield.company.example:8443 \
  --output /private/location/agent-config.json

.venv/bin/python -m netshield.agent_receiver --settings /path/to/settings.json serve \
  --bind 192.168.1.10 --port 8443 \
  --cert /private/location/server.crt --key /private/location/server.key
```

`--settings` verilmezse mevcut kullanıcının `~/.config/netshield/settings.json`
(veya XDG_CONFIG_HOME) dosyası kullanılır. Paneli root ile başlatıyorsanız farklı
ayar dizini kullanabileceğini dikkate alın. Alıcı root gerektirmez. Varsayılan
bind `127.0.0.1` olduğundan başka bilgisayarlar için açıkça LAN adresi seçilmelidir.
Hiçbir firewall, port yönlendirme, DNS veya servis ayarı otomatik değiştirilmez.

Alıcı artık asenkron HTTPS ve işlemsel SQLite kullanır. Kurulum bağımlılığı,
kabul sınırları ve ölçülmüş yük sonuçları için [alıcı rehberine](../../docs/RECEIVER_OPERATIONS.md) bakın. Yalnızca şirketin
özel LAN/VPN erişimine açın. Aynı ayar dizininde tek alıcı çalıştırın ve eşleştirme
komutlarını sırayla yürütün. İnternete doğrudan yayın için üretim sunucusu,
merkezi yönetim ve yük testleri ayrıca gerekir.

## 3. Windows'ta görünür biçimde başlatın

`NetShield-Agent.ps1`, yanındaki **Core/AgentCore.cs** dosyası (klasör yapısı
korunarak) ve cihaza özel `agent-config.json` dosyasını güvenli bir yöntemle
bilgisayara aktarın. .NET Framework 4.7.2+ ve Windows PowerShell 5.1 gerekir. Yapılandırma bir erişim anahtarı içerir: Git'e veya
ortak paylaşım alanına koymayın, NTFS izinlerini kullanıcı/yöneticiyle sınırlandırın.
Kurumsal script imzalama/yürütme politikanıza uygun olarak başlatın:

```powershell
powershell.exe -STA -File .\NetShield-Agent.ps1 -Config .\agent-config.json
```

Pencere hangi bilgilerin nereye gönderildiğini gösterir. **Ajanı durdur** veya
pencereyi kapatma gönderimi durdurur. Otomatik başlatma, gizli çalışma, servis
kurma veya yürütme politikası atlatma uygulanmaz. Oturum açılmadan önce veya
ajan çalışmıyorken olaylar izlenmez. Sonraki çalıştırmada yalnızca son açılış
zamanı öğrenilir; aradaki olaylar Windows günlüğünden geriye dönük alınmaz.

Normal HTTPS sertifika/ad doğrulaması kullanılır; HTTP yönlendirmeleri izlenmez.
Proxy ve DNS davranışı Windows ağ ayarlarına tabidir. Ağ iletişimi C# işçisinde
çalışır; pencerenin timer işleyicisi ağ yanıtını beklemez. Tek gönderim aynı anda
çalışır, istek süresi 5 saniyeyle sınırlıdır. Hatalarda rastgele küçük gecikme
ile kademeli yeniden deneme (yaklaşık 2–61 saniye), kuyruk boşken 30 saniyelik
heartbeat, birikmiş kayıtlar için başarılı gönderimler arasında 2,5 saniye kullanılır.
Kapatma sırasında pencere en fazla 2 saniyelik son gönderim denemesi yapar, ardından
isteği iptal eder; Windows kapanışını bekletmez. Son mesajın ulaşması garanti değildir.

İlk `-Config` çalıştırmasında anahtar ve kuyruk, mevcut Windows kullanıcısına bağlı
DPAPI ile `%LOCALAPPDATA%\NetShield\Agent\CIHAZ_KIMLIGI\state.dat` içinde korunur.
Dizin ACL'si o kullanıcıyla sınırlandırılır. Sonraki çalıştırmada açık metin dosya
gerektirmez:

```powershell
powershell.exe -STA -File .\NetShield-Agent.ps1 -DeviceId PANELDEKI_KIMLIK
```

İlk içe aktarma JSON'u otomatik silinmez; hâlâ açık metin anahtar içerir. Çalışmayı
doğruladıktan sonra kurumunuzun güvenli saklama/silme politikasını uygulayın.
Anahtar değiştirirken aynı cihaz/sunucu için yeni dosyayı `-Config` ile içe aktarın;
bekleyen olaylar korunur. Başka cihaz/sunucu aynı kuyruğu kullanamaz.

Kuyruk diskte en fazla 1.000 olay / 7 gün tutar, mesaj başına ilk 100 olayı gönderir.
Teslim onayı yalnız gönderilmiş olay kimliklerini kapsıyorsa o olaylar diskten silinir.
Onay alınmazsa kimlikleri değişmeden tekrar gönderilir. Yeni eklenen olaylar eski bir
bildirimin onayıyla silinmez. Kota/süre nedeniyle düşen olay sayısı pencere ve panelde
görünür. 7 günlük sınır cihaz saatine dayanır; cihaz saati yanlışsa saklama da etkilenir.
Disk doluluğu/bozuk veya çözülemeyen durum dosyası sessizce sıfırlanmaz. Bozuk dosyayı
koruyup kurumun kurtarma sürecini uygulayın. Kalıcı yazım bitmeden güç kesilirse
son olay yine kaybolabilir; bu sürüm tam fiziksel güç kaybı garantisi vermez.

## 4. Erişimi iptal edin

```bash
.venv/bin/python -m netshield.agent_receiver --settings /path/to/settings.json revoke --device-id PANELDEKI_KIMLIK
```

İptal sonraki istekte uygulanır. Panelde envanter kaydının silinmesi de sonraki
bildirimleri reddeder. Yeniden `enroll` yeni anahtar üretir, eski anahtarı geçersiz
kılar; yeni bir output yolu verin ve Windows yapılandırmasını güncelleyin.

## Veri saklama ve pilot kabul kontrolü

Alıcı ayar dizininde `agent-credentials.json` (anahtarların SHA-256 özetleri) ve
`agent-status.sqlite3` (cihaz başına en fazla 1.000 olay; panelde son 100) tutar.
Varsayılan saklama süresi sunucu alım saatine göre 30 gündür. Alıcı açıkken 60 saniyede
bir bakım yapılır. POSIX izinleri 0600; DB yazımları işlemseldir. Eski JSON tek sefer
aktarılır ve orijinali otomatik silinmez. Ayrıntılar ve sınırlamalar
[alıcı rehberinde](../../docs/RECEIVER_OPERATIONS.md).

Windows ajanının kalıcı kuyruğu ve anahtarı CurrentUser DPAPI ile korunur. Aynı
Windows hesabındaki yetkili/kötü amaçlı süreçler bu korumanın dışında değildir.
Anahtar kopyalanırsa cihaz taklit edilebilir; donanımsal kimlik veya
kurcalama koruması yoktur. Olaylar trafik JSON/HTML raporlarına eklenmez.

Pilot Windows bilgisayarında sırayla doğrulayın:

1. Doğru sertifika/anahtarla bildirim; yanlış sertifika/anahtarla reddetme.
2. Kilitleme/açma ve uyku/uyanma olaylarının zaman çizelgesine gelmesi.
3. Ajanı kapatınca PC kapanışı yerine ajan durduruldu gösterimi.
4. Ağ kesilince 90 saniye sonra kapanış bilinmiyor; geri gelince yeniden bağlantı.
5. Yeniden başlatma sonrası ajanı tekrar açınca açılış zamanının güncellenmesi.
6. IP değişiminde aynı envanter kimliğine bağlanma; anahtar iptalinde reddetme.

Alıcı/protokol/TLS ve panel testleri Linux'ta çalıştırılır:
`python3 -m unittest discover -s tests -v`.

API dayanakları: [SessionSwitch](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.systemevents.sessionswitch),
[PowerModeChanged](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.systemevents.powermodechanged),
[Windows açılış zamanı](https://devblogs.microsoft.com/scripting/powertip-get-the-last-boot-time-with-powershell/).

## Geliştirici ve Windows kabul testleri

```powershell
powershell.exe -NoProfile -File .\Test-Agent.ps1
```

Bu betik Windows DPAPI, korumalı kuyruk yeniden açma ve bozulmuş dosyanın reddini
sentetik verilerle kontrol eder; ağ bağlantısı veya servis kurulumu yapmaz.
Kilit/uyku/RDP etkileşimli kabul testlerinin yerine geçmez. Bu çalışma ortamında
betik yalnız sözdizimi açısından kontrol edildi, Windows üzerinde çalıştırılmadı.

Ortak C# çekirdeği Linux'ta .NET 10 SDK ile test edilebilir:

```bash
dotnet run --project agents/windows/Core.Tests/Core.Tests.csproj
dotnet build agents/windows/Core/AgentCore.csproj
.venv/bin/python scripts/test_agent_core_https.py --dotnet /path/to/dotnet
```

15 ortak çekirdek testi geçiyor; test koruyucusu DPAPI değildir. Framework 4.7.2
hedefiyle derleme ve PowerShell parser kontrolü geçmiştir. Gerçek C# HttpClient ile
Python HTTPS alıcısı testi güvenilmeyen TLS'de kuyruğun korunduğunu, güvenilen
sertifikayla yeniden başlatmada teslim edildiğini doğrular. Windows işletim sistemi
üzerindeki koruma/oturum/uyku/kapanış doğrulaması hâlâ zorunlu açık iştir.

## Oturum bağlamı ve güncelleme sırası

Olaylar gözlemci Windows oturum numarası ve olayın kaydedildiği açılış zamanı ile
saklanır. Güncel bildirimin oturum numarası ayrıca gönderilir: yeni açılışta veya
başka oturumda teslim edilen eski olayların bağlamı değiştirilmez. Panel son bildiren
oturumu gösterir; tüm RDP/yerel oturumların ortak durumunu hesaplamaz. Eski olaylara
sonradan oturum numarası atanmaz. Oturum numarası bir kişi kimliği değildir ve
Windows tarafından tekrar kullanılabilir; kullanıcı adı/SID toplanmaz.

Önce alıcı ve paneli, sonra ajanı güncelleyin. Yeni alanları tanımayan eski alıcı
isteği reddeder; ajan onaysız kuyruğu silmez. Alıcı SQLite şema 1/2'yi 3'e yükseltir.
Ajan korumalı durum dosyasını sürüm 1'den 2'ye yükseltir. Eski ajan sürüm 2 kuyruğu
reddeder; bu dosyalar eski sürüme doğrudan geri verilmemelidir. Otomatik downgrade
ve imzalı kurulum henüz uygulanmadı. Aynı cihaz anahtarını birden çok Windows
kullanıcı ajanına dağıtmak desteklenen çoklu oturum kurulumu değildir; merkezi servis
ve görünür oturum bileşeni hâlâ geliştirme işidir.

Windows servisinde oturum olayının kendi SessionId bilgisi korunmalıdır;
servis sürecinin Session 0 kimliği kullanıcı oturumu yerine yazılmamalıdır.
Dayanaklar: [ServiceBase](https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicebase),
[oturum bildiriminin kapsamı](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification).

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

`NetShield-Agent.ps1` ve o cihaza özel `agent-config.json` dosyasını güvenli bir
yöntemle bilgisayara aktarın. Yapılandırma bir erişim anahtarı içerir: Git'e veya
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
Proxy ve DNS davranışı Windows ağ ayarlarına tabidir. Hata durumunda 30 saniyede
bir yeniden denenir. En fazla 100 olay RAM'de bekler; süreç kapanırsa gönderilmeyen
olaylar kaybolabilir. Uyku/kapanış öncesi son mesajın ulaşması garanti edilmez.

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

Windows ajanının mevcut gönderim kuyruğu hâlâ RAM'dedir; kalıcı ajan kuyruğu henüz
uygulanmadı. Anahtar kopyalanırsa cihaz taklit edilebilir; donanımsal kimlik veya
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

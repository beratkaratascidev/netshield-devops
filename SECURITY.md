# NetShield yerel güvenlik tabanı

## Kapsam

NetShield seçilen arayüzde pasif trafik analizi yapar. Masaüstü pasif analiz bileşeninde
harici GeoIP, telemetri, bulut aktarımı, aktif tarama, uzaktan güncelleme veya
raporları tarayıcıda otomatik açma yolu bulunmaz. Diğer programların internet
bağlantısını, işletim sistemi trafiğini veya kullanıcının genel IP'sini değiştirmez.

Paketler tespit için kısa süreli bellekte işlenir. Arayüz/kuyruk kayıtlarına ham
bayt, uygulama yükü, HTTP URL ve MAC içeren özet yazılmaz. Kaynak/hedef IP ve
portlar yerel analiz için ekranda ve sınırlı bellekte bulunur. HTTP içeriklerinin
RAM'e hiç girmediği veya Python belleğinden güvenli silindiği iddia edilmez.

## Kullanıcı ve yönetici politikaları

| İşlem | Varsayılan Bireysel | Kurumsal |
|---|---|---|
| Yerel maskeli JSON/HTML | Açık | Kapalı |
| Maskeli özeti panoya kopyalama | Kapalı | Kapalı |
| Manuel IPv4 INPUT kuralı | Kapalı | Kapalı |
| Pasif analiz bileşeninden harici sorgu / ağ gönderimi | Yok | Yok |

Bireysel profilde pano ve firewall açıkça etkinleştirilebilir. Firewall için
ayrıca root yetkili canlı oturum gerekir; simülasyonda ve normal kullanıcıyla
çalışmaz. `sudo` çağrılmaz, shell metni yürütülmez. Eklenen kurallar oturuma özel
bir yorumla tanımlanır. Mevcut OS kuralları topluca silinmez. Görünümü temizlemek,
uygulamayı kapatmak veya bir izni kapatmak eklenmiş kuralları geri almaz.

Kullanıcı tarafından seçilen profil bir rol veya kimlik doğrulama sistemi değildir.
Kurum, kullanıcı tercihlerini sınırlamak için `/etc/netshield/policy.json`
dosyasını yönetebilir. `deploy/policy.example.json` üç işlemi de kapatan örnektir.
Bu geliştirme sırasında `/etc` veya gerçek firewall üzerinde değişiklik yapılmaz.

Yönetici tarafından dağıtım örneği:

```bash
sudo install -d -o root -g root -m 0755 /etc/netshield
sudo install -o root -g root -m 0644 deploy/policy.example.json /etc/netshield/policy.json
```

Politika root sahipliğinde, grup/diğer kullanıcılarca yazılamayan normal bir
JSON dosyası olmalıdır. Alanlar `allow_exports`, `allow_clipboard` ve
`allow_firewall`; değerler boolean'dır. `false` kullanıcı seçimini veto eder;
`true` kullanıcının kapattığı izni açmaz. Politika her hassas işlemde yeniden
okunur. Dosya varsa ama bozuk/uygunsuzsa üç işlem de kapatılır. Dosya yoksa
kullanıcı profili uygulanır. Bu nedenle dağıtım dizini de kullanıcıların yazma
hakkı olmayan yönetici denetimindeki bir konum olmalıdır.

Root, uygulama kodunu değiştirebilen kullanıcı veya başka bir program bu
uygulama politikasının güvenlik sınırı içinde değildir. Kurumsal kullanımda
kod/dependency dağıtımı, OS erişim kontrolü ve süreç bazlı ağ çıkış denetimi
ayrıca kurum tarafından yönetilmelidir. GUI halen canlı yakalama için root
isteyebilir; ayrı yetkisiz GUI / ayrıcalıklı yakalama servisi mimarisi bu sürümde yoktur.

## Dosya ve pano güvenliği

JSON/HTML yalnızca kullanıcı bir dosya seçtiğinde yazılır. Yazım atomiktir;
POSIX izinleri `0600` olur. Mevcut hedef sembolik bağlantıysa reddedilir.
Rapor CSP ile ağ kaynağı, script ve form işlemlerini kapatır; dinamik HTML
alanları escape edilir. Tarayıcı başlatılmaz.

IP'ler dosya başına yeni rastgele HMAC anahtarıyla takma kimliğe çevrilir.
Anahtar kaydedilmez. Aynı dosyada kaynaklar ilişkilendirilebilir; farklı
raporlarda doğrudan aynı kimlik kullanılmaz. Port, protokol, zaman ve ölçüm
metaverisi hâlâ hassas olabilir. Bu yöntem tam anonimlik garantisi değildir.

Dosya seçici, kullanıcıya işletim sisteminin sunduğu konumları gösterir.
Bulutla eşitlenen dizinler, ağ diskleri veya eşitlenen pano işletim sisteminin
ya da başka uygulamaların denetimindedir; NetShield bunları güvenilir biçimde
ayırt edemez. Dışarı aktarımın hiçbir biçimde istenmediği kurumlarda yönetici
politikasında export ve clipboard kapalı tutulmalıdır.

Ayar dosyası eşikler, tercihler ve takip IP'leri içerir; `0600` geçici dosya ve
atomik değiştirme kullanır. Trafik/alarm geçmişi otomatik diske kaydedilmez.
Disk şifreleme, ekran kilidi, swap/crash dump koruması ve hesap yetkileri OS
katmanına aittir. Eski sürümlerin ürettiği dosyalar bu değişiklikle silinmez.

## Doğrulama

`python3 -m unittest discover -s tests -v`

Testler politika vetosu ve hata durumunda kısıtlama, maskelerde tutarlılık ve
raporlar arası farklılık, içerik/IP sızıntısı, dosya izinleri, sembolik bağlantı
reddi, HTML escape/CSP, firewall önkoşulları ve GUI politika akışını denetler.
Bir HTTP işleme testinde Python soket gönderme/bağlanma/DNS çözümleme çağrıları
hata verecek biçimde kapatılır; işlem ve alarm tespiti yine çalışır.

Bu test, üçüncü taraf kütüphaneler veya işletim sistemi için kapsamlı bir ağ
sızıntısı sertifikası değildir. Gerçek firewall ve canlı ağ değişiklikleri
test sırasında yapılmaz. Kurumsal yayından önce ayrıcalık ayrımı, bağımlılık
incelemesi ve izole ortamda süreç ağ trafiği doğrulaması gerekir.

### Yerel çalışan / cihaz envanteri

Ad/cihaz adı, bölüm, IP ve isteğe bağlı arayüz eşleştirmeleri kullanıcıya ait
`settings.json` içinde atomik olarak, `0600` izinleriyle saklanır. Bunlar kişisel
veri içerebilir; dosya şifrelenmez ve bilgisayarın yetkili kullanıcısı/root tarafından
okunabilir. Envanter girdileri düzenlenebilir veya silinebilir; silme yedekleri
ya da dosya sistemindeki eski kopyaları güvenli biçimde yok etme garantisi vermez.

Envanter dışarıya gönderilmez ve mevcut JSON/HTML trafik dışa aktarımlarına ad/bölüm
alanları eklenmez. Trafik yakalama ve güvenlik politikası değişmez. IP kaydı tarama,
bağlantı denemesi veya uzak bilgisayara ajan kurulumu başlatmaz. Ağ görünürlüğü ve
IP atamasının doğruluğu yönetici tarafından sağlanmalıdır. Simülasyon kayıtları
mod filtresiyle ayrılabilir; çalışan takibinde **Canlı** kapsamını seçin.

### İsteğe bağlı Windows ajanı ve HTTPS alıcısı

Ayrı başlatılan Windows ajanı, yalnızca yöneticinin yapılandırdığı HTTPS sunucusuna
cihaz durum metaverisi gönderir. Bu, pasif analizden farklı ve açıkça etkinleştirilen
bir ağ aktarımıdır; bulut hizmeti kullanılmaz. Ajan/alıcının çalıştırılması GUI'deki
Bireysel/Kurumsal dışa aktarım politikasından bağımsızdır. Kurum bu özelliği
istemiyorsa ajan/alıcının dağıtımını ve ağ erişimini OS katmanında engellemelidir.
GUI kendi başına alıcı başlatmaz veya ajana bağlanmaz; yerel durum dosyasını okur.

Ajan anahtarları cihaz başınadır; sunucuda yalnız özetleri saklanır. HTTPS TLS 1.2+
ve sertifika doğrulaması zorunludur. Anahtar iptali ve envanter üyeliği her istekte
kontrol edilir. İstek boyutu/olay sayısı sınırlıdır; serbest içerik kabul edilmez.
Cihazın bildirdiği olay saatleri güvenilir sunucu saati olarak değerlendirilmez;
son görülme sunucunun alım saatidir. Bu pilot donanımsal kimlik doğrulama, çok
kiracılı RBAC, servis sürekliliği veya kurcalamaya dayanıklı denetim kaydı sağlamaz.
Saklama ve Windows pilot kontrol adımları: [ajan rehberi](agents/windows/README.md).

### Alıcı deposu ve eşzamanlılık güncellemesi

HTTPS alıcısı aiohttp ve SQLite WAL kullanır. Bildirimler commit sonrasında onaylanır;
aynı olay kimliği farklı içerikle kabul edilmez. Sınırlı etkin POST sayısı ve tek DB
işçisi kullanılır. Saklama varsayılanı 30 gün, cihaz başına 1.000 olay; panelde son
100 olaydır. Süre ve kayıt silme bakımı alıcı açıkken 60 saniyede bir çalışır.
Eski JSON otomatik aktarılır ancak kaynak dosya otomatik silinmez. DB varken eski
JSON'a sessiz geri dönüş yapılmaz. Disk okumaları GUI dışında yürütülür.
[Kurulum, protokol, testler ve sınırlar](docs/RECEIVER_OPERATIONS.md).

### Yerel eşleştirme penceresi

GUI ve CLI aynı eşleştirme işlevini kullanır. Her işlem OS dosya kilidiyle sıralanır;
cihaz anahtarı yenileme/iptali farklı cihaz kayıtlarını ezmez. Yeni yapılandırma
dosyası özel izinlerle ve yalnız dosya henüz yoksa oluşturulur; uygulamanın veri
dosyaları çıktı olarak seçilemez. Anahtar özeti kaydedilemezse yeni çıktı kaldırılır
ve mevcut anahtar değiştirilmez. İki dosya için süreç çökmesine dayanıklı tek bir
transaction garantisi yoktur: çıktı yazıldıktan sonra süreç çökerse henüz geçerli
olmayan bir yapılandırma kalabilir; yeni bir dosyaya yeniden eşleştirme yapılmalıdır.

Pencere anahtarı göstermez ve ağ isteği yapmaz. Bildirim kontrolü yerel alıcı kaydını
okur; sertifika/DNS tanılaması yapıldığı veya yeni anahtarın uzak Windows üzerinde
kullanıldığı tek başına kanıtlanmaz. Anahtar hâlâ Windows'a taşınacak JSON dosyasında
açık metindir. Ajan içe aktardıktan sonra yerel çalışma kopyası CurrentUser DPAPI
ile korunur; ilk JSON otomatik silinmez. Windows üzerindeki DPAPI doğrulaması henüz
gerçekleştirilmedi.

### Windows kalıcı kuyruk ve arka plan göndericisi

Windows ajanının C# bileşeni anahtar ve olay kuyruğunu kullanıcıya bağlı DPAPI ile
korur. Dizin ACL'si kullanıcıya sınırlanır; tek süreç kilidi çift ajan erişimini
engeller. Dosya geçici şifreli kopya, flush ve atomik değiştirmeyle yazılır; hata
olursa bellekteki durum eski kalır. Bozuk veri sessiz silinmez. Kuyruk 1.000 olay ve
7 günle sınırlıdır; kayıp sayacı saklanır ve bildirilir. İlk yapılandırma JSON'u,
anahtarın bellekteki kopyası, aynı hesaptaki süreçler veya OS yöneticisi bu dosya
korumasıyla tamamen korunmuş sayılmaz. Aynı hesabı paylaşan kişiler ayrılmaz.

Gönderim HttpClient üzerinden ayrı işçide, sertifika/ad doğrulaması ve yönlendirme
reddiyle yapılır. V2 teslim onayındaki kimlikler gönderilen küme ile eşleşmeden
kuyruk temizlenmez. Sunucuya isteğe bağlı `agent_state`, `pending_events` ve
`dropped_events` gönderilir. `agent_state` eski kuyruk olaylarından ayrıdır; önceki
oturumun durdurma olayını göndermek çalışan ajanı durmuş olarak göstermez.
SQLite şeması 1 → 2, geçmiş korunarak işlem içinde yükseltilir. Eski V1 istemciler
ve salt okunur şema 1 panel okuması desteklenir.

Bu aşamada Windows servisi/otomatik başlatma uygulanmış sayılmaz. Ortak çekirdek
Linux'ta, Framework hedefi derlenerek ve gerçek HTTPS entegrasyonuyla doğrulandı;
Windows DPAPI/NTFS ve etkileşimli oturum testleri için `agents/windows/Test-Agent.ps1`
ve ajan rehberindeki kabul adımları kullanılmalıdır.

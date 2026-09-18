# Kararlılık hedefinin uygulama ve doğrulama takibi

Tam kapsam: docs/STABILITY_REVIEW.md içindeki P0/P1/P2 maddeleri, ekran sadeleştirmesi,
performans ve yayın öncesi kontroller. Bu liste tamamlanmadan tüm hedef bitmiş sayılmaz.

| İş | Durum | Gerekli kanıt |
|---|---|---|
| Kayıt görünürlüğü | Tamamlandı | Tk Kaydet akışı, arama, sekme, hata regresyonları |
| Tek ekranlı cihaz ekleme/eşleştirme | Yerel sihirbaz uygulandı; otomatik Windows kurulum ve uzak TLS tanılama bekliyor | Tk: IP olmadan kayıt, dosya oluşturma, bildirim kontrolü, anahtar iptali; CLI ile ortak işlev |
| Windows servis ve görünür oturum bileşeni | Bekliyor | Windows yeniden başlatma, oturum yokken heartbeat, RDP |
| Ajan arka plan iletişimi ve iptal | Ortak çekirdek uygulandı/test edildi; gerçek WinForms testi bekliyor | Asenkron HttpClient, tek istek, iptal, sınırlı kapanış; C# core testleri |
| Kalıcı gönderim kuyruğu ve teslim onayı | Uygulandı; Windows disk/güç kesintisi testi bekliyor | Yeniden açma, yazım hatası, kota/süre, ACK, TLS başarısızlığı sonrası yeniden başlatma testleri |
| Üretim HTTP sunucusu ve sınırlı eşzamanlılık | Kod ve kısa yerel yük testi tamam; uzun süre/gerçek ağ bekliyor | aiohttp; TLS, yavaş istemci, taşma ve 10/100/500 sentetik cihaz testleri; receiver-load-results.json |
| İşlemsel durum/olay deposu ve saklama süresi | Uygulandı ve yerelde doğrulandı | test_agent_store: migration, rollback, concurrency, restart, retention; backup ayrı iş |
| Ayrıcalıklı yakalama yardımcısı | Bekliyor | Normal kullanıcıda yakalama, yetkisiz isteğin reddi |
| IP'den bağımsız ajan envanteri | Opsiyonel IP tamam; zaman damgalı IP eşleştirme bekliyor | Birden çok IP'siz kayıt, seçilen cihazda doğru işlem ve boş IP ile filtre güvenliği testleri |
| Roller, korumalı anahtar ve denetim izi | DPAPI/ACL kodu eklendi; gerçek Windows doğrulaması, roller ve denetim izi bekliyor | CurrentUser DPAPI; Windows smoke betiği; imza/hesap ayrımı açık |
| Yedek/geri yükleme | Bekliyor | Geri yüklenen verinin doğruluğu ve anahtar hariç tutma |
| Tanılama ve sürüm uyumluluğu | Ajan DNS/TLS/kimlik/ACK/kota kodları uygulandı; birleşik tanılama ekranı bekliyor | Core hata sınıflandırma, DB 1→2 geçmiş koruma, V1/V2 testleri |
| Başlangıç oturum bilgisi ve saat sapması | Olay oturum/açılış bağlamı uygulandı; başlangıç kilit bilgisi, servis ve saat sapması bekliyor | Yeniden açma, geçmiş bağlamı, RDP/gerçek Windows ve saat ileri/geri testleri |
| Tespit eşik/istisna/tekrar yönetimi | Bekliyor | Etiketli normal ve anormal trafik ölçümü |
| İmzalı kurulum ve geri alma | Bekliyor | İmza zinciri + Windows yükleme/kaldırma/upgrade |
| Ana gezinme ve tek cihaz ayrıntısı | Bekliyor | Temel görevler, boş durum, klavye/DPI testleri |
| GUI dışında okuma/özet ve indeksleme | Okuma işçisi ve indeksleme tamam; tüm ağır özetleri ayırma/uzun süre bekliyor | Bloke okuma sırasında Tk callback testi; eşdeğer sonuçla 234 ms → 5,4 ms özet hesabı |
| Windows kabul testleri | Bekliyor | Gerçek Windows 10/11 test çıktıları |
| Uzun süre ve yük/arıza testleri | Bekliyor | Zaman, kaynak, gecikme ve veri kaybı ölçümleri |

İlk incelemede Windows, PowerShell, .NET SDK ve dumpcap yoktu. Ortak ajan
çekirdeğini doğrulamak için .NET 10 SDK ve PowerShell 7 parserı geçici dizine kuruldu.
Windows işletim sistemi ve dumpcap hâlâ yok.
Bu durum kod geliştirmesine engel değildir; ilgili gerçek platform doğrulaması için
ayrı ortam gerekecek. Anahtar/sertifika üretimi ve paket imzası test sertifikası ile
kurumsal güvenilir imza olarak eşitlenmeyecek.

18 Eylül 2026: 89 otomatik test geçti (sanal ortamda aiohttp dahil). Değişiklikler
Windows ajanının servis/kalıcı kuyruk/korumalı anahtar eksiklerini çözmüş sayılmaz.

Eşleştirme/opsiyonel IP adımı sonrası 96 test geçti. Yerel sihirbazın görünümü
gerçek Tk penceresinden alınan görüntüyle kontrol edildi; callback hatası oluşmadı.

Windows ajan çekirdeği aşaması: 98 Python testi + 13 C# çekirdek testi başarılı.
.NET Framework 4.7.2 derlemesi 0 hata/0 uyarı. PowerShell betikleri parser kontrolünden
geçti. Gerçek C# → HTTPS → Python → SQLite testi, güvenilmeyen TLS'de kuyruk koruma
ve güvenilen sertifikayla tekrar teslimi doğruladı. Testteki yerel koruyucu Windows
DPAPI taklidi olarak başarı sayılmaz; gerçek Windows kabulü açık kalır.

Oturum bağlamı aşaması: 101 Python testi, 15 C# testi; geçmiş olayın oturum/açılış
bilgisini yeni bildirimden ayrı koruma, değişmiş bağlamla aynı kimliği reddetme,
SQLite 1/2 → 3 ve kuyruk 1 → 2 geçişleri test edildi. Gerçek Tk testinde güncel
#7 oturumu ile geçmiş #2 oturumu ayrı gösteriliyor. Bu servis için veri sözleşmesi
hazırlığıdır; Windows servis hostu, görünür eşlikçi ve imzalı kurulum bitmiş değildir.

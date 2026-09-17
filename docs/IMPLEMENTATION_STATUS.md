# Kararlılık hedefinin uygulama ve doğrulama takibi

Tam kapsam: docs/STABILITY_REVIEW.md içindeki P0/P1/P2 maddeleri, ekran sadeleştirmesi,
performans ve yayın öncesi kontroller. Bu liste tamamlanmadan tüm hedef bitmiş sayılmaz.

| İş | Durum | Gerekli kanıt |
|---|---|---|
| Kayıt görünürlüğü | Tamamlandı | Tk Kaydet akışı, arama, sekme, hata regresyonları |
| Tek ekranlı cihaz ekleme/eşleştirme | Yerel sihirbaz uygulandı; otomatik Windows kurulum ve uzak TLS tanılama bekliyor | Tk: IP olmadan kayıt, dosya oluşturma, bildirim kontrolü, anahtar iptali; CLI ile ortak işlev |
| Windows servis ve görünür oturum bileşeni | Bekliyor | Windows yeniden başlatma, oturum yokken heartbeat, RDP |
| Ajan arka plan iletişimi ve iptal | Bekliyor | Ulaşılamayan sunucuda çalışan Durdur/GUI |
| Kalıcı gönderim kuyruğu ve teslim onayı | Bekliyor | Süreç çökmesi/ağ kesintisi sonrası tekrarsız teslim |
| Üretim HTTP sunucusu ve sınırlı eşzamanlılık | Kod ve kısa yerel yük testi tamam; uzun süre/gerçek ağ bekliyor | aiohttp; TLS, yavaş istemci, taşma ve 10/100/500 sentetik cihaz testleri; receiver-load-results.json |
| İşlemsel durum/olay deposu ve saklama süresi | Uygulandı ve yerelde doğrulandı | test_agent_store: migration, rollback, concurrency, restart, retention; backup ayrı iş |
| Ayrıcalıklı yakalama yardımcısı | Bekliyor | Normal kullanıcıda yakalama, yetkisiz isteğin reddi |
| IP'den bağımsız ajan envanteri | Opsiyonel IP tamam; zaman damgalı IP eşleştirme bekliyor | Birden çok IP'siz kayıt, seçilen cihazda doğru işlem ve boş IP ile filtre güvenliği testleri |
| Roller, korumalı anahtar ve denetim izi | Bekliyor | Yetki matrisi, iptal/yenileme ve sır sızıntısı testleri |
| Yedek/geri yükleme | Bekliyor | Geri yüklenen verinin doğruluğu ve anahtar hariç tutma |
| Tanılama ve sürüm uyumluluğu | Bekliyor | DNS/TLS/kimlik/şema/kota hatalarını ayırma |
| Başlangıç oturum bilgisi ve saat sapması | Bekliyor | RDP, kullanıcı geçişi, saat ileri/geri testleri |
| Tespit eşik/istisna/tekrar yönetimi | Bekliyor | Etiketli normal ve anormal trafik ölçümü |
| İmzalı kurulum ve geri alma | Bekliyor | İmza zinciri + Windows yükleme/kaldırma/upgrade |
| Ana gezinme ve tek cihaz ayrıntısı | Bekliyor | Temel görevler, boş durum, klavye/DPI testleri |
| GUI dışında okuma/özet ve indeksleme | Okuma işçisi ve indeksleme tamam; tüm ağır özetleri ayırma/uzun süre bekliyor | Bloke okuma sırasında Tk callback testi; eşdeğer sonuçla 234 ms → 5,4 ms özet hesabı |
| Windows kabul testleri | Bekliyor | Gerçek Windows 10/11 test çıktıları |
| Uzun süre ve yük/arıza testleri | Bekliyor | Zaman, kaynak, gecikme ve veri kaybı ölçümleri |

Bu çalışma ortamında Windows, PowerShell, .NET SDK ve dumpcap bulunmadığı doğrulandı.
Bu durum kod geliştirmesine engel değildir; ilgili gerçek platform doğrulaması için
ayrı ortam gerekecek. Anahtar/sertifika üretimi ve paket imzası test sertifikası ile
kurumsal güvenilir imza olarak eşitlenmeyecek.

18 Eylül 2026: 89 otomatik test geçti (sanal ortamda aiohttp dahil). Değişiklikler
Windows ajanının servis/kalıcı kuyruk/korumalı anahtar eksiklerini çözmüş sayılmaz.

Eşleştirme/opsiyonel IP adımı sonrası 96 test geçti. Yerel sihirbazın görünümü
gerçek Tk penceresinden alınan görüntüyle kontrol edildi; callback hatası oluşmadı.

# NetShield kararlılık ve kullanım incelemesi

Tarih: 17 Eylül 2026. Kapsam: mevcut kaynak kodu, yerel otomatik testler ve aşağıda
bağlantıları verilen resmi belgeler. Bu belge bir sertifikasyon veya tamamlanmış
Windows pilot testi değildir. Öneriler, mevcut uygulanan özelliklerden ayrıdır.

**Sonuç:** uygulama işlevsel bir prototip/pilot. Şirket geneline dağıtımdan önce
kurulum, ajan sürekliliği, olay teslimatı ve alıcı ölçeklenmesi tamamlanmalı.
Daha fazla grafik veya tespit türünden önce bunlara yatırım yapmak daha yararlı.

## Bu turda düzeltilen görünürlük sorunu

`netshield/ui/inventory.py::_save_device`, arama metnini koruyordu; eşleşmeyen
arama yeni kaydı gizleyebiliyordu. `_refresh_tracking`, takip sayfası açık değilse
çalışmıyordu. Windows durum tablosu da kayıt değişikliği sırasında hemen
yenilenmiyordu. Bunlar kod ve regresyon testleriyle doğrulanan hata yollarıdır;
kullanıcının ekranında hangisinin yaşandığı ayrıca gözlenmedi.

Kaydetme artık aramayı temizliyor, takip sayfasını açıyor, ilgili sekmede kalıyor,
iki tabloyu yeniliyor ve yeni kaydı seçip görünür konuma kaydırıyor. Ajan
bildirimi gelmeden de satır `Ajan verisi yok` durumuyla görülüyor. Windows sekmesine
`Cihaz ekle` eklendi; silme iki tabloya hemen yansıyor. Başarısız kayıtta arama ve
tercihler değişmiyor. 71 test başarılı; bunlardan biri gerçek Tk ekleme penceresindeki
Kaydet düğmesini çalıştırıyor. Gerçek Windows ajanı henüz çalıştırılıp doğrulanmadı.

Başka bir kullanıcıyla veya sudo ile açılan panel farklı settings.json kullanabilir.
Bu ayrı bir görünürlük nedeni olabilir; bu turda kullanıcının özel ayarları okunmadı
ve dizinleri otomatik birleştirilmedi. İleride görünür bir veri konumu/çalışma alanı
seçimi bu karışıklığı azaltmalı.

## Önceliklendirilmiş çalışma listesi

| Öncelik | Kodda görülen eksik | Önerilen değişiklik | Tamamlanma ölçütü |
|---|---|---|---|
| P0 | Ekleme, eşleştirme ve alıcı kurulumu farklı ekran/komutlarda | Cihaz ekleme sihirbazı: kayıt → ajan yapılandırması → bağlantı kontrolü | Teknik olmayan kullanıcı cihazı ekleyip ilk bildirimi aynı akışta görür; hata açıklaması sonraki adımı belirtir |
| P0 | Windows ajanı manuel ve pencereye bağlı | Yönetilen Windows servisi + kullanıcıya görünür oturum bileşeni; imzalı kurulum/kaldırma ve kurtarma davranışı | Yeniden başlatma ve kullanıcı oturumu olmadan temel heartbeat sürer; oturum bileşeni doğru kullanıcı oturumunu raporlar |
| P0 | `Send-Status` doğrudan WinForms timer ve kapanış işleyicisinde ağ çağrısı yapıyor | Arka planda sınırlı gönderim kuyruğu, iptal edilebilir istek, kademeli/rastgele gecikmeli tekrar deneme | Ulaşılamayan sunucuda pencere ve Durdur düğmesi yanıt vermeye devam eder |
| P0 | Gönderilmeyen en fazla 100 olay yalnız RAM'de; kapanışta kaybolabilir | OS erişim denetimli, boyut/süre sınırlı kalıcı kuyruk; olay kimliğiyle onay ve tekilleştirme | Ajan çökmesi/ağ kesintisi sonrası olaylar tekrarsız teslim edilir; kota aşımı sessiz veri kaybı yerine görünür sayaç üretir |
| P0 | Alıcı tek istek işler; her istekte tüm durum JSON'u yeniden yazılır | Üretime uygun HTTP sunucusu; sınırlandırılmış eşzamanlılık, tek yazıcı veri katmanı, sağlık ölçümleri | Yavaş/bozuk istemci diğer cihazları durdurmaz; hedef cihaz sayısında gecikme ve hata bütçesi sağlanır |
| P0 | Canlı yakalama ana uygulamada root gerektiriyor | Yakalamayı küçük ayrıcalıklı yardımcı sürece ayır; GUI ve dosya işlemleri normal kullanıcıda | GUI root olmadan çalışır; yetkisiz yakalama isteği reddedilir |
| P1 | Cihaz kimliği var ama IP zorunlu; pasif trafik ve ajan eşleştirmesi aynı formda | Ajan cihazını sabit kimlikle kaydet; IP'yi isteğe bağlı, zaman damgalı ağ eşleştirmesi yap | DHCP/IP değişiminde kişi kaydı bozulmaz; eski IP trafiği yanlış kişiye otomatik atfedilmez |
| P1 | Token düz metin istemci dosyasında; kurumsal kullanıcı rolleri ve işlem kaydı yok | Windows korumalı anahtar saklama, anahtar döndürme, yönetici/analist/okuyucu rolleri, yönetim denetim kaydı | Okuyucu cihaz/anahtar silemez; iptal sonrası bildirim reddedilir; işlemin kim tarafından yapıldığı görülebilir |
| P1 | Cihaz başına son 100 olay var; süre bazlı silme yok | Saklama süresi, silme/arsiv politikası, kontrollü yedek/geri yükleme; yerel SQLite aday | Süresi dolan veri silinir; geri yükleme testi geçer; anahtarlar rapor/yedeğe gelişigüzel katılmaz |
| P1 | Tek bir genel bağlantı hata metni | TLS, DNS, erişim reddi, alıcı durumu, kuyruk doluluğu ve sürüm uyumsuzluğu için ayrı tanılama | Sorun ve yapılacak işlem görünür; gizli anahtar/hassas içerik hata kaydına yazılmaz |
| P1 | Oturum bilgisi ilk olaya kadar bilinmiyor; kaynak zamanı istemciden | Başlangıç oturum sorgusu, oturum/başlatma kimliği, olay zamanı + alım zamanı, saat sapması işareti | RDP, kullanıcı değiştirme ve saat değişimi yanlış kişi/durum oluşturmaz |
| P2 | Sabit eşikler normal yoğun trafiği de işaretleyebilir | Tespit başına açıklama, istisna süresi, hizmet/ağ bazında eşik ve tekrar birleştirme | Etiketli normal/anormal trafik üzerinde yanlış alarm ve kaçırma oranı ölçülür |
| P2 | Dağıtım ve sürüm geçişi elle | İmzalı paketler, sürüm uyumluluğu, geri alma ve veri şeması geçişleri | Eski ajan yeni alıcıyla tanımlı biçimde çalışır veya anlaşılır hata verir |

Windows servisleri Session 0'da çalışır; mevcut pencereyi doğrudan servise dönüştürmek
kullanıcı oturumunu izlemeyi çözmez. Servis ile oturum bileşeni ayrı tasarlanmalıdır.
[Microsoft: Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services).
Servis kurtarma eylemleri kuruluma eklenebilir.
[Microsoft: Failure Actions](https://learn.microsoft.com/en-us/windows/win32/msi/msiserviceconfigfailureactions-table).

Mevcut alıcı Python `HTTPServer` tabanlıdır. Python belgeleri `http.server` modülünü
üretim için önermiyor; yalnızca TLS eklenmiş olması bunu değiştirmiyor.
[Python HTTP server](https://docs.python.org/3/library/http.server.html).
Eşzamanlı sunucuya geçerken paylaşılan Receiver durumuna sadece thread eklemek veri
yarışı yaratabilir; veri yazımı ayrıca tasarlanmalı.

## Kullanıcıya önerilen ekran düzeni

Ana gezinme: **Genel bakış · Cihazlar · Olaylar · Ağ analizi · Ayarlar**.
Ana iş akışı: **Cihaz ekle → ajanı eşleştir → ilk bildirimi doğrula → cihaz ayrıntısı**.

- Genel bakış: toplam cihaz, ajanı bağlı cihaz, bildirim bekleyen cihaz, bağlantısı
  kesilen cihaz ve yeni alarmlar. Her sayı ilgili filtreyi açmalı.
- Cihazlar: ad, bölüm, ajan durumu, son görülme ve eylemler. Arama/sıralama kalıcı;
  yeni kayıt arama nedeniyle gizlenirse kullanıcıya görünür açıklama sunulmalı.
- Cihaz ayrıntısı: Durum, Zaman çizelgesi, Ağ bağlantıları ve Eşleştirme bölümleri.
  Aynı cihazın bilgileri farklı listelerde aranmak zorunda kalmamalı.
- Boş ekran: yalnız boş tablo yerine `Henüz cihaz yok → Cihaz ekle` veya
  `Kayıt var, ajan bildirimi bekleniyor → Kurulumu kontrol et`.
- Durumlar: Kayıtlı, ilk bildirim bekleniyor, bağlı/kilitli, bağlı/kilidi açık,
  ajan durduruldu, bağlantı kesildi, veri okunamadı. Hata durumu çevrimdışıyla
  birleştirilmemeli. Eşleştirme/iptal durumu ayrı bir alan olmalı.
- Göreli zaman ve tam zaman beraber: `2 dk önce` ve ayrıntıda saat dilimli tarih.
  Yaşayan bilgisayar durumu ile sonlu trafik önizlemesi açıkça ayrılmalı.
- Ağ analizi: mevcut paket/arayüz/protokol araçlarını koru; şirket cihaz takibinin
  ana ekranını paket analizi kontrolleriyle doldurma.
- Klavye ile erişim, görünür odak, renk dışında metin/ikon durumları, yüksek DPI
  ve küçük ekran testleri; hata mesajlarında doğrudan düzeltilebilir alanı göster.

**Sadeleştirilmesi gerekenler:** Cihazlar, takip listesi ve envanterin ana gezinmede
tekrarı; normal kullanıcı akışındaki elle kimlik/komut kopyalama; simülasyon ile
canlı sayılarının varsayılan karışımı; ileri düzey firewall işlemlerinin ana takip
akışındaki ağırlığı. Özellikler gerektiğinde gelişmiş ağ analizi altında kalabilir.

**Eklenmemesi gerekenler:** `bağlantı yok = PC kapandı`, `kilit açık = çalışıyor`
çıkarımları; kanıtsız mesai/verimlilik puanları; bu kullanım amacına katkı sağlamayan
klavye/ekran/içerik toplama. Bunlar durum izleme sisteminin doğruluğunu artırmaz.
Windows hızlı başlatma da fiziksel açma/kapatma ile çekirdek açılışını farklılaştırır.
[Microsoft: System power states](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states).

## Performans ve veri mimarisi

Yerel tek ölçüm: 500 cihazın 2.000 sentetik paket üzerinde `device_activity`
çağrıları, alarm yokken **0,232 saniye** sürdü. Tk çizimi, disk ve ağ bu ölçümün
dışında; sonuç kapasite garantisi değildir. Kod her cihaz için tüm paketleri
tekrar tarıyor. IP/arayüz başına bir kez indeksleme ve özetleri GUI dışında üretme
öncelikli optimizasyon olmalı. Yalnız seçili cihazın ayrıntıları hesaplanmalı.

Panel `read_snapshot` ile dosyayı okuyup doğruluyor; büyük olay dosyalarında bu iş
GUI'de yapılmamalı. Dosya değişiklik kontrolü, arka planda okuma ve ana iş parçacığında
küçük tablo güncellemeleri kullanılmalı. Tk olay işleyicilerinin hızlı dönmesi
resmi belgelerde de vurgulanır.
[Python Tkinter threading model](https://docs.python.org/3/library/tkinter.html#threading-model).
WinForms için de ağ işi arka planda, kontrol güncellemesi UI iş parçacığında tutulmalı.
[Microsoft: thread-safe control calls](https://learn.microsoft.com/en-us/dotnet/desktop/winforms/controls/how-to-make-thread-safe-calls).

Yerel tek sunuculu başlangıç için SQLite WAL değerlendirmeye uygun: okuma ve yazma
birlikte ilerleyebilir fakat tek eşzamanlı yazıcı sınırı devam eder; ağ paylaşımı
üzerine birden fazla makineden WAL kullanımı uygun değildir. Çok sunuculu modelde
ayrı veritabanı hizmeti değerlendirilir. Bu bir mimari öneridir, şu an uygulanmadı.
[SQLite WAL](https://www.sqlite.org/wal.html).

Paket yakalamada ayrıcalık ayrımı Wireshark'ın da kullandığı yaklaşımdır. Mevcut
Tkinter arayüzünü tamamen başka teknolojiye taşımak bu ayrımı yapmak için gerekli
değildir. Önce iş yüklerini ayırmak daha küçük ve ölçülebilir bir değişikliktir.
[Wireshark capture architecture](https://www.wireshark.org/docs/wsdg_html_chunked/ChWorksCapturePackets).

## Yayın öncesi doğrulama sırası

1. Mevcut görünürlük ve CRUD regresyonları — bu turda geçti.
2. Gerçek Windows 10/11: kilitleme/açma, uyku, hızlı başlatma, normal yeniden başlatma,
   oturum kapatma, RDP ve kullanıcı değiştirme. Pilot cihazda henüz doğrulanmadı.
3. Kesinti testleri: ağ yok, DNS/TLS hatası, iptal edilmiş anahtar, sunucu yeniden
   başlatma, ajan çökmesi, disk dolması, bozuk durum dosyası, saat ileri/geri alınması.
4. Hedef olarak 10 → 100 → 500 ajan, normal ve eşzamanlı yeniden bağlanma yükü.
   Ölç: p95 bildirim gecikmesi, CPU/RAM, disk yazımı, reddedilen/kaybolan olaylar,
   UI yanıtı. Bunlar henüz yapılmış kapasite testleri değildir.
5. Önerilen kabul hedefi: cihaz kaydı kaydetme sonrası hemen görünür; sağlıklı ağda
   çoğu bildirim 5 saniye içinde işlenir; bağlantı kaybı 90 saniye + panel yenileme
   süresinde görünür; uzun çalışma boyunca kuyruk/bellek sınırları korunur. Hedefler
   kurumun gerçek cihaz sayısı ve ağ koşullarıyla doğrulanmalı.

Önerilen geliştirme sırası: önce görünürlük/kurulum, ardından ajan sürekliliği ve
olay teslimatı, sonra üretim alıcısı/veri saklama, en son gelişmiş analiz ve görsel
iyileştirmeler. Böylece her aşama bağımsız ve ölçülebilir biçimde teslim edilebilir.

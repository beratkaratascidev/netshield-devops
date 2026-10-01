# NetShield · 2 dakikalık demo rehberi

Bu akış, canlı ağ yakalama izni veya ayrı bir Windows bilgisayar gerektirmeden
NetShield'ın ana fikrini göstermek içindir. Simülasyon verisi ağa paket
göndermez.

## Hazırlık

```bash
python3 ids.py
```

Uygulama açıldığında **Simülasyon** modu seçili olmalıdır. Değilse üst araç
çubuğundan seçin ve yakalamayı başlatın.

## Sunum metni

| Süre | Ekrandaki işlem | Söylenebilecek kısa açıklama |
|---|---|---|
| 0:00–0:15 | Ana ekranı açın. | “NetShield, seçili yerel arayüzde pasif görünürlük sağlayan; bulut, telemetri ve aktif tarama kullanmayan bir masaüstü MVP'si.” |
| 0:15–0:35 | **Demo üret** düğmesini kullanın. | “Simülasyon gerçek tespit motorundan geçiyor; test ve sunum için ağ trafiği üretmiyor.” |
| 0:35–0:55 | **Alarmlar** sekmesinden Kritik/Yüksek filtresi uygulayın, bir alarmı seçin. | “Alarm; kaynak, hedef, eşik ve ölçüm bağlamını gösterir. Bu bir saldırı hükmü değil, inceleme sinyalidir.” |
| 0:55–1:15 | **Cihazlar ve bağlantılar** sekmesinde bir akışa çift tıklayın. | “Akış ve cihaz görünümü, pakete geri filtreleme yapıyor; yalnızca sınırlı bellekte tutulan önizlemeyi kullanıyor.” |
| 1:15–1:30 | **Yönetim denetim günlüğü** sekmesini açın. | “Ayar, cihaz ve anahtar işlemleri için sınırlı, salt okunur yerel audit kaydı var. Anahtar veya paket içeriği kaydedilmiyor.” |
| 1:30–1:45 | **Çalışma alanı → Yerel yedek oluştur** menüsünü gösterin. | “Kurtarma arşivi anahtarları hariç tutuyor; geri yükleme canlı kurulumu ezmek yerine yalnızca yeni bir klasöre yapılabiliyor.” |
| 1:45–2:00 | **Windows cihaz durumu** sekmesini açın. | “İsteğe bağlı ajan IP'ye bağlı olmadan, HTTPS üzerinden cihaz durum olaylarını bildirebiliyor. Bu kısım pilot seviyesinde ve gerçek Windows kabulü roadmap'te açık.” |

## Sunumda dürüstçe belirtilecek sınırlar

- Bu sürüm Wireshark alternatifi veya tam bir IDS/IPS değildir.
- Simülasyon, gerçek ağ veya Windows hizmeti testi yerine geçmez.
- Windows servis hostu, imzalı paket ve rol tabanlı yetkilendirme tamamlanmış
  özellikler değildir.
- Paket görünürlüğü, seçilen arayüzün gerçekten görebildiği trafikle sınırlıdır.

## Ekran görüntüsü listesi

Bir proje sayfası için şu üç gerçek ekran görüntüsü yeterlidir:

1. Demo üretildikten sonra paket ve alarm tabloları.
2. **Cihazlar ve bağlantılar** sekmesindeki akış/cihaz özeti.
3. **Yönetim denetim günlüğü** veya **Windows cihaz durumu** sekmesi.

Ekran görüntülerinde gerçek IP, cihaz adı, dosya yolu veya anahtar görünüyorsa
yayınlamadan önce maskeleyin. Simülasyon verisi bu amaç için daha uygundur.

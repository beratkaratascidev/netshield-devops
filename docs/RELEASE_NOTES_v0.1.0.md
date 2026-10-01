# NetShield v0.1.0 — MVP / pilot

Tarih: 1 Ekim 2026

## Kapsam

NetShield; Türkçe Tkinter arayüzüyle pasif ağ önizlemesi, eşik tabanlı alarm
üretimi, sınırlı cihaz/akış takibi ve yerel güvenlik iş akışlarını bir araya
getiren bir MVP'dir. İsteğe bağlı Windows ajanı, ayrı HTTPS alıcısına cihaz
durum olayları iletebilir.

Öne çıkanlar:

- IPv4/IPv6, TCP/UDP/DNS/HTTP/ICMP trafik özeti ve dokuz eşik tabanlı tespit.
- Sınırlı bellek/kuyruklar, atomik ayar yazımı ve hata regresyonları.
- IP'den bağımsız Windows cihaz eşleştirmesi, anahtar geçişi ve kalıcı olay
  kuyruğu için ortak çekirdek.
- Token, paket içeriği ve serbest metin içermeyen sınırlı yerel yönetim audit
  günlüğü ile salt okunur GUI görünümü.
- Anahtarları hariç tutan yerel yedekleme ve yalnız yeni bir klasöre geri
  yükleme; CLI ve GUI akışı.

## Doğrulama

```bash
python3 -W error::ResourceWarning -m unittest discover -s tests -q
```

Bu sürümde 124 test geçmektedir. HTTPS alıcı testleri için isteğe bağlı
bağımlılığı kurun:

```bash
python3 -m pip install -r requirements-receiver.txt
python3 -m unittest discover -s tests -p 'test_agent_http.py' -v
```

## Bilinen sınırlar

- Windows servis hostu/otomatik başlatma, imzalı kurulum ve gerçek Windows
  DPAPI/ACL kabulü tamamlanmamıştır.
- Rol tabanlı yetkilendirme ve merkezi/kurcalamaya dayanıklı audit sistemi yoktur.
- Tespitler inceleme sinyalidir; saldırı kanıtı veya otomatik müdahale kararı değildir.
- Uzun süreli gerçek ağ yükü ve yanlış alarm ölçümleri ayrı kabul ortamı gerektirir.

Tam takip: [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

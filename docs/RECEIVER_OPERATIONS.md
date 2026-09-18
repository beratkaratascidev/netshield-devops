# HTTPS alıcısı: kurulum, veri ve doğrulama

Alıcı `aiohttp` kullanır; masaüstü pasif analiz için bu ek bağımlılık gerekmez.
Bağımlılıkları sistem Python'una eklemek yerine proje ortamına kurun:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-receiver.txt
.venv/bin/python -m netshield.agent_receiver --settings /path/to/settings.json serve \
  --bind 192.168.1.10 --port 8443 --cert /private/server.crt --key /private/server.key \
  --retention-days 30 --max-inflight 128
```

Sertifika adı istemcideki sunucu adıyla eşleşmeli, CA istemcide güvenilir olmalıdır.
TLS 1.2 altı kapalıdır. Varsayılan bind loopback; ağ/firewall ayarları değiştirilmez.
`python3 -m venv` ensurepip hatası verirse dağıtımın Python venv paketini kurmak
veya hazır bir sanal ortam kullanmak gerekir. Bu depo sistem Python'una paket kurmaz.
Alıcı ve panel aynı settings.json dizinini kullanmalıdır; sudo farklı kullanıcı
ayarları seçebilir. Tek çalışma alanında tek alıcı çalıştırın.

## Davranış

- Ağ okuma asenkrondur. En fazla 128 etkin POST isteği kabul edilir; fazlası
  `503 receiver_busy` ve Retry-After döndürür. Bu, tüm TCP bağlantıları için bir
  işletim sistemi kotası değildir; ağ erişim sınırları ayrıca uygulanmalıdır.
- Gövde en fazla 32 KiB ve 100 olay; sıkıştırılmış/chunked gövdeler reddedilir.
  Gövde 5 saniyede tamamlanmazsa 408 döner. Tek DB işçisi, kabul sınırı sayesinde
  sınırsız büyümeyen bir iş kuyruğuyla veriyi yazar. Yavaş yükleme DB işçisini tutmaz.
- Envanter ve anahtar dosyaları değişmediyse doğrulanmış veri önbellekten kullanılır.
  Inode, boyut, mtime/ctime veya izin değişimi önbelleği geçersiz kılar. İptal ve
  kayıt silme bir sonraki yetkilendirme kontrolünde geçerlidir; yazımdan önce
  yetkilendirme tekrarlanır.
- `POST /v1/status/{device_id}` eski ajanla uyumlu 204 cevabını korur.
- `POST /v2/status/{device_id}` aynı gövdeyi alır; yalnız DB commit sonrasında
  `{code:"accepted",protocol:2,accepted_event_ids:[...]}` cevabı verir.
- Olay kimliği saklanan kapsamda tekildir. Aynı kimlikle farklı içerik gönderilirse
  tüm bildirim geri alınır. ACK kaybolursa istemci aynı kimlikle tekrar deneyebilir.
  Saklama süresi/kotasıyla silinmiş olaylar için sonsuz tekilleştirme garantisi yoktur.
- `GET /healthz` veri veya kimlik içermeyen hazır/depo hatası yanıtıdır. Arka plandaki
  bakım son sonucunu gösterir; anlık disk yazılabilirliği veya yük garantisi değildir.
- 400/403/408/413/415/429/503 cevapları makine tarafından ayırt edilebilir hata kodları
  içerir. Hassas içerik ve anahtarlar HTTP erişim günlüğüne yazılmaz.

## Saklama ve eski sürümden geçiş

Ajan durumları `agent-status.sqlite3` içinde SQLite WAL ve işlemlerle tutulur.
POSIX dosya izinleri 0600; farklı kullanıcı veya açık izinli DB reddedilir.
Panel SQLite'ı salt okunur, arka plan işçisinden okur. WAL dosyası değişimi de
panel önbelleğini geçersiz kılar. Okuma hatası `Veri okunamadı` olarak gösterilir;
çevrimdışı veya kayıtsız cihaz gibi sunulmaz.

Alıcı ilk açılışta eski `agent-status.json` dosyasını doğrular ve tek işlemde
aktarır. Başarısız aktarım tamamlanmış işaretlenmez; veri düzeltildikten sonra tekrar
başlatılabilir. Şema sürümü bilinmiyorsa otomatik düşürme veya sessiz sıfırlama yapılmaz.
Aktarım sonrasında eski JSON otomatik silinmez; eski kopya içerdiğinden kurumun
saklama politikasına göre ayrıca kaldırılmalıdır. DB varken bozuk DB'yi gizlemek
amacıyla eski JSON'a geri dönülmez.

Varsayılan saklama 30 gündür (`--retention-days 1..365`). Sunucunun alım zamanı
kullanılır; istemci saatinin yanlış olması süreyi değiştirmez. Cihaz başına en
fazla 1.000 olay saklanır; panel son 100 olayı gösterir. Silinen cihaz kayıtları
ve süresi dolan veriler, alıcı açıkken en geç periyodik bakım çalışmasında
(60 saniye) temizlenir. Ayar dosyası kayıpsa/bozuksa bakım silmeyi durdurur.
Alıcı kapalıyken bakım çalışmaz. Silme disk/SSD/yedeklerde adli düzeyde güvenli
imha garantisi değildir. DB ve WAL/SHM dosyaları bütün olarak düşünülmelidir;
çalışan DB'nin yalnız ana dosyasını kopyalamak güvenilir yedek değildir.

Anahtar özetleri hâlâ ayrı `agent-credentials.json` dosyasındadır. Yönetici rolleri,
korumalı Windows anahtar deposu ve kontrollü yedek/geri yükleme sonraki işlerde;
bu değişiklik onları tamamlanmış saymaz.

## Doğrulama

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/benchmark_receiver.py --output docs/receiver-load-results.json
```

Yük aracı geçici sentetik cihazlar ve geçici test sertifikası kullanır; yalnız
loopback üzerinde dinler, gerçek kullanıcı yapılandırmasına dokunmaz. Her cihaz
bir bildirim gönderir, istemci eşzamanlılığı 64'tür. Gecikme, istemci sırasını da
kapsar. Ölçülen CPU/RAM aynı süreçteki istemci ve sunucunun toplamıdır.

18 Eylül 2026 yerel ölçümü:

| Cihaz | Bildirim başına olay | Kaydedilen olay | p95 süre |
|---|---:|---:|---:|
| 10 | 1 / 100 | 10 / 1.000 | 0,053 / 0,070 sn |
| 100 | 1 / 100 | 100 / 10.000 | 0,469 / 0,646 sn |
| 500 | 1 / 100 | 500 / 50.000 | 2,113 / 3,232 sn |

Ayrıntılı çıktı: `receiver-load-results.json`. Bu kısa yük testi gerçek Windows
ajanını, gerçek LAN/VPN gecikmesini, uzun süre çalışmayı veya tüm DoS koşullarını
kanıtlamaz. Bunlar IMPLEMENTATION_STATUS.md içinde açık işlerdir.

## Windows ajanı V2 tanılama alanları

Yeni ajan isteğe bağlı `agent_state` (`running`/`stopped`), `pending_events` ve
`dropped_events` alanlarını gönderir. Kuyruk sayıları bildirim hazırlanma anındandır.
Geçmişteki `agent_stopped` olayı, `agent_state=running` olan güncel istemciyi durdu
olarak göstermez. Bu alanlar SQLite şema 2'de saklanır; alıcı şema 1'i işlem içinde
yükseltir ve geçmişi korur. Şema 2 DB eski alıcıya doğrudan düşürülmemelidir.
Panel güncellemesi şema 1'i salt okunur açabilir. 1→2 geçişi yedek/geri alma tasarımının
tek başına tamamlandığı anlamına gelmez; kontrollü yedek/geri yükleme hâlâ ayrı iştir.

## Oturum bağlamı (şema 3)

İsteğe bağlı üst düzey `session_id`, son bildiren Windows oturumudur. Yeni olaylar
`session_id` ve `boot_time` alanlarını birlikte taşır; alan çifti eksikse istek
reddedilir. Sayısal oturum kimliği 0–2147483647 aralığında bir tamsayı olmalıdır.
Aynı olay kimliğiyle değiştirilmiş oturum/açılış bilgisi tüm yazımı geri aldırır.
Geçmiş bağlamı güncel bildirimin değerleriyle doldurulmaz.

Güncel alıcı şema 1/2'yi işlem içinde 3'e yükseltir; salt okunur panel eski şemaları
da okuyabilir. Geçmiş ve kuyruk tanılaması korunur. Yeni ajan eski alıcıya yeni alanlar
ile bildirim gönderirse reddedilir; önce alıcı/panel güncellenmelidir. Şema 3 dosyası
eski alıcıyla açılmamalıdır. Gerçek çoklu oturum servis kurulumu henüz desteklenmez.

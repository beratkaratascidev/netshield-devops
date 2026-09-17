# NetShield / DDO IDS

Python ve Tkinter ile IPv4 trafik izleme, ICMP/SYN/UDP yoğunluk alarmı,
port tarama tespiti ve HTML raporlama uygulaması.

## Çalıştırma

Python 3.10 veya üstü ve Tkinter gerekir. Scapy canlı paket yakalama için,
Matplotlib trafik grafiği için kullanılır. Bu iki paket olmadan da simülasyon
çalışır; Matplotlib yoksa grafik gösterilmez.

```bash
python3 ids.py
```

Linux'ta root yetkisi ve Scapy mevcutsa canlı dinleme başlar:

```bash
sudo python3 ids.py
```

Root yetkisi veya Scapy yoksa üretilmiş örnek olaylarla simülasyon çalışır.
Simülasyonun paketleri ağa gönderilmez. Manuel ban düğmesi ise her iki modda
da gerçek `sudo iptables` komutu çalıştırır; simülasyon bu işlemi taklit etmez.
Otomatik ban etkin değildir. Uygulama kapanırken eklenmiş firewall kuralları
kaldırılmaz. Ban listesi yalnızca mevcut uygulama oturumundaki işlemleri gösterir.

## Göstergeler ve tespit sınırları

- **PAKET:** Oturumda işlenen IPv4 paketlerinin toplamı; simülasyonda üretilen toplam.
- **PKT/SN:** Son ölçüm aralığındaki paket sayısının geçen süreye bölünmesi.
- **TOPLAM OLAY / FLOOD:** Bildirim sayılarıdır. Aynı kaynak ve tür için
  bildirimler bekleme aralığıyla sınırlandırılır; paket sayısına eşit değildir.
- HTTP Flood tespiti, TCP paketinin başında görülebilen HTTP/1 istek satırlarını
  sayar. HTTPS, HTTP/2 ve TCP parçalarının yeniden birleştirilmesi desteklenmez.
- Birden fazla arayüzde görülen aynı paket birden fazla sayılabilir.
- Eşikler `netshield/config.py` dosyasından düzenlenir.
- Rapor, kayıtlı olayları ve bulunabilen GeoIP bilgilerini içerir. Genel IP'ler
  için GeoIP sorguları `ip-api.com` servisine gönderilir.
- Sıfırla, arayüz sayaçlarını ve olay geçmişini temizler; firewall kurallarını
  ve motorun tespit pencerelerini değiştirmez.

## Test

```bash
python3 -m unittest discover -s tests -v
```

Testler gerçek firewall işlemi yapmadan ve ağ paketi göndermeden raporlamayı,
ban durumunu, trafik ölçümünü, HTTP alarmını ve motor yaşam döngüsünü denetler.

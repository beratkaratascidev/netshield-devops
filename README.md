# NetShield — Ağ Analizi

Türkçe, koyu temalı Tkinter masaüstü uygulaması. Seçilen ağ arayüzündeki
paketleri listeler; hız ve port çeşitliliği eşiklerine göre şüpheli trafik
alarmları üretir. Wireshark benzeri paket listesi ve ayrıntı düzeni sunar;
Wireshark'ın tüm protokol çözümleyicilerini veya filtre dilini içermez.

## Çalıştırma

Python 3.10+ ve Tkinter gerekir. Canlı dinleme için Scapy kurulmalıdır.
Grafik Tkinter Canvas kullanır; Matplotlib gerektirmez.

```bash
python3 ids.py
```

Root yetkisi veya Scapy yoksa ilk açılış simülasyon modundadır. Linux'ta canlı
inceleme için Scapy bulunan Python ortamıyla:

```bash
sudo python3 ids.py
```

Üst çubuktan **modu ve arayüzü** seçin. Seçimi değiştirmek için önce
**Durdur**, ardından **Başlat** düğmesini kullanın. Kayıtlar durdurulduğunda
korunur. Hatalı arayüz veya eksik yetki sistem günlüğünde gösterilir; canlı
mod sessizce simülasyona dönüştürülmez.

Yerel ağdaki bütün cihazların trafiği normal bir switch portuna ulaşmaz.
Uygulama seçili arayüzün görebildiği trafiği inceler. Diğer cihazlar için
switch üzerinde port aynalama/SPAN, bir TAP veya ilgili ağ geçidinden
ölçüm gerekebilir. Wi-Fi monitor-mode yapılandırması yapılmaz.

## Çalışma alanı

- **Paketler:** Zaman, kaynak/hedef, protokol, uzunluk ve paket özeti.
  TCP, UDP, HTTP/1, DNS, ICMP, ARP ve IPv6 görüntülenir.
- **Ayrıntılar:** Seçili paket için portlar, TCP bayrakları, yük ve ham
  paketin ilk 256 baytı; seçili alarm için ölçüm ve eşik.
- **Alarmlar:** Kaynak, hedef, tespit türü, önem ve ölçüm penceresi.
- **Akışı izle:** Otomatik kaydırmayı kapatarak eski kayıtları inceleyin.
- **Eşikler:** Yakalama durdurulunca değiştirilebilir. Sonraki başlatmada
  uygulanır; uygulama kapanınca varsayılanlara döner.
- **JSON dışa aktar:** Bellekteki paket önizlemeleri, alarmlar ve eşikler.
  Tam PCAP kaydı değildir. Filtre yalnızca görünümü etkiler; dışa aktarım
  bellekteki bütün kayıtları içerir.
- **HTML rapor:** Bellekte tutulan alarm geçmişi.

### Görüntüleme filtresi

```text
src=192.168.1. proto=TCP port=443
proto=DNS
info="GET /"
192.168.1.10
```

Alanlar: `src`, `dst`, `proto`, `port`, `info`. Birden fazla koşul **VE**
olarak birleştirilir. Adres ve metin koşulları alt metin arar; CIDR desteği
yoktur. `proto=TCP`, TCP üzerinde çözümlenen HTTP ve DNS kayıtlarını da
kapsar. Port hem kaynakta hem hedefte aranır. Geçersiz filtre, önceki geçerli
filtrenin yerine uygulanmaz. Filtreler alarm üretimini durdurmaz.

## Tespitler

| Tespit | Ölçülen davranış |
|---|---|
| ICMP | Aynı kaynak/hedef arasında IPv4 echo istek yoğunluğu |
| SYN | ACK içermeyen TCP SYN yoğunluğu |
| UDP | UDP paket yoğunluğu |
| HTTP Flood | Paketin başında görülebilen HTTP/1 istek satırları |
| ACK Flood | Veri taşımayan, yalnız ACK bayraklı TCP paketleri |
| RST Flood | TCP RST yoğunluğu |
| DNS Flood | DNS sorgu yoğunluğu; yanıtlar sorgu sayılmaz |
| Port Tarama | Aynı kaynak/hedef/protokol için farklı hedef portlar; TCP'de SYN girişimleri |
| Dağıtık Flood Şüphesi | Hedef toplam hızı ve farklı kaynak sayısının birlikte eşiği aşması |

Bunlar **sezgisel alarmlardır**, saldırı kanıtı değildir. Eşikler ağın normal
trafiğine göre ayarlanmalıdır. Varsayılanlar `netshield/config.py` içindedir.
Hız penceresi on adet 100 ms kovasıyla yaklaşık bir saniyedir. Aynı alarm
kaynak/hedef/tür başına en çok saniyede bir bildirilir. Dağıtık alarm hedef
başına sınırlandırılır. Kritik seviye, bildirilen ölçümün eşiğin en az iki
katı olmasıdır; bağımsız bir saldırı doğrulaması değildir.

HTTPS çözme, HTTP/2, TCP akış birleştirme, yeniden iletim ayıklama ve ICMPv6
flood analizi yoktur. IPv6 TCP/UDP trafiği aynı hız kurallarıyla işlenir;
IPv6 uzantı başlıklarının ayrıntılı görünümü yoktur. ARP görüntülenir,
ARP zehirleme tespiti yapılmaz. UDP port çeşitliliği normal sunucu trafiğinde
de oluşabilir.

## Bellek, simülasyon ve ban işlemleri

- Son **2000 paket önizlemesi** ve **2000 alarm** bellekte tutulur. Eski
  kayıtlar çıkarılır; sayaçlar oturum toplamını korur. Motor önizleme kuyruğu
  ve olay kuyruğu sınırlıdır. Taşma sayıları durum çubuğunda görünür.
- Tespit depoları en çok 4096 etkin anahtar tutar; kapasite dolduğunda en
  eski kullanılan kayıt çıkarılır. Çok yüksek kaynak çeşitliliğinde tespit
  geçmişi azalabilir. Port/kaynak kümeleri anahtar başına 1024 ile sınırlıdır.
- Simülasyon sentetik kayıtları **aynı tespit motoruna** verir; ağa paket
  göndermez. Sentetik kayıtlarda gerçek ham paket bulunmaz. Demo üretimi
  senaryo başına 5000 paketle sınırlıdır.
- Otomatik ban kapalıdır. Manuel ban, **simülasyonda da gerçek**
  `sudo iptables` komutu çalıştırır. IPv4 INPUT zincirini etkiler; ağdaki
  başka cihazların firewall'larını değiştirmez. Uygulama kapanınca kurallar
  kaldırılmaz. Liste yalnızca bu uygulama oturumundaki işlemleri gösterir.
- Görünümü temizlemek firewall kurallarını ve tespit pencerelerini silmez.
- Bu sürüm otomatik harici GeoIP sorgusu göndermez.

## Test

```bash
python3 -m unittest discover -s tests -v
```

Testler tespit eşiklerini, yanlış alarm ayrımlarını, filtreleri, kuyruk
sınırlarını, Scapy paket çözümlemesini ve firewall hata davranışlarını sınar.
Ekran varsa Tkinter arayüz testleri de çalışır. Gerçek paket gönderimi veya
firewall değişikliği yapılmaz; canlı yakalama testleri taklit edilir.

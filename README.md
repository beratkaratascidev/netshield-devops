# NetShield — Ağ Analizi

Türkçe, koyu temalı Tkinter masaüstü uygulaması. Seçilen ağ arayüzündeki
paketleri listeler; hız ve port çeşitliliği eşiklerine göre şüpheli trafik
alarmları üretir. Cihaz/bağlantı takibi ve alarm inceleme araçları içerir. Wireshark benzeri paket listesi ve ayrıntı düzeni sunar;
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
- **Ayrıntılar:** Seçili paket için portlar, TCP bayrakları ve boyut;
  seçili alarm için ölçüm ve eşik. Ham baytlar, yük ve HTTP URL saklanmaz.
- **Alarmlar:** Kaynak, hedef, tespit türü, önem ve ölçüm penceresi.
- **Akışı izle:** Otomatik kaydırmayı kapatarak eski kayıtları inceleyin.
- **Eşikler:** Yakalama durdurulunca değiştirilebilir. Sonraki başlatmada
  uygulanır ve kullanıcı ayarlarına kaydedilir. Hassas, Dengeli ve Yoğun ağ
  profilleri başlangıç noktası sağlar; bunlar otomatik öğrenilen eşikler değildir.
- **JSON dışa aktar:** İzinli alanlarla sınırlandırılmış paket/alarm metaverisi;
  IP adresleri her dosyaya özel takma kimliklerle gösterilir (şema sürümü 2).
  Tam PCAP kaydı değildir. Filtre yalnızca görünümü etkiler; dışa aktarım
  bellekteki bütün kayıtları içerir.
- **HTML rapor:** Maskeli alarm geçmişi. Kullanıcı dosya konumunu seçer;
  tarayıcı otomatik açılmaz. Kurumsal profilde JSON ve HTML kaydı kapalıdır.

### Görüntüleme filtresi

```text
src=192.168.1. proto=TCP port=443
proto=DNS
info="GET /"
192.168.1.10
```

Alanlar: `src`, `dst`, `ip`, `proto`, `port`, `sport`, `dport`, `info`. Birden fazla
koşul **VE** olarak birleştirilir. `ip=192.168.1.10` iki uçta tam IP eşleşmesi;
`ip=192.168.1.0/24` veya `src=2001:db8::/32` CIDR ağ eşleşmesi yapar. CIDR
içermeyen `src`/`dst` ve metin koşulları alt metin aramaya devam eder. `proto=TCP`, TCP üzerinde çözümlenen HTTP ve DNS kayıtlarını da
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

HTTP/1 sınıflandırması yükün ilk 512 baytıyla sınırlıdır; daha uzun istek
satırları tanınmayabilir. HTTPS çözme, HTTP/2, TCP akış birleştirme, yeniden iletim ayıklama ve ICMPv6
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
- Otomatik ban yoktur; manuel firewall işlemleri de varsayılan olarak kapalıdır.
  Bireysel profilde açıkça etkinleştirilirse yalnızca root yetkili canlı oturumda
  `/usr/sbin/iptables` kullanılır; uygulama `sudo` ile yetki yükseltmez.
  Simülasyonda engelleme yapılmaz. Kurallar oturuma özel yorumla IPv4 INPUT
  zincirine eklenir. Kapatmak veya profili değiştirmek mevcut kuralları kaldırmaz;
  liste yalnızca bu oturumun eklediği kuralları gösterir. Çıkış trafiğine veya
  başka cihazların firewall'larına dokunulmaz.
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

## Takip ve inceleme çalışma alanı

**Cihazlar ve bağlantılar** sekmesi, bellekteki son 2000 paket önizlemesinden
IP başına gönderilen/alınan paketleri, bayt miktarını ve son görülme saatini
hesaplar. Panelde Tüm modlar/Canlı/Simülasyon seçilerek yalnızca ilgili
kayıtlar incelenebilir. Paket tablosundaki Mod sütunu da sentetik kayıtları
belirtir; `mode=live` ve `mode=demo` görüntüleme filtreleri desteklenir.
İlişkili alarm sayısı son 2000 alarmdan hesaplanır; iki geçmişin zaman
aralığı aynı olmak zorunda değildir. Bunlar oturum toplamı veya tüm ağ envanteri
değildir. Önizleme taşması varsa takip tablosu yakalanan tüm paketleri kapsamaz.

- **Cihazlar:** Bir IP'ye çift tıklamak o IP'nin paketlerini filtreler.
- **Bağlantılar:** Protokol ve IP/port uçlarıyla iki yön birleştirilir. Çift
  tıklamak tam uç eşleşmeli `flow=` filtresi oluşturur. TCP akış birleştirme
  veya bağlantı kurulmuş olduğuna dair doğrulama yapılmaz.
- **Takip listem:** Trafiği görünmeyen sabitlenmiş IP'ler de sıfır sayaçla
  görünür. IP eklemek ağ taraması başlatmaz, alarmları susturmaz veya erişim
  izni vermez.
- **Alarmlar:** Önem, tespit türü ve Yeni/İncelendi filtreleri vardır.
  İncelendi işareti aynı kayıtta geri alınabilir; sonraki alarmları engellemez.
  JSON çıktısı bu işareti içerir.
- **Sağ tık:** Paket tablosundan kaynak/hedef IP'yi filtreleyin, bağlantıyı
  izleyin, IP'yi takibe ekleyin veya paket özetini kopyalayın.
- **Sütun başlıkları:** Sayısal sütunlar sayısal olarak sıralanır; yeniden
  tıklamak yönü değiştirir. Sıralama otomatik kaydırmayı kapatır. Akan paketlerin
  sıralaması saniyelik yenilemede uygulanır.

### Görünüm ve ayarlar

Üstteki **Çalışma alanı** menüsünde görünüm/IP takip ayarları, eşik profilleri
ve durdurulmuş yakalama için arayüz listesini yenileme bulunur. **Görünüm**
menüsünden sağ panel ve paket ayrıntıları gizlenebilir. Rahat/Kompakt tablo
satır yoğunluğu seçilebilir.

Eşikler, güvenlik tercihleri, satır yoğunluğu ve en fazla 100 takip IP'si
`$XDG_CONFIG_HOME/netshield/settings.json` konumunda; değişken tanımlı değilse
`~/.config/netshield/settings.json` konumunda saklanır. Dosya atomik olarak
değiştirilir; bozuk dosyada varsayılanlar yüklenir ve günlükte neden belirtilir.
Paketler, alarm geçmişi, inceleme işaretleri, sıralama ve panel yerleşimi
uygulama kapanınca saklanmaz. Root ile açılan uygulama farklı kullanıcı ayar
konumunu kullanabilir. Görünüm tercihleri çalışan yakalamayı değiştirmez;
eşiklerin etkinleşmesi için yeniden başlatma gerekir.

Kısayollar: **Ctrl+F** filtreye odaklanır; filtrede **Enter** uygular,
**Esc** temizler; **Ctrl+E** JSON dışa aktarır; paket tablosunda **Ctrl+C**
güvenlik politikasında izin verilmişse maskeli özeti kopyalar. Yardım menüsünde de bu bilgiler bulunur.

## Güvenlik tabanı

**Güvenlik merkezi** üzerinden Bireysel/Kurumsal profil ve işlem izinleri seçilir.
Varsayılan Bireysel profilde maskeli yerel dosya kaydı açık; pano ve firewall
kapalıdır. Kurumsal profil üçünü de kapatır. Yönetici politikası bu izinleri
daha da kısıtlayabilir. Harici GeoIP istemcisi kaldırılmıştır; uygulamada
telemetri, bulut yüklemesi, aktif ağ taraması ve otomatik tarayıcı açma yoktur.

Raporlar/JSON dosyaları POSIX'te `0600` izinle atomik yazılır. IP maskesi aynı
dosyada tutarlı, farklı dosyalarda farklıdır; maskeleme anahtarı dışa aktarılmaz.
Yük, ham bayt, URL, serbest metin, arayüz adı ve takip listesi dışa aktarılmaz.
Bu bir veri azaltma ve takma kimlik yöntemidir; bütün metaverinin anonim olduğu
anlamına gelmez. Geçmiş sürümlerde oluşturulmuş dosyalar otomatik değiştirilmez.

Kurumsal dağıtım sınırları, yönetici politikası kurulumu ve test kapsamı için
[SECURITY.md](SECURITY.md) dosyasına bakın. Bu taban işletim sistemi güvenlik
sınırı, sertifikasyon veya diğer uygulamalar için ağ çıkış engeli değildir.

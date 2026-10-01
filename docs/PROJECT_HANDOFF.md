# NetShield proje devri

Tarih: 1 Ekim 2026. Durum: MVP / pilot; üretim kabulü tamamlanmadı.

## Çalışan kapsam

Pasif trafik önizlemesi ve eşik alarmları, cihaz envanteri, isteğe bağlı Windows
etkileşimli ajan/HTTPS alıcısı, kalıcı teslim kuyruğu, kontrollü anahtar geçişi,
yerel denetim günlüğü ve anahtarsız yedek/geri yükleme. Ayrıntı: README.md.

## Doğrulama

Yerelde 124 Python ve 15 ortak C# testi geçti; Framework derlemesi ve gerçek
C# → HTTPS → SQLite entegrasyonu başarılı. GitHub Actions Linux ve Windows
depolama smoke kontrollerini her push/PR'da tekrarlar. Etiket yayınları iki işin
başarısını bekler. Windows Server runner sonucu, Windows 10/11 etkileşimli
kabul veya servis doğrulaması olarak yorumlanmaz.

## Öncelikli açık işler

1. Windows servis hostu ve görünür oturum bileşeni; RDP ve başlangıç durum bilgisi.
2. Rol tabanlı yetkilendirme ve yönetici/operatör erişim ayrımı.
3. Normal kullanıcı GUI'sinden ayrıcalıklı yakalama yardımcısı.
4. Birleşik tanılama, saat sapması ve cihaz/IP geçmiş eşleştirmesi.
5. Uzun süreli trafik, yanlış alarm ve arıza ölçümleri; tespit istisnaları.
6. İmzalı Windows dağıtımı, yükseltme ve geri alma kabulü.

NetShield verileri ve anahtarları yeni projeye kopyalanmamalıdır. Mevcut kullanıcı
ayarları, OS firewall kuralları ve servisler bu devirde silinmez/değiştirilmez.
Yeni proje için farklı bir klasör ve Git deposu kullanın. Ortak `lean_finder`,
`lean_fixer`, `lean_reviewer` ajanları aynı WSL kullanıcısında kullanılabilir;
NetShield'in AGENTS.md dosyasını başka projeye taşımayın.

## Devam komutları

```bash
.venv/bin/python -m unittest discover -s tests -q
python3 ids.py
dotnet run --project agents/windows/Core.Tests/Core.Tests.csproj
```

Geliştirici bağımlılıkları `requirements-dev.txt`; HTTPS alıcısı için
`requirements-receiver.txt`. GUI testleri çalışan bir DISPLAY veya Linux'ta
`xvfb-run -a` gerektirir. Kısıtlı/doğrulanmamış alanlar için SECURITY.md ve
IMPLEMENTATION_STATUS.md kullanılmalıdır.

# NetShield v0.1.1 — MVP / pilot

Tarih: 1 Ekim 2026

Bu sürüm mevcut NetShield MVP'sinin yayın ve geliştirici iş akışını düzenler.
Üretim kullanımı için tamamlanmış bir şirket izleme ürünü değildir.

- GitHub Actions: Linux Python/Tk testleri, ortak C# testleri, Framework derlemesi
  ve C# → HTTPS → SQLite entegrasyonu.
- Windows PowerShell 5.1 Add-Type derlemesindeki eksik `System.Xml` referansı düzeltildi.
- Windows Server 2022 runner'ında PowerShell 5.1 sözdizimi ve gerçek CurrentUser
  DPAPI/kalıcı kuyruk smoke testi başarıyla geçti; [kanıt](https://github.com/beratkaratascidev/netshield-devops/actions/runs/36833438567/job/110275085133).
- Sürüm etiketi için her iki iş başarılı olmadan yayın oluşturulmaz.
- Kaynak ZIP ve SHA-256 özeti; imzalı Windows kurulum paketi içermez.
- NetShield'e özel kısa AGENTS.md ve ortak kullanıcı ajanlarına geçiş rehberi.
- Yerel ayar, denetim veritabanı, sertifika ve arşivlerin yanlışlıkla eklenmesine
  karşı Git ignore kapsamı genişletildi.

Yerel doğrulama: 124 Python testi, 15 C# testi, Framework 4.7.2 derlemesi ve
sertifika reddi/tekrar teslim içeren HTTPS entegrasyonu başarılı. GitHub runner
sonuçları ayrıca sürüm commit'inin Actions kaydından doğrulanmalıdır.

## Açık kalan kapsam

Windows servis hostu/görünür oturum bileşeni, imzalı kurulum, gerçek Windows 10/11
kilit/uyku/RDP kabulü, roller, ayrıcalıklı yakalama yardımcısı, birleşik tanılama,
uzun süreli gerçek ağ ve yanlış alarm ölçümleri tamamlanmadı. Windows Server
DPAPI smoke testi bu kabul listesinin yerine geçmez. Yerel denetim günlüğü
kurcalamaya dayanıklı merkezi audit değildir.

[Proje devri ve açık işler](https://github.com/beratkaratascidev/netshield-devops/blob/v0.1.1/docs/PROJECT_HANDOFF.md) ·
[Detaylı uygulama takibi](https://github.com/beratkaratascidev/netshield-devops/blob/v0.1.1/docs/IMPLEMENTATION_STATUS.md)

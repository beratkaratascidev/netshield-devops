# NetShield: kısa ve odaklı çalışma

- Türkçe, kısa yanıt ver: değişiklik, doğrulama, kalan engel. Uzun günlük dökümleri verme.
- Önce `git status --short`, sonra görevde geçen sembolleri `rg -n` ile ara.
  İlgili fonksiyonları oku; tüm repoyu, README'yi ve geçmiş raporları her görevde tarama.
  Bilinmeyen bağımlılık veya güvenlik etkisi ortaya çıkarsa kapsamı gerektiği kadar genişlet.
- Kullanıcı analiz istiyorsa bulguları sun; düzenleme istiyorsa uygula ve doğrula.
  İlgisiz refactor, yeni özellik ve genel temizlik ekleme.
- Küçük görevleri ana ajan yapsın. Alt ajanları yalnız kullanıcı istediğinde kullan;
  bir seferde bir ajan, tek somut görev. Ajan sonucunu kullan, aynı araştırmayı tekrarlama.
  Eksik kanıtı doğrula. Ajan oluşturma isteği otomatik paralel çalışma yetkisi değildir.
- Büyük komut çıktısını sınırlı döndür; kesilen hata ayrıntılarını hedefli olarak tekrar oku.
  `.venv`, `.git`, `__pycache__`, `bin`, `obj` içeriğini normal kod aramasına katma.
- Değişiklikle ilgili testleri çalıştır; ortak altyapı/protokol/güvenlik değişiminde tam
  süiti bir kez çalıştır. Yeni değişiklik veya hata olmadan aynı testleri yineleme.
- Anahtar, sertifika, gerçek cihaz verisi ve kullanıcı ayarlarını bağlama dökme.
  Mevcut TLS, izin, gizlilik ve teslim onayı kontrollerini koru.
- Windows DPAPI/servis davranışını Linux testleriyle doğrulanmış sayma.
  Güvenlik/veri biçimi değişiminde ilgili SECURITY.md bölümünü oku ve güncelle.
- Tam kapsamlı geliştirmede açık işler `docs/IMPLEMENTATION_STATUS.md` içinde;
  tek dosyalık görevde bu raporu yeniden incelemek gerekmez.

## Dosya haritası ve testler

- Tk arayüzü: `ids.py`, `netshield/ui/`; `test_workspace.py`, `test_regressions.py`.
- Trafik/tespit: `netshield/core/motor.py`, `detection.py`, `http_prefix.py`;
  `test_detection.py`, `test_interfaces.py`, `test_http_prefix.py`.
- Windows alıcısı/eşleştirme: `netshield/agent_receiver.py`, `core/agent_*.py`,
  `core/enrollment.py`; `test_agent_*.py`, `test_enrollment.py`.
- Güvenlik/ayar/yedek: `core/security.py`, `settings.py`, `audit.py`, `netshield/backup.py`;
  ilgili `tests/test_*.py` dosyaları.
- Windows ajanı: `agents/windows/`; ortak C# testleri `Core.Tests/`.
- Hedefli: `.venv/bin/python -m unittest discover -s tests -p 'test_<alan>.py' -q`
- Tam: `.venv/bin/python -m unittest discover -s tests -q`
- `.venv` yoksa uygun Python ortamını belirle; sessizce test atlama.

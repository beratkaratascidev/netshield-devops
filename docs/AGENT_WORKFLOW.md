# Ortak ajan kullanımı

Ajanlar artık bu projeye özel değildir. Bu WSL/Linux ortamında `five` kullanıcısının
`~/.codex/agents/` ve `~/.claude/agents/` dizinlerine kuruldu.

| Görev | Codex | Claude Code |
|---|---|---|
| Kodun yerini bul | `lean_finder` | `lean-finder` |
| Tek hatayı düzelt | `lean_fixer` | `lean-fixer` |
| Diff incele | `lean_reviewer` | `lean-reviewer` |

VS Code'da Developer: Reload Window çalıştırıp yeni sohbet açın.
Örnek: “lean_fixer ajanını kullan: ids.py içindeki [hatayı] düzelt;
beklenen [davranış]. İlgili testleri çalıştır ve kısa rapor ver.”

Küçük işler için doğrudan ana ajanı kullanın. Alt ajan zinciri otomatik başlatılmaz.
NetShield'in dosya haritası ve test komutları proje kökündeki AGENTS.md'de kalır;
Claude bu dosyayı CLAUDE.md üzerinden içe alır. Genel rehber: ~/AGENT_WORKFLOW.md.

Başka proje aynı kullanıcı/ortamda bu ortak ajanları kullanabilir. Başka makine,
WSL dağıtımı, Windows profili veya container için kullanıcı tanımlarını ayrıca
kurmak gerekir. Bu repo tek başına kullanıcı ajanlarını başka bilgisayara taşımaz.
Proje/oturum ayarları genel ayarları geçersiz kılabilir. Gerçek model çağrısı veya
token tasarrufu ölçümü yapılmadı; kurulum sabit bir tasarruf oranı vaat etmez.

Kaynaklar: [Codex kullanıcı ajanları](https://learn.chatgpt.com/docs/agent-configuration/subagents),
[Claude Code kullanıcı ajanları](https://code.claude.com/docs/en/sub-agents).

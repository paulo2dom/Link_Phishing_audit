# Email Link Forensic Analysis Tool

## Overview

`analyze_email_links.sh` é uma ferramenta forense para análise passiva e controlada de links suspeitos extraídos de emails, focada em deteção de phishing e malware delivery.

## Características de Segurança

✅ **Apenas recolha passiva** - Sem exploração ativa
✅ **Sem JavaScript** - Não executa código client-side
✅ **Limites controlados** - Timeouts, tamanhos máximos, redirects limitados
✅ **Redação de dados sensíveis** - Parâmetros sensíveis redatados nos relatórios
✅ **Cadeia de custódia** - Hashes SHA256 de todos os artefactos
✅ **Rate limiting** - Controlo de velocidade de pedidos

## Dependências

### Obrigatórias
- `curl` - Recolha HTTP/HTTPS
- `openssl` - Inspeção TLS
- `sha256sum` - Hashing de evidências

### Opcionais
- `dig` ou `host` - Resolução DNS detalhada
- `bc` - Para rate limiting preciso

### Instalação (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install curl openssl coreutils dnsutils bc
```

### Instalação (RHEL/CentOS/Fedora)
```bash
sudo yum install curl openssl coreutils bind-utils bc
```

### Instalação (macOS)
```bash
# curl e openssl geralmente já vêm instalados
brew install coreutils bind bc
```

## Uso Básico

### Sintaxe
```bash
./analyze_email_links.sh <urls_file> [output_dir] [options]
```

### Exemplo 1: Análise simples
```bash
./analyze_email_links.sh suspicious_urls.txt
```

### Exemplo 2: Análise com diretório específico
```bash
./analyze_email_links.sh urls.txt ./evidence_case_2024_001
```

### Exemplo 3: Sem seguir redirects
```bash
./analyze_email_links.sh urls.txt --no-follow
```

### Exemplo 4: Análise conservadora (timeouts curtos, sem DNS/TLS)
```bash
./analyze_email_links.sh urls.txt --timeout 10 --max-bytes 100 --no-dns --no-tls
```

### Exemplo 5: Com rate limiting (500ms entre pedidos)
```bash
./analyze_email_links.sh urls.txt --rate-limit 500
```

## Opções Disponíveis

| Opção | Descrição | Default |
|-------|-----------|---------|
| `--follow` | Seguir redirects | ✓ |
| `--no-follow` | Não seguir redirects | |
| `--max-redirs N` | Máximo de redirects | 5 |
| `--timeout S` | Timeout de conexão (segundos) | 20 |
| `--max-bytes KB` | Tamanho máximo do body (KB) | 200 |
| `--user-agent "..."` | User-Agent customizado | Chrome/120 |
| `--no-dns` | Desativar resolução DNS | |
| `--no-tls` | Desativar inspeção TLS | |
| `--rate-limit MS` | Sleep entre URLs (milissegundos) | 0 |
| `--verbose` | Output detalhado | |

## Formato do Ficheiro de URLs

```text
# Comentários começam com #
# URLs podem estar com ou sem esquema http/https
# Espaços são removidos automaticamente

https://suspicious-site.com/login
microsoft-verify.example.com/account
http://192.168.1.100/phish.php
bit.ly/suspicious

# URLs duplicados são automaticamente removidos
https://suspicious-site.com/login
```

## Estrutura de Output

```
report_20240119_143022/
├── REPORT.md                          # Relatório principal em Markdown
├── urls_normalized.txt                # URLs normalizados e deduplicados
├── sha256sum_all.txt                  # Hashes master (cadeia de custódia)
├── logs/                              # Logs de execução
└── per_url/
    ├── https___example_com_path_1/
    │   ├── raw/
    │   │   ├── headers.txt           # Headers HTTP (HEAD request)
    │   │   ├── headers.txt.stderr    # Erros do curl
    │   │   ├── body.html             # Corpo da resposta (GET)
    │   │   ├── body.html.headers     # Headers + curl info do GET
    │   │   └── body.html.stderr      # Erros do curl (GET)
    │   ├── dns/
    │   │   └── resolution.txt        # Resolução DNS (A/AAAA/CNAME)
    │   ├── tls/
    │   │   ├── certificate.txt       # Info do certificado
    │   │   └── certificate_chain.pem # Cadeia completa
    │   ├── analysis/
    │   │   └── content_analysis.txt  # Análise de conteúdo suspeito
    │   ├── metadata.env              # Metadados extraídos
    │   └── hashes.txt                # SHA256 de todos os ficheiros
    └── ...
```

## Relatório Gerado (REPORT.md)

O relatório inclui:

### 1. Executive Summary
- Número total de URLs analisados
- Scope da análise
- Medidas de segurança aplicadas

### 2. URL Analysis Summary (Tabela)
```markdown
| # | Original URL | Status | Server | IPs | Redirects | Suspicious Flags |
|---|-------------|--------|--------|-----|-----------|------------------|
| 1 | `https://example.com/...` | 200 | nginx/1.18 | 93.184.216.34 | 0 | ⚠️ Medium |
| 2 | `https://phish-site.com/...` | 302 | Apache | 192.0.2.1 | 3 | ⚠️ High |
```

### 3. Indicators of Compromise (IOCs)
- **Domínios** observados
- **IPs** resolvidos
- **URLs finais** (pós-redirect)
- **Fingerprints TLS** (SHA256)

### 4. Evidence Files
- Estrutura completa dos artefactos recolhidos

### 5. Methodology & Limitations
- Métodos de recolha
- Limitações técnicas
- Considerações éticas/legais

### 6. Recommendations
- Ações recomendadas baseadas nos findings

## Indicadores Suspeitos Detetados

O script procura automaticamente por:

### Keywords Suspeitas
- `microsoft`, `office`, `login`, `password`, `verify`, `update`
- `atob(`, `localStorage`, `$.ajax`, `fetch(`
- `next.php`, `post.php`, `send.php`
- `eval(`, `base64_decode`, `document.write`
- `window.location`, `onclick=`, `onerror=`
- `credentials`, `account`, `suspend`, `confirm`
- `security`, `billing`

### Elementos HTML
- Forms (`<form>`)
- Input fields (`<input>`)
- Script tags (`<script>`)
- External resources (src/href)

### Flags de Risco
- **⚠️ High**: >5 indicadores suspeitos
- **⚠️ Medium**: 3-5 indicadores suspeitos

## Exemplo de Execução

```bash
$ ./analyze_email_links.sh example_urls.txt

[2024-01-19 14:30:15] analyze_email_links.sh v1.0.0
[2024-01-19 14:30:15] Forensic Email Link Analysis Tool

[INFO] Configuration:
  URLs file: example_urls.txt
  Output directory: ./report_20240119_143015
  Follow redirects: 1 (max: 5)
  Timeout: 20s
  Max body size: 200KB
  DNS resolution: 1
  TLS inspection: 1
  Rate limit: 0ms

[INFO] Normalizing and deduplicating URLs...
[SUCCESS] Found 3 unique URLs

[INFO] [1] Analyzing: https://www.microsoft.com
  → Collecting headers...
  → Collecting body...
  → Resolving DNS...
  → Inspecting TLS...
  → Analyzing content...
  → Computing hashes...
[SUCCESS] [1] Complete: https://www.microsoft.com

[INFO] [2] Analyzing: https://login.microsoftonline.com
  → Collecting headers...
  → Collecting body...
  → Resolving DNS...
  → Inspecting TLS...
  → Analyzing content...
  → Computing hashes...
[SUCCESS] [2] Complete: https://login.microsoftonline.com

[INFO] [3] Analyzing: https://google.com
  → Collecting headers...
  → Collecting body...
  → Resolving DNS...
  → Inspecting TLS...
  → Analyzing content...
  → Computing hashes...
[SUCCESS] [3] Complete: https://google.com

[INFO] Generating final report...
[SUCCESS] Report generated: ./report_20240119_143015/REPORT.md
[INFO] Generating master hash file for chain of custody...
[SUCCESS] Master hash file: ./report_20240119_143015/sha256sum_all.txt

[SUCCESS] Analysis complete!
Results: ./report_20240119_143015
Report: ./report_20240119_143015/REPORT.md
Master hashes: ./report_20240119_143015/sha256sum_all.txt

⚠️  Review the report for IOCs and high-risk indicators
```

## Exemplo de Relatório (Mock)

```markdown
# Email Link Forensic Analysis Report

**Generated by:** analyze_email_links.sh
**Timestamp:** 2024-01-19 14:30:45 UTC

---

## Executive Summary

This report contains forensic evidence collected from **3** URLs extracted from email messages.
The analysis was conducted using passive, controlled methods with no active exploitation.

---

## URL Analysis Summary

| # | Original URL | Status | Server | IPs | Redirects | Suspicious Flags |
|---|-------------|--------|--------|-----|-----------|------------------|
| 1 | `https://www.microsoft.com` | 200 | Microsoft-IIS/10.0 | 20.112.52.29 | 0 |  |
| 2 | `https://login.microsoftonline.com` | 200 | Microsoft-IIS/10.0 | 20.190.160.1 | 0 | ⚠️ Medium |
| 3 | `https://google.com` | 301 | gws | 142.250.185.46 | 1 |  |

---

## Indicators of Compromise (IOCs)

### Domains Observed

```
google.com
login.microsoftonline.com
www.google.com
www.microsoft.com
```

### IP Addresses

```
20.112.52.29
20.190.160.1
142.250.185.46
2a00:1450:4001:808::200e
```

### Final URLs (Post-Redirect)

```
https://www.google.com/
https://www.microsoft.com/
https://login.microsoftonline.com/
```

### TLS Certificate Fingerprints

```
SHA256 Fingerprint=A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:90:AB:CD:EF...
SHA256 Fingerprint=12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF...
```

---

## Recommendations

1. **High-Risk URLs:** Review any URLs with ⚠️ flags in detail
2. **IOC Matching:** Cross-reference domains/IPs with threat intelligence feeds
3. **Certificate Validation:** Check for self-signed, expired, or suspicious certificates
4. **Redirect Patterns:** Investigate URLs with multiple redirects (possible cloaking)
5. **Further Analysis:** Consider sandboxed browser analysis for high-risk candidates
```

## Considerações de Segurança

### O Que Este Script FAZ
✅ Recolha passiva de headers HTTP/HTTPS
✅ Download controlado de conteúdo HTML (limites de tamanho)
✅ Resolução DNS (A/AAAA/CNAME)
✅ Inspeção de certificados TLS
✅ Análise de padrões suspeitos no conteúdo
✅ Documentação de cadeia de redirects

### O Que Este Script NÃO FAZ
❌ Exploração de vulnerabilidades
❌ Brute force ou fuzzing
❌ Execução de JavaScript
❌ Browser automation (Selenium, Puppeteer)
❌ Submissão de credenciais
❌ Crawling profundo ou recursivo
❌ Bypass de proteções (CAPTCHA, WAF)
❌ Ataques ativos de qualquer tipo

### Considerações Éticas e Legais

⚠️ **IMPORTANTE**:
- Este script destina-se a análise forense **autorizada** e resposta a incidentes
- Obtenha autorização adequada antes de analisar URLs de terceiros
- Respeite Termos de Serviço e políticas de rate limiting
- Não use para atividades maliciosas ou não autorizadas
- Em caso de dúvida, consulte o departamento legal/compliance

### Rate Limiting e Boa Cidadania

Para análises de grande volume, considere:
```bash
# Rate limit de 1 segundo entre pedidos
./analyze_email_links.sh urls.txt --rate-limit 1000

# Timeouts mais conservadores
./analyze_email_links.sh urls.txt --timeout 10 --max-bytes 100
```

## Troubleshooting

### Problema: "Missing required dependencies"
**Solução**: Instale as dependências listadas na secção de instalação

### Problema: "DNS resolution failed"
**Solução**:
- Verifique conectividade de rede
- Use `--no-dns` para pular resolução DNS
- Instale `dig` ou `host`

### Problema: "TLS certificate collection failed"
**Solução**:
- Verifique se `openssl` está instalado
- Use `--no-tls` para pular inspeção TLS
- Alguns sites podem bloquear conexões openssl diretas

### Problema: "Timeout errors on all URLs"
**Solução**:
- Aumente timeout: `--timeout 30`
- Verifique firewall/proxy
- Alguns sites podem bloquear User-Agent do curl

### Problema: Problemas com CRLF (Windows)
**Solução**:
```bash
# Converter ficheiro para LF (Unix line endings)
dos2unix analyze_email_links.sh
# ou
sed -i 's/\r$//' analyze_email_links.sh

# Dar permissões de execução
chmod +x analyze_email_links.sh
```

## Compatibilidade

- **Bash**: 4.0+
- **Zsh**: Compatível (invoque como `./script.sh`)
- **Sistemas**: Linux, macOS, WSL (Windows)
- **Codificação**: UTF-8

## Workflow Recomendado

1. **Extração**: Extrair URLs de emails (.eml, .msg) usando ferramentas como `ripgrep`, `emlAnalyzer`, etc.
2. **Preparação**: Criar ficheiro de texto com 1 URL por linha
3. **Análise**: Executar `analyze_email_links.sh`
4. **Revisão**: Analisar `REPORT.md` e identificar IOCs
5. **Correlação**: Cross-reference com threat intelligence (VirusTotal, AlienVault, etc.)
6. **Resposta**: Tomar ações baseadas nos findings (block, alert, investigate)

## Integração com Outras Ferramentas

### VirusTotal
```bash
# Após análise, submeter URLs/IPs/hashes ao VT
cat report_*/urls_normalized.txt | while read url; do
    vt url "$url"
done
```

### TheHive / MISP
```bash
# Exportar IOCs para plataformas SIEM/SOAR
# Os ficheiros de metadata podem ser parseados para automação
```

### Splunk / ELK
```bash
# Logs estruturados podem ser ingeridos para correlação
```

## Licença e Contribuições

Este script é fornecido "as-is" para fins educacionais e de segurança defensiva.
Use sob sua própria responsabilidade e com autorização adequada.

---

**Versão**: 1.0.0
**Última atualização**: 2024-01-19
**Autor**: Security Analysis Tool

# Link Phishing Audit

🔍 **Forensic Email Link Analysis Tool** - Ferramenta de análise forense passiva para deteção de phishing e malware delivery em URLs extraídos de emails.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/security-passive%20only-brightgreen.svg)](README.md)

## 🎯 Objetivo

Esta ferramenta permite realizar análise forense **segura e controlada** de links suspeitos encontrados em emails, focando-se exclusivamente em **recolha passiva de evidências** sem qualquer tipo de exploração ativa.

## ✨ Características Principais

### 🛡️ Segurança em Primeiro Lugar
- ✅ **100% Passivo** - Apenas recolha HTTP/HTTPS com curl
- ✅ **Sem JavaScript** - Não executa código client-side
- ✅ **Sem Exploração** - Nada de brute force, fuzzing ou ataques
- ✅ **Limites Controlados** - Timeouts, tamanhos máximos, redirects limitados
- ✅ **Redação Automática** - Parâmetros sensíveis redatados nos relatórios

### 🔬 Análise Forense Completa
- 📡 **HTTP/HTTPS Collection** - Headers (HEAD) e Body (GET) com limites
- 🌐 **DNS Resolution** - Records A/AAAA/CNAME via dig/host
- 🔐 **TLS Inspection** - Certificados, fingerprints SHA256, cadeia completa
- 🕵️ **Content Analysis** - Deteção de 30+ indicadores suspeitos
- 🔄 **Redirect Tracking** - Cadeia completa de redirects (até 5 níveis)
- 🔒 **Chain of Custody** - SHA256 de todos os artefactos

### 📊 Reporting Profissional
- 📝 **Relatório Markdown** - Formato legível e estruturado
- 🎯 **IOC Extraction** - Domínios, IPs, URLs finais, TLS fingerprints
- ⚠️ **Risk Flags** - Classificação automática (High/Medium) baseada em indicadores
- 📂 **Organização** - Estrutura clara de evidências por URL

## 🚀 Quick Start

### Instalação

```bash
# Clone o repositório
git clone https://github.com/paulo2dom/Link_Phishing_audit.git
cd Link_Phishing_audit

# Dar permissões de execução
chmod +x analyze_email_links.sh

# Verificar dependências
./analyze_email_links.sh --help
```

### Dependências

**Obrigatórias:**
- `curl` - Recolha HTTP/HTTPS
- `openssl` - Inspeção TLS
- `sha256sum` - Hashing

**Opcionais:**
- `dig` ou `host` - DNS resolution
- `bc` - Rate limiting preciso

```bash
# Debian/Ubuntu
sudo apt-get install curl openssl coreutils dnsutils bc

# RHEL/CentOS/Fedora
sudo yum install curl openssl coreutils bind-utils bc

# macOS
brew install coreutils bind bc
```

### Uso Básico

```bash
# 1. Criar ficheiro com URLs (1 por linha)
cat > urls.txt <<EOF
https://suspicious-site.com/login
microsoft-verify.example.com
http://192.0.2.1/phish.php
EOF

# 2. Executar análise
./analyze_email_links.sh urls.txt

# 3. Revisar relatório
cat report_*/REPORT.md
```

## 📖 Documentação

### Sintaxe Completa

```bash
./analyze_email_links.sh <urls_file> [output_dir] [options]
```

### Opções Principais

| Opção | Descrição | Default |
|-------|-----------|---------|
| `--follow` | Seguir redirects | ✓ |
| `--no-follow` | Não seguir redirects | - |
| `--max-redirs N` | Máximo de redirects | 5 |
| `--timeout S` | Timeout de conexão (segundos) | 20 |
| `--max-bytes KB` | Tamanho máximo do body (KB) | 200 |
| `--user-agent "..."` | User-Agent customizado | Chrome/120 |
| `--no-dns` | Desativar resolução DNS | - |
| `--no-tls` | Desativar inspeção TLS | - |
| `--rate-limit MS` | Sleep entre URLs (ms) | 0 |
| `--verbose` | Output detalhado | - |

### Exemplos de Uso

```bash
# Análise simples
./analyze_email_links.sh suspicious_urls.txt

# Com diretório de output específico
./analyze_email_links.sh urls.txt ./case_2024_001

# Sem seguir redirects
./analyze_email_links.sh urls.txt --no-follow

# Análise conservadora (timeouts curtos)
./analyze_email_links.sh urls.txt --timeout 10 --max-bytes 100

# Com rate limiting (500ms entre pedidos)
./analyze_email_links.sh urls.txt --rate-limit 500

# Análise completa customizada
./analyze_email_links.sh urls.txt ./evidence \
  --max-redirs 3 \
  --timeout 15 \
  --max-bytes 150 \
  --rate-limit 1000 \
  --verbose
```

## 📁 Estrutura de Output

```
report_20240119_143022/
├── REPORT.md                          # Relatório principal em Markdown
├── urls_normalized.txt                # URLs normalizados e deduplicados
├── sha256sum_all.txt                  # Hashes master (cadeia de custódia)
├── logs/                              # Logs de execução
└── per_url/
    └── https___example_com_path/
        ├── raw/
        │   ├── headers.txt           # Headers HTTP (HEAD request)
        │   ├── body.html             # Corpo da resposta (GET)
        │   └── *.stderr              # Erros do curl
        ├── dns/
        │   └── resolution.txt        # Resolução DNS (A/AAAA/CNAME)
        ├── tls/
        │   ├── certificate.txt       # Info do certificado
        │   └── certificate_chain.pem # Cadeia completa
        ├── analysis/
        │   └── content_analysis.txt  # Análise de conteúdo suspeito
        ├── metadata.env              # Metadados extraídos
        └── hashes.txt                # SHA256 de todos os ficheiros
```

## 🔍 Indicadores Detetados

### Keywords Suspeitas
O script procura automaticamente por:

- **Phishing comum**: `microsoft`, `office`, `login`, `password`, `verify`, `update`, `account`, `suspend`, `confirm`
- **JavaScript suspeito**: `atob(`, `eval(`, `base64_decode`, `document.write`, `window.location`
- **Web APIs**: `localStorage`, `$.ajax`, `fetch(`
- **Event handlers**: `onclick=`, `onerror=`
- **Scripts comuns**: `next.php`, `post.php`, `send.php`
- **Sensível**: `credentials`, `security`, `billing`

### Elementos HTML
- Forms (`<form>`)
- Input fields (`<input>`)
- Script tags (`<script>`)
- External resources (src/href)

### Classificação de Risco
- **⚠️ High**: >5 indicadores suspeitos
- **⚠️ Medium**: 3-5 indicadores suspeitos
- **✓ Low**: <3 indicadores

## 📊 Exemplo de Relatório

```markdown
## URL Analysis Summary

| # | Original URL | Status | Server | IPs | Redirects | Suspicious Flags |
|---|-------------|--------|--------|-----|-----------|------------------|
| 1 | `https://www.microsoft.com` | 200 | Microsoft-IIS/10.0 | 20.112.52.29 | 0 |  |
| 2 | `https://phish-site.com/login` | 302 | Apache | 192.0.2.1 | 3 | ⚠️ High |
| 3 | `https://suspicious.com/verify` | 200 | nginx | 93.184.216.34 | 1 | ⚠️ Medium |

## Indicators of Compromise (IOCs)

### Domains Observed
```
phish-site.com
suspicious.com
www.microsoft.com
```

### IP Addresses
```
20.112.52.29
93.184.216.34
192.0.2.1
```
```

## 🔐 Considerações de Segurança

### ✅ O Que Este Script FAZ
- Recolha passiva de headers HTTP/HTTPS
- Download controlado de conteúdo HTML (limites de tamanho)
- Resolução DNS (A/AAAA/CNAME)
- Inspeção de certificados TLS
- Análise de padrões suspeitos no conteúdo
- Documentação de cadeia de redirects

### ❌ O Que Este Script NÃO FAZ
- Exploração de vulnerabilidades
- Brute force ou fuzzing
- Execução de JavaScript
- Browser automation (Selenium, Puppeteer)
- Submissão de credenciais
- Crawling profundo ou recursivo
- Bypass de proteções (CAPTCHA, WAF)
- Ataques ativos de qualquer tipo

### ⚠️ Uso Responsável

**IMPORTANTE:**
- Este script destina-se a análise forense **autorizada** e resposta a incidentes
- Obtenha autorização adequada antes de analisar URLs de terceiros
- Respeite Termos de Serviço e políticas de rate limiting
- Não use para atividades maliciosas ou não autorizadas
- Em caso de dúvida, consulte o departamento legal/compliance

## 🛠️ Workflow Recomendado

1. **Extração** - Extrair URLs de emails (.eml, .msg) usando ferramentas como `ripgrep`, `emlAnalyzer`
2. **Preparação** - Criar ficheiro de texto com 1 URL por linha
3. **Análise** - Executar `analyze_email_links.sh`
4. **Revisão** - Analisar `REPORT.md` e identificar IOCs
5. **Correlação** - Cross-reference com threat intelligence (VirusTotal, AlienVault, etc.)
6. **Resposta** - Tomar ações baseadas nos findings (block, alert, investigate)

## 🔗 Integração com Outras Ferramentas

### VirusTotal
```bash
# Submeter URLs para análise
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

## 🐛 Troubleshooting

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

### Problema: Problemas com CRLF (Windows/WSL)
**Solução**:
```bash
# Converter ficheiro para LF (Unix line endings)
dos2unix analyze_email_links.sh
# ou
sed -i 's/\r$//' analyze_email_links.sh

# Dar permissões de execução
chmod +x analyze_email_links.sh
```

## 📋 Compatibilidade

- **Bash**: 4.0+
- **Zsh**: Compatível
- **Sistemas**: Linux, macOS, WSL (Windows)
- **Codificação**: UTF-8

## 📚 Ficheiros do Projeto

- **[analyze_email_links.sh](analyze_email_links.sh)** - Script principal de análise
- **[README_FORENSIC.md](README_FORENSIC.md)** - Documentação técnica detalhada
- **[example_urls.txt](example_urls.txt)** - Ficheiro de exemplo para testes
- **[collect_phish_evidence.sh](collect_phish_evidence.sh)** - Script original de referência

## 🤝 Contribuir

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para a sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit as suas alterações (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto é fornecido "as-is" para fins educacionais e de segurança defensiva.
Use sob sua própria responsabilidade e com autorização adequada.

## ⚡ Roadmap

- [ ] Suporte para análise de ficheiros .eml/.msg diretamente
- [ ] Integração com APIs de threat intelligence (VirusTotal, URLhaus)
- [ ] Output em formato JSON para automação
- [ ] Screenshot capture (opcional, com headless browser)
- [ ] Análise de WHOIS para domínios
- [ ] Deteção de typosquatting automática
- [ ] Dashboard HTML interativo

## 📧 Contacto

Paulo Domingos - [@paulo2dom](https://github.com/paulo2dom)

Project Link: [https://github.com/paulo2dom/Link_Phishing_audit](https://github.com/paulo2dom/Link_Phishing_audit)

---

**⚠️ Disclaimer**: Esta ferramenta destina-se exclusivamente a profissionais de segurança e equipas de resposta a incidentes. O uso inadequado ou não autorizado é da responsabilidade do utilizador.

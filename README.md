# 🔐 OAuth Login - Sistema de Autenticação Seguro com Google

## 📋 Sobre o Projeto

Sistema de autenticação robusto desenvolvido em ASP.NET Core 8.0 que implementa OAuth 2.0 com Google, seguindo as melhores práticas de segurança web modernas.

## 🛡️ Práticas de Segurança Implementadas

### 1. **Autenticação OAuth 2.0 com Google**
- **Provedor Confiável**: Utiliza o Google como provedor de identidade, eliminando a necessidade de armazenar senhas
- **Fluxo Seguro**: Implementação completa do fluxo OAuth 2.0 com tokens seguros
- **Claims Mapping**: Extração segura de informações do usuário (email, nome, foto) via Claims
- **Callback Seguro**: Endpoint `/auth/callback` protegido para processamento de autenticação

### 2. **Gerenciamento Seguro de Cookies**

#### Configurações de Cookie Hardening:
- **HttpOnly**: `true` - Previne acesso via JavaScript (proteção contra XSS)
- **SecurePolicy**: `Always` - Cookies transmitidos apenas via HTTPS
- **SameSite**: `Lax` - Proteção contra CSRF mantendo usabilidade
- **Sliding Expiration**: Renovação automática de sessão em uso ativo
- **Tempo de Expiração**: 7 dias com renovação deslizante

### 3. **Rate Limiting (Limitação de Taxa)**

Proteção contra ataques de força bruta e DDoS:
- **Limite Global**: 100 requisições por minuto por usuário/host
- **Janela Fixa**: Renovação a cada 1 minuto
- **Auto Replenishment**: Reabastecimento automático de permissões
- **Status Code 429**: Resposta padrão para requisições excedentes

### 4. **CORS (Cross-Origin Resource Sharing)**

Política restritiva de compartilhamento de recursos:
- **Origem Específica**: Permite apenas domínios configurados
- **Credenciais Permitidas**: Suporte a cookies e autenticação
- **Configuração via appsettings**: URL do frontend gerenciada externamente

### 5. **Security Headers (Cabeçalhos de Segurança HTTP)**

#### Headers implementados:

| Header | Valor | Proteção |
|--------|-------|----------|
| `X-Content-Type-Options` | `nosniff` | Previne MIME type sniffing |
| `X-Frame-Options` | `DENY` | Proteção contra Clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Filtro XSS do navegador |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controle de informações de referência |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Desabilita APIs sensíveis |
| `Content-Security-Policy` | Ver detalhes abaixo | Previne XSS e injeção de código |

#### Content Security Policy (CSP) Detalhada:

```plaintext
// Exemplo de diretiva CSP
default-src 'self'; // Apenas permite recursos do mesmo origem
script-src 'self' https://apis.google.com; // Permite scripts da própria origem e do Google APIs
style-src 'self' 'unsafe-inline'; // Permite estilos da própria origem e inline
img-src 'self' data:; // Permite imagens da própria origem e imagens embutidas
font-src 'self' https://fonts.gstatic.com; // Permite fontes da própria origem e do Google Fonts
connect-src 'self' https://www.googleapis.com; // Permite conexões da própria origem e com a API do Google
```

### 6. **Autorização Baseada em Atributos**

- **[Authorize]**: Proteção de endpoints sensíveis
- **Respostas Personalizadas**: 
  - `401 Unauthorized` para requisições não autenticadas
  - `403 Forbidden` para acessos negados
- **Tratamento de Redirecionamentos**: Diferenciação entre requisições API e web

### 7. **Gerenciamento Seguro de Configurações**

- **User Secrets**: Credenciais sensíveis armazenadas fora do código-fonte
- **Validação de Configuração**: Lançamento de exceções para configurações ausentes

### 8. **Logging e Auditoria**

- **ILogger Integration**: Logging estruturado para rastreamento de eventos
- **Dependency Injection**: Logger injetado nos controllers para auditoria

### 9. **Proteção de Dados Pessoais (LGPD/GDPR Ready)**

- **Mínimo Necessário**: Coleta apenas email, nome e foto do perfil
- **Sem Persistência Desnecessária**: Dados mantidos apenas em sessão
- **Logout Completo**: Limpeza de sessão e cookies no logout

## 🚀 Configuração

### Pré-requisitos

- .NET 8.0 SDK
- Credenciais OAuth do Google Cloud Console

### Variáveis de Ambiente/Configuração

Configure no `appsettings.json` ou User Secrets:


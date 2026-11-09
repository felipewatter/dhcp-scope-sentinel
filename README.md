# DHCP ScopeSentinel

**Auditoria defensiva de DHCPv4, segurança do plano de endereçamento e prevenção de regressões operacionais — 100% offline.**

[![CI](https://github.com/felipewatter/dhcp-scope-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/dhcp-scope-sentinel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/felipewatter/dhcp-scope-sentinel)](https://github.com/felipewatter/dhcp-scope-sentinel/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)

> **O que faz:** compara a configuração pretendida de escopos DHCP, pools, reservas, gateways, DNS, servidores permitidos e relays com invariantes de segurança e evidências normalizadas de ofertas DHCP. Produz achados explicáveis e bloqueia alterações de alto risco em pipelines. **Não captura tráfego, não altera servidores e não se conecta à rede.**

[English documentation](README.en.md) · [Arquitetura](docs/ARCHITECTURE.md) · [Esquema JSON](docs/SCHEMA.md) · [Modelo de ameaças](docs/THREAT_MODEL.md) · [Runbook operacional](docs/OPERATIONS.md) · [Política de segurança](SECURITY.md)

## Por que este projeto existe

Alterações em servidores DHCP, reservas e roteamento são uma fonte recorrente de incidentes operacionais: distribuição de IP duplicado, sobreposição entre pools, configuração de gateway indevido, reservas inconsistentes em failover, roteamento conflitante entre segmentos e mudanças na lista de servidores autorizados. A simples passagem do servidor pelo teste de sintaxe não garante que o *plano lógico de endereços* não sofreu uma regressão.

O **DHCP ScopeSentinel** cria uma etapa de revisão prévia para operações de infraestrutura, SRE e segurança. Uma exportação normalizada representa o estado proposto; um contrato separado, mantido pela equipe de segurança, representa controles que a própria proposta não pode ampliar livremente. Opcionalmente, registros de **DHCPOFFER já coletados por meios autorizados** permitem correlacionar servidor, IP oferecido e opções recebidas.

**Importante:** este projeto não afirma impedir um DHCP rogue em tempo real; não substitui DHCP snooping, ARP inspection, 802.1X, segurança de portas ou a inspeção do tráfego real. Nem todo DHCPOFFER suspeito representa uma concessão, e Option 82 não autentica o remetente criptograficamente.

## Funcionalidades

| Módulo | Capacidade técnica | Evidência / saída |
| --- | --- | --- |
| Plano IPv4 | Validação estrita de redes, gateway, VRF, VLAN e hosts utilizáveis | `DHCP007` |
| Pools | Verificação de intervalos sobrepostos, auto-sobreposição e endereços de infraestrutura | `DHCP001`, `DHCP004`, `DHCP009` |
| Failover declarativo | Coerência entre pools, exclusões, reservas e pares de servidores | `DHCP002` |
| Reservas | Identificação de IPs repetidos, mesmo cliente com IPs divergentes e reserva dinâmica sem exclusão | `DHCP005`, `DHCP008` |
| Servidores | Servidores de escopo e identificadores observados versus autorizados | `DHCP003`, `DHCP101` |
| Opções observadas | Divergência de gateway, DNS e IP oferecido | `DHCP102`–`DHCP104`, `DHCP107`–`DHCP108` |
| Relay | Presença e valor de identificadores de relay em registros normalizados | `DHCP105` |
| Indícios de colisão | Mesma oferta de endereço para múltiplos clientes, sem alegar conflito de lease | `DHCP106` |
| Contratos independentes | Mínimo de capacidade, limite de escopos, relay obrigatório, DNS, servidores/gateway/rede/relays permitidos | `DHCP201`–`DHCP208` |
| Change gate | Fingerprint SHA-256 estável, introduzidos / persistentes / resolvidos | `diff`, `--all-findings` |
| Integração DevSecOps | JSON, SARIF 2.1.0, saída determinística e códigos de saída | GitHub Actions 3 SO × 3 Python |

**25 regras de achados** são definidas em `src/dhcp_scope_sentinel/engine.py`. Os limites de dados e formatos estão descritos em [SCHEMA.md](docs/SCHEMA.md).

## Instalação

Pré-requisitos: **Python 3.11, 3.12 ou 3.13** e `pip`. O motor usa exclusivamente a biblioteca padrão do Python em tempo de execução.

```bash
# Após clonar o repositório
python -m pip install -e .
dhcp-scope-sentinel --version
```

É possível operar sem instalar:

```bash
PYTHONPATH=src python -m dhcp_scope_sentinel --version
```

No Windows PowerShell, utilize `python -m pip install -e .` e o comando `dhcp-scope-sentinel` normalmente; para executar a partir da árvore sem instalação, configure `$env:PYTHONPATH='src'`.

## Primeiro teste: ambiente esperado versus desvio inseguro

Os exemplos contêm exclusivamente **endereços de documentação fictícia de laboratório** em uma faixa privada e identificadores inventados; não há exportação real de cliente.

### 1) Auditar a configuração esperada

```bash
dhcp-scope-sentinel audit examples/baseline.json \
  --policy examples/contracts.json \
  --fail-on high
```

**Resultado esperado:** relatório com `findings: []` e **exit code `0`**.

### 2) Detectar comportamento divergente

```bash
dhcp-scope-sentinel diff examples/baseline.json \
  examples/candidate-risky.json \
  --policy examples/contracts.json \
  --fail-on high
```

**Resultado esperado:** achados críticos referentes a servidor não autorizado e gateway divergente, entre outras evidências, com **exit code `2`**. O ambiente não é acessado ou alterado.

### 3) Gerar relatórios JSON e SARIF

```bash
mkdir -p reports
dhcp-scope-sentinel diff examples/baseline.json \
  examples/candidate-risky.json \
  --policy examples/contracts.json \
  --json-out reports/dhcp-diff.json \
  --sarif-out reports/dhcp-diff.sarif
```

**Atenção:** saídas existentes **não são sobrescritas**. Remova ou renomeie o relatório antigo antes de repetir a exportação. O comando `mkdir -p` é compatível com shells Unix; no PowerShell, crie a pasta via `New-Item -ItemType Directory -Force reports`.

### 4) Escolher a severidade do gate

```bash
# Bloquear apenas achados críticos
dhcp-scope-sentinel audit examples/candidate-risky.json --fail-on critical

# Produzir relatório sem bloquear pipeline
dhcp-scope-sentinel audit examples/candidate-risky.json --fail-on none

# Bloquear também achados que já existiam no baseline
dhcp-scope-sentinel diff examples/baseline.json examples/candidate-risky.json --all-findings
```

| Código | Interpretação | Orientação no CI |
| --- | --- | --- |
| `0` | Sem achados no limiar selecionado | Continuar (o resultado **não prova** a segurança da rede) |
| `2` | Achados iguais ou superiores ao limiar | Bloquear alteração e revisar evidências |
| `3` | Entrada/saída inválida ou insegura | Bloquear pipeline e corrigir exportação/esquema |

Erros de uso do `argparse` utilizam seu código habitual `2` e mensagem em `stderr`; diferencie esse cenário pela estrutura do relatório e pela ausência de resultado de auditoria. Em pipelines, forneça argumentos válidos previamente.

## Modelo de dados

Uma **fotografia de estado** contém `schema_version: 1`, `segments` e, opcionalmente, `observations`:

```json
{
  "schema_version": 1,
  "segments": [
    {
      "id": "SCHOOL-LAB", "vrf": "CAMPUS", "vlan": 120,
      "network": "10.20.120.0/24", "gateway": "10.20.120.1",
      "dns_servers": ["10.20.0.10"],
      "authorized_servers": ["10.20.0.2"],
      "trusted_relays": ["relay-campus-120"], "require_relay": true,
      "scopes": [{
        "id": "LAB", "server": "10.20.0.2",
        "pools": [["10.20.120.100", "10.20.120.180"]],
        "exclusions": [], "reservations": []
      }]
    }
  ]
}
```

Um **contrato** é separado da fotografia do serviço, permitindo revisão e versionamento próprios:

```json
{
  "schema_version": 1,
  "contracts": [{
    "segment": "SCHOOL-LAB",
    "approved_network": "10.20.120.0/24",
    "approved_gateway": "10.20.120.1",
    "authorized_server_allowlist": ["10.20.0.2"],
    "trusted_relay_allowlist": ["relay-campus-120"],
    "must_require_relay": true,
    "min_usable_capacity": 60,
    "max_scopes": 2,
    "dns_allowlist": ["10.20.0.10"]
  }]
}
```

Detalhes dos campos, validações, limitações de capacidade e representação de `observations` estão em [docs/SCHEMA.md](docs/SCHEMA.md). A ferramenta **não traduz** configurações DHCP de fornecedores; importe somente JSON normalizado previamente validado pelo operador.

## Como a detecção de regressão funciona

1. Interpreta, normaliza e valida os dois snapshots com a mesma política externa.
2. Avalia todas as regras separadamente no baseline e no candidato.
3. Gera um fingerprint SHA-256 de `(rule, segment, subject, detail)`. Alterações na evidência criam uma nova ocorrência; reordenações de objetos não criam diferenças artificiais.
4. Classifica em `introduced`, `persistent` e `resolved`.
5. Por padrão, o comando `diff` bloqueia apenas achados introduzidos. Use `--all-findings` para bloquear também achados persistentes.

**Importante:** um baseline vulnerável pode fazer achados conhecidos parecerem persistentes. Para auditorias contínuas rigorosas, use `--all-findings` e contratos externos revisados separadamente.

## Modelo de risco e limitações explícitas

O modelo é intencionalmente restrito ao IPv4, com intervalos finitos e campos estritamente declarados. Não há simulação de servidor Kea, Microsoft DHCP ou ISC, protocolos DHCPv6/RA, estado real de lease, latência, DHCP snooping, autenticação de Option 82, ARP/DAD, troca real de pacotes nem inferência de host físico. Um **DHCPOFFER não comprova um ACK ou conflito de lease**. Por isso o alerta de ofertas concorrentes tem nível `medium` e é descrito como hipótese. Falta de observações não representa inexistência de servidores indevidos.

Um identificador de servidor inserido no JSON não é evidência autenticada; configure a coleta por meios confiáveis e preserve a cadeia de custódia. Não inclua endereços reais, MACs, nomes de clientes, IDs pessoais ou logs operacionais sigilosos em issues ou repositórios públicos.

## Segurança da implementação

- Limite de **2 MB por JSON**, 35.000 nós, 28 níveis de profundidade, no máximo 200 segmentos e 5.000 observações por snapshot.
- Falha explícita para chaves duplicadas, IPv6 fora do escopo, IPs não canônicos, campos inesperados e estruturas malformadas.
- Sem scripts, execução de comandos externos, avaliação dinâmica nem conexões de rede no runtime.
- Recusa a links simbólicos de entrada, destinos existentes e tentativas de sobrescrever entrada/contrato.
- Relatórios JSON determinísticos e SARIF, com fingerprints de ocorrências.
- GitHub Actions com ações fixadas em SHA, `contents:read` na CI, liberação restrita ao commit `main` aprovado, tags históricas preservadas.
- Arquivos da distribuição verificados por manifesto SHA-256 e checksums. **SHA-256 verifica integridade, não autenticidade criptográfica da autoria.**

Veja [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) para ameaças não mitigadas e riscos residuais.

## Qualidade e testes

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/build_release.py dist
```

A matriz definida em `.github/workflows/ci.yml` executa em **Ubuntu, Windows e macOS**, nas versões Python **3.11, 3.12 e 3.13** (9 combinações). O workflow de release recompila e retesta no commit que realmente passou pela CI, confirma que a `main` não avançou e publica exclusivamente uma nova tag SemVer, sem regravar versões publicadas.

## Produção e operação

O projeto é uma **ferramenta de revisão**, não um serviço em execução permanente. O uso em ambientes reais requer:

1. Inventariar os escopos DHCPv4 por segmento/VRF e transformar o export de fornecedor em JSON normalizado revisado.
2. Versionar o contrato de segurança fora da área de modificação do operador que prepara a proposta.
3. Obter logs de observação apenas de fontes autorizadas, com retenção e anonimização adequadas.
4. Executar a auditoria no CI antes da mudança e submeter as divergências ao responsável de infraestrutura.
5. Validar a mudança real com mecanismos próprios do fornecedor, DHCP snooping, monitoração e testes de cliente controlados.

**Uso defensivo e autorizado exclusivamente.** Não contém exploit, sniffer ou código de intrusão.

## Referências e trabalhos relacionados

A implementação usa conceitos descritos nos seguintes padrões e projetos, sem copiar seus códigos:

- [RFC 2131 — Dynamic Host Configuration Protocol](https://www.rfc-editor.org/rfc/rfc2131.html)
- [RFC 2132 — DHCP Options and BOOTP Vendor Extensions](https://www.rfc-editor.org/rfc/rfc2132.html)
- [RFC 3046 — DHCP Relay Agent Information Option](https://www.rfc-editor.org/rfc/rfc3046.html)
- [RFC 5227 — IPv4 Address Conflict Detection](https://www.rfc-editor.org/rfc/rfc5227.html)
- [Kea DHCP (ISC)](https://www.isc.org/kea/)
- [SpatiumDDI — plataforma DDI](https://github.com/spatiumnorth/spatiumddi)
- [rDHCP — servidor DHCP em Rust](https://github.com/ZerosAndOnesLLC/rDHCP)

**Diferencial:** não é servidor DHCP nem console IPAM nem detector ativo. Seu foco é um *security gate* declarativo, offline, determinístico, com contrato externo e histórico de achados para revisão de mudanças.

## Licença e autoria

MIT — consulte [LICENSE](LICENSE). Desenvolvido por **Felipe Watter**; contribuições e relatos responsáveis de falhas são bem-vindos conforme [CONTRIBUTING.md](CONTRIBUTING.md) e [SECURITY.md](SECURITY.md).

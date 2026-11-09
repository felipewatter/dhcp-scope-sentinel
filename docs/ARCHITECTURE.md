# Arquitetura técnica

## Objetivo

Detectar riscos de consistência e segurança no *planejamento* de DHCPv4 e em observações normalizadas, sem tornar o analisador um agente com acesso privilegiado à rede.

```text
              snapshots JSON                       contratos JSON (governança)
             baseline / candidato                   mantidos separadamente
                       |                                      |
                       v                                      v
             parse.load() + _bounded()            parse.load() + parse_contracts()
                       |                                      |
                       v                                      v
                    model.parse() <--------------------  política validada
                       |
               Intervalos / VRFs / scopes
                       |
                       v
                    engine.audit()
                       |
         ----------------+------------------
         |                                   |
   Auditoria simples                         Diff de baseline/candidato
         |                                   |
         |                         hashlib.sha256(rule + evidência)
         |                                   |
         +----------------+------------------+
                          |
                          v
                  relatório determinístico
                     JSON + SARIF
                          |
                          v
                  gate de severidade (0/2/3)
                          |
                          v
                 CI/CD / aprovação humana
```

## Pacotes

| Arquivo | Responsabilidade |
| --- | --- |
| `parse.py` | Leitura local limitada, recusa de JSON inválido, de campos inesperados, duplicatas e links de entrada |
| `model.py` | Construção de dataclasses imutáveis, endereços IPv4, intervalos e relações entre escopos |
| `engine.py` | Regras de consistência, contratos independentes, intervalos, severidades e fingerprints |
| `report.py` | JSON ordenado e SARIF 2.1.0 sem dados inventados de linha/coluna |
| `cli.py` | Orquestração, comparação, controle de falha e escrita atômica sem sobrescrever arquivos |
| `scripts/build_release.py` | ZIP de fontes reproducível, manifesto de hashes e lista SHA-256 |

## Semântica de falha

- **Erro de parsing/contrato** → `3`: aborta com mensagem em `stderr`, não assume resultado seguro.
- **Finding de severidade >= limiar** → `2`: relatório completo presente.
- **Nenhum finding no limiar** → `0`: somente indicação de conformidade com regras e observações fornecidas.
- **Diff padrão** bloqueia novos achados; `--all-findings` inclui os persistentes.
- **Mudança da política em paralelo** pode esconder o desvio; por isso contratos precisam de aprovação em outra trilha.

## Integridade e cadeia de distribuição

1. CI é executada no `main` e em PRs, em matriz de nove ambientes.
2. Workflow `release` recebe somente evento `workflow_run` bem-sucedido de push para `main` no repositório de origem.
3. O job com `contents:write` confirma via API GitHub que SHA testado = HEAD da `main` = checkout local.
4. Compara a versão do pacote (`__version__`) com `pyproject.toml`.
5. Recusa a criação se a tag já existir; não modifica releases antigos.
6. Reexecuta a suíte, monta ZIP de fontes e wheel, gera manifesto e SHA256SUMS.
7. Publica release apenas para a nova versão imutável.

### Análise de complexidade

As comparações de intervalos entre escopos são limitadas pelos tamanhos aceitos do JSON. A capacidade utiliza operações aritméticas sobre intervalos, **não expande endereços do IPv4**, mantendo uso de memória previsível para redes grandes. Como o snapshot inteiro cabe em 2 MB e há limites de elementos, uma entrada adversarial não deve ter liberdade para produzir listas ilimitadas.

## Limitações de escopo

A operação não executa o protocolo DHCP nem simula a lógica exata dos servidores. Não observa uplinks reais, não verifica o roteamento, não autentica Option 82 e não comprova leases ativos. Para avaliar um fornecedor concreto, é necessário implementar um adaptador com suporte semântico específico e testes adicionais.

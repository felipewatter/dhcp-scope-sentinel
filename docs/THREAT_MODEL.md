# Modelo de ameaças — DHCP ScopeSentinel

## Ativos protegidos

1. **Integridade do plano de endereçamento:** pools, exclusões, reservas, gateway e sub-redes.
2. **Limites de confiança:** conjunto de servidores DHCP autorizados e relays esperados.
3. **Segurança de mudanças:** impedir regressão não revisada ao integrar configuração nova.
4. **Integridade de evidências:** preservar distinção entre dado observado e conclusão técnica.
5. **Integridade de relatórios e release:** não sobrescrever entradas/artefatos históricos.

## Adversários e cenários

| Ameaça | Risco | Mitigação implementada | Limite conhecido |
| --- | --- | --- | --- |
| Operador habilita servidor externo no escopo | Servidor não aprovado passa a receber endereços | `DHCP003` + `DHCP206` com allowlist externa | Sem verificação de origem em rede |
| Servidor não autorizado anuncia IP, router ou DNS divergente | Redirecionamento de tráfego ou indisponibilidade | `DHCP101`–`DHCP107` com observações normalizadas | `server_ip`, `router`, DNS e relay podem ser forjados na evidência |
| Dois escopos distribuem a mesma faixa | Conflito operacional de endereçamento | `DHCP001` e consistência estrita de failover `DHCP002` | Não simula mecanismos exclusivos de fornecedor |
| Reserva e pool permitem mesmo endereço | Alocação indesejada | `DHCP008`, com aviso para evitar falso positivo de operação | Alguns fornecedores são seguros sem exclusão explícita |
| Alguém amplia a própria lista de confiança | Autoaprovação maliciosa | `DHCP206`/`207`/`208` validados por contrato externo | Governança do contrato deve estar fora da autoridade do proponente |
| JSON adversarial consome recursos | DoS de ferramenta de CI | Limites de bytes, profundidade, nós e tamanho de listas | Não substitui sandbox do runner |
| JSON possui chave duplicada | Divergência no parsing | Erro fail-closed ao encontrar duplicata | Não interpreta formatos alternativos |
| Caminho de relatório aponta para contrato | Sobrescrita de controle de segurança | Recusa de input/output alias e saída existente; escrita atômica | Não isola usuário local privilegiado com permissão no mesmo diretório |
| PR externo manipula release | Publicação de código não testado | Evento de push interno, SHA exato, `main` inalterada, permissão mínima e release imutável | Requer confiança no GitHub Actions e conta do mantenedor |

## Presunções de confiança

- Dados são **normalizados por um operador** e obtidos por fontes autorizadas. Logs de DHCPOFFER podem estar incompletos, truncados ou manipulados; não são certificados pelo analisador.
- IDs de relay não são autenticação do relay por si mesmos. O RFC 3046 define subopções, mas o ambiente deve implementar as próprias políticas de confiança.
- O contrato possui processo de revisão distinto; se um atacante controla tanto o snapshot quanto o contrato, consegue alterar o objetivo de segurança.
- As regras são invariantes **escolhidos**, e não modelo completo de todo equipamento ou caminho de pacote.

## Fora do escopo deliberado

- DHCPv6, RA, roteamento IPv6 e DHCPv6 Shield.
- Sniffer, sondagem ativa, DHCP starvation, simulação de redes reais e detecção em tempo real.
- Tradução direta de `dhcpd.conf`, JSON do Kea, Windows DHCP/PowerShell ou pacotes PCAP.
- Validação de ACK, leases reais e detecção definitiva de colisões em hosts; RFC 5227 requer observação de conflitos IPv4 e não pode ser inferido de um único OFFER.
- Autenticidade dos registros, assinatura de relatórios ou de release, verificação de execução em hardware de rede.

## Segurança operacional recomendada

- Combine os relatórios com DHCP snooping, ACLs, proteção de switch e logs assinados quando disponíveis.
- Faça revisão por pares de todo desvio `critical/high` e dos contratos alterados.
- Mantenha logs reais fora do repositório; use IDs anonimizados em testes e issues.
- Execute em runners com permissões mínimas e retenção de artefatos definida.
- Nunca execute alteração de configuração automaticamente com base apenas neste relatório.

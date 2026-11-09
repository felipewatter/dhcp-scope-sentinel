# Runbook de Operação — revisão de alterações DHCP

## Preparação

1. Faça o inventário da fonte (Windows DHCP, Kea, ISC ou documentação interna).
2. Extraia os campos mínimos: segmentos/VRFs, redes, gateways, servidores, pools, exclusões e reservas.
3. Normalize manualmente para `schema_version=1` ou utilize um adaptador específico revisado.
4. Anonimize IDs de cliente e hosts antes de compartilhar exemplos.
5. Versione `contracts.json` de forma independente da configuração candidata.
6. Copie `examples/baseline.json` e `examples/contracts.json` para seu workspace privado, substituindo dados fictícios pelos autorizados.

## Pré-mudança

```bash
dhcp-scope-sentinel audit baseline.json --policy contracts.json --fail-on high
dhcp-scope-sentinel diff baseline.json candidato.json --policy contracts.json --fail-on high
```

Se um achado for introduzido:

- `critical`: interrompa a aprovação, revise servidor DHCP, router e allowlists do contrato.
- `high`: valide sobreposição, endereços protegidos, failover, escopos e modificações no segmento.
- `medium`: investigue a origem, fornecedor e as condições operacionais; falsos positivos são possíveis.
- Erro `3`: revise exportação, CIDR canônico, opções obrigatórias, duplicações e encoding UTF-8.

## Pós-mudança

1. Valide efetivamente os escopos no fornecedor e confirme sincronismo do failover.
2. Verifique relays e DHCP snooping na infraestrutura, especialmente VLANs novas.
3. Colete amostras autorizadas de respostas e confirme opções gateway/DNS quando disponíveis.
4. Compare logs reais de ACK e mecanismos de detecção de conflitos; DHCPOFFER sozinho não prova lease.
5. Salve relatórios em armazenamento com política de acesso; guarde links da aprovação/change ticket.

## Tratamento de incidentes

Uma observação `DHCP101` não comprova automaticamente um rogue DHCP: valide o identificador com o endereço de origem, ponto de captura e registros da rede. Se confirmado servidor indevido, siga o procedimento interno de resposta a incidentes e controles no switch, sem deixar a ferramenta realizar ações automáticas.

## Política de saída

Os caminhos de destino precisam ser novos; o processo não sobrescreve dados existentes. Para um novo run, utilize pastas ou nomes separados (por exemplo, vinculados a ID de change). Diferencie CIDR/VRF de segmento de endpoints de infraestrutura centralizados: servidores DNS e DHCP podem legitimamente estar fora da sub-rede de cliente.

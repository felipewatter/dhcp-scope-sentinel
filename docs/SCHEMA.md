# Especificação de entrada — DHCP ScopeSentinel v1

A ferramenta aceita exclusivamente **JSON normalizado**, não configurações brutas. Não há execução de código, de scripts ou comandos de rede. Todos os nomes, endereços e contratos devem representar evidência obtida por meios autorizados.

## Estrutura de um snapshot

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
      "static_hosts": [{"ip": "10.20.120.10", "asset": "print-server"}],
      "scopes": [
        {
          "id": "LAB", "server": "10.20.0.2",
          "pools": [["10.20.120.100", "10.20.120.180"]],
          "exclusions": [["10.20.120.150", "10.20.120.150"]],
          "reservations": [{"ip": "10.20.120.150", "client_id": "training-terminal"}],
          "failover_group": "CAMPUS-HA"
        }
      ]
    }
  ],
  "observations": [
    {
      "segment": "SCHOOL-LAB", "server_ip": "10.20.0.2",
      "offered_ip": "10.20.120.115", "client_id": "lab-011",
      "router": "10.20.120.1", "dns_servers": ["10.20.0.10"],
      "relay_id": "relay-campus-120"
    }
  ]
}
```

O `schema_version` obrigatório deve ser o **número inteiro** 1. O conjunto `segments` deve ser não vazio, com `id` exclusivo. `observations` é opcional, mas **ausência de observações não é ausência de ameaça**.

### Segmento

| Campo | Obrigatório | Significado e validação |
| --- | --- | --- |
| `id` | Sim | Identificador único, até 64 caracteres, `[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}` |
| `vrf` | Sim | Domínio de roteamento. Redes repetidas em VRFs distintos são permitidas |
| `vlan` | Sim | Inteiro de 1 a 4094; serve como metadado de inventário |
| `network` | Sim | Rede IPv4 em CIDR **canônico**, com prefixo máximo `/30` |
| `gateway` | Sim | Endereço de host válido dentro de `network`, sem ser rede ou broadcast |
| `dns_servers` | Sim | Lista de até 16 IPv4, com ordem considerada significativa em observações |
| `authorized_servers` | Sim | Lista não vazia, sem duplicações, de até 16 IPv4 permitidos; servidor pode estar fora da sub-rede |
| `trusted_relays` | Não | Lista de até 64 IDs não duplicados de relay, até 64 caracteres cada |
| `require_relay` | Não | Booleano, padrão `false`. Se `true`, exige `trusted_relays` não vazio e `relay_id` nas observações |
| `static_hosts` | Não | Até 2000 objetos `{ip, asset}`; endereços de host únicos na sub-rede |
| `scopes` | Sim | Lista não vazia de até 200 escopos por segmento |

### Escopo

| Campo | Obrigatório | Semântica |
| --- | --- | --- |
| `id` | Sim | Identificador único do escopo dentro do segmento |
| `server` | Sim | Identificador IPv4 do servidor responsável pelo escopo |
| `pools` | Sim | Até 300 intervalos `[primeiro, último]` inclusivos; podem estar vazios se houver reservas |
| `exclusions` | Sim | Até 300 intervalos excluídos da alocação dinâmica |
| `reservations` | Sim | Até 1000 registros `{ip, client_id}`; um escopo pode funcionar só com reservas |
| `failover_group` | Não | ID de grupo de failover; dois escopos com mesmo grupo devem ter pools, exclusões e reservas idênticos, em servidores diferentes |

Intervalos devem possuir extremos válidos e ordenados dentro da mesma rede. Um IP reservado que também aparece no pool deve estar excluído da alocação dinâmica para não gerar `DHCP008` (aviso `medium`). Isso é um modelo conservador; alguns fornecedores podem tratar reservas dentro de pools de forma segura sem exclusão explícita, exigindo análise humana.

### Observação normalizada

`observations` aceita até 5000 objetos. Campos obrigatórios: `segment`, `server_ip`, `offered_ip`, `client_id`. Campos opcionais: `router`, `relay_id`, `dns_servers`.

`server_ip` representa o **identificador declarado** do servidor em uma observação coletada previamente. Não é necessariamente o IP de origem real do pacote, tampouco é autenticado por esta ferramenta. `relay_id` reflete a evidência normalizada disponível; algumas capturas do lado cliente não contêm Option 82 porque um relay pode removê-la. A ausência deve ser analisada conforme ponto de coleta, nunca assumida como violação confirmada.

`router` e `dns_servers` são opcionais porque nem todos os registros possuem opções DHCP completas. Uma opção ausente não é tratada como divergência observada.

## Arquivo de política independente

```json
{
  "schema_version": 1,
  "contracts": [{
    "segment": "SCHOOL-LAB",
    "min_usable_capacity": 60,
    "max_scopes": 2,
    "must_require_relay": true,
    "dns_allowlist": ["10.20.0.10", "10.20.0.11"],
    "authorized_server_allowlist": ["10.20.0.2", "10.20.0.3"],
    "approved_gateway": "10.20.120.1",
    "approved_network": "10.20.120.0/24",
    "trusted_relay_allowlist": ["relay-campus-120"]
  }]
}
```

Cada contrato identifica um segmento, e IDs são exclusivos. Os campos adicionais são opcionais e estritos: capacidade e máximo de escopos são inteiros não negativos; `must_require_relay` é booleano; listas aceitam identificadores/endereço IPv4 conforme indicado. Se um segmento indicado não existir no snapshot, gera `DHCP205`.

A lista de servidores do snapshot pode ser alterada por um operador. Por isso **recomenda-se `authorized_server_allowlist` em um arquivo separado**, com controle de alterações distinto, para evitar que o mesmo PR amplie silenciosamente os próprios servidores confiáveis. A mesma lógica se aplica a `approved_gateway`, `approved_network` e `trusted_relay_allowlist`.

## Regras e severidades

O catálogo executável está em `src/dhcp_scope_sentinel/engine.py` (`RULES`). Categorias:

- `DHCP001`–`DHCP009`: consistência de plano, reservas, gateway e failover.
- `DHCP101`–`DHCP108`: identificação e opções em observações fornecidas.
- `DHCP201`–`DHCP208`: restrições de contratos independentes.

### Capacidade utilizável

A capacidade `min_usable_capacity` corresponde à **união de intervalos alocáveis** por escopo, descontando exclusões *do próprio escopo*, IPs de gateway, inventário estático e reservas. Não enumera todos os hosts e não equivale a leases disponíveis em tempo real. A união entre escopos é feita apenas uma vez, inclusive em pares de failover. Isso protege o cálculo contra dupla contagem.

## Limites e erros

- Até **2 MB por arquivo**, até **35 mil nós JSON**, até **28 níveis** de profundidade.
- Identificadores têm até 64 caracteres, sem espaço, barra ou controle; listas e identificadores duplicados rejeitados quando invalidam a estrutura.
- Valores `NaN`, `Infinity`, CIDR com bits de host, network/broadcast em pools, IPv6 e campos não declarados são inválidos.
- Links simbólicos são recusados na entrada; outputs existentes são recusados para impedir sobrescrita.
- `schema_version` desconhecido encerra a operação com erro e exit code 3.

**Compatibilidade:** o modelo não declara conformidade com um arquivo de configuração específico de ISC DHCP, Kea ou Microsoft DHCP. Crie um adaptador separado com testes e revisão humana. A implementação não suporta DHCPv6, RA, gestão de leases nem autodescoberta.

# DHCP ScopeSentinel v0.1.0 — primeira versão pública

Ferramenta **offline** para auditar consistência e segurança de escopos DHCPv4 e observações normalizadas de DHCPOFFER.

- Escopos, pools, exclusões, reservas e failover declarativo com invariantes explicadas.
- Detecção de conflitos com gateway, inventário estático, VRFs e endereços reservados.
- Identificação de servidores não autorizados, divergência de gateway/DNS e suspeitas em identificadores de relay em evidências fornecidas.
- Contratos de segurança independentes do snapshot para capacidade, relay, DNS e orçamento de scopes.
- Comparação baseline/candidate com fingerprints estáveis, classificação de introduzidos/persistentes/resolvidos e bloqueio em CI.
- JSON determinístico, SARIF 2.1.0 e saídas protegidas contra sobrescrita.
- Testes adversariais, CI 3 sistemas x 3 versões Python, pacote wheel, ZIP de fontes, manifesto e checksums SHA-256.

**Aviso:** não detecta DHCP rogue em tempo real, não interpreta PCAP/exports brutos de fabricantes, não autenticará Option 82, não envia pacotes e não garante ausência de conflitos reais. Leitura de RFC 2131/2132/3046 e `docs/THREAT_MODEL.md` recomendada.

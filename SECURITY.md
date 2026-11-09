# Política de Segurança

## Divulgação responsável

Abra um aviso privado via **Security > Advisories > Report a vulnerability** no repositório do GitHub.
Não abra issues públicas com exploits, segredos ou registros DHCP reais.
Descreva versão, pré-condições, entrada mínima fictícia, impacto e passos para reprodução.

## Limites de segurança

- Programa passivo/offline. Não acessa equipamentos, não autentica servidores DHCP e não transmite pacotes.
- O formato de entrada é JSON normalizado; não lê configurações ISC/Kea/Windows DHCP diretamente.
- Dados de IP, client_id e identificadores de relay podem conter metadados sensíveis: processe localmente e controle acesso aos relatórios.
- A ferramenta identifica inconsistência com a configuração informada, não prova ocorrência de ataques ou de conflitos reais de leases.
- Um `server_ip` nos dados de observação é uma declaração externa, não um identificador criptograficamente autenticado.
- Exigir aprovação humana antes de qualquer alteração de rede.

## Proteções existentes

- Sem `eval`, execução de shell ou dependências de rede na rotina principal.
- Limites de tamanho, profundidade, nós e contagem de objetos; rejeição de chaves duplicadas, valores não canônicos, campos desconhecidos e links simbólicos de entrada.
- Recusa de sobrescrita de arquivos de entrada e saída, com publicação atômica em caminho novo.
- GitHub Actions com privilégios mínimos, ações fixadas por SHA e release vinculado ao commit exato de `main` aprovado pela CI.
- Releases históricos imutáveis. SHA-256 detecta alterações acidentais ou posteriores, mas **não fornece assinatura de origem**.

Leia `docs/THREAT_MODEL.md` para ameaças fora do escopo.

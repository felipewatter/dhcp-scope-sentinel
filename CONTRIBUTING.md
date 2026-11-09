# Contribuindo

## Ambiente

- Python 3.11+ (3.11, 3.12 e 3.13 na matriz de CI).
- Execute `python -m pip install -e .` e `python -m unittest discover -s tests -v`.
- Execute `python -m compileall -q src tests scripts` antes de enviar PR.
- Utilize apenas dados fictícios nos exemplos e nos logs de testes.

## Regras de contribuição

1. Abra uma issue com o cenário reproduzível e o impacto operacional.
2. Proponha testes que falhem antes da correção e passem depois.
3. Prefira alterações pequenas, com tipos explícitos e sem dependências desnecessárias.
4. Preservar semântica **fail-closed**: entradas não modeladas devem resultar em erro explícito, nunca permissão presumida.
5. Não misture regras observacionais com prova de comportamento do equipamento; relatórios devem distinguir hipótese, evidência e conclusão.
6. Evite algoritmos que expandam redes inteiras em memória (ex.: um /8).
7. Atualize README e documentação de ameaças quando o escopo ou semântica mudar.
8. Não force `main`, não mova tags, não regrave releases; use versionamento SemVer.

## Checklist do PR

- [ ] Regressões e testes de casos adversariais incluídos.
- [ ] CI nas nove combinações verde.
- [ ] Nenhum segredo, cliente real, IP sensível ou pacote PCAP incluído.
- [ ] Alterações explicadas e limitações documentadas.
- [ ] Sem execução de comandos externos sobre dispositivos.

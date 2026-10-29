# Eventos EVE JSON e Guia de Telemetria

O Suricata utiliza o formato **EVE (Extensible Event Format)** para registrar eventos estruturados em JSON em uma única linha por evento.

---

## Tipos de Eventos Suportados

1. **`alert`:** Violações de regras de detecção. Contém `gid`, `signature_id` (SID), `rev`, `signature`, `category`, `severity`.
2. **`flow`:** Resumo estatístico de fluxos de rede bidirecionais. Contém contadores de pacotes (`pkts_toserver`, `pkts_toclient`), bytes e timestamps de início/término.
3. **`dns`:** Consultas e respostas de nomes de domínio, com `rrname`, `rrtype`, `rcode` (ex: `NXDOMAIN`) e endereços IP resolvidos.
4. **`http`:** Transações completas da camada de aplicação web, incluindo `hostname`, `url`, `http_method`, `user_agent`, `status` e tamanhos.
5. **`tls`:** Metadados de handshake SSL/TLS, incluindo Server Name Indication (`sni`), versão negociada, fingerprint e certificados emitidos.
6. **`ssh`:** Conexões Secure Shell, versões de cliente e servidor e algoritmos criptográficos.
7. **`fileinfo`:** Arquivos transferidos na rede identificados pelo motor, com hashes (`md5`, `sha256`) e tamanhos.
8. **`anomaly`:** Anomalias em pacotes de rede (como tamanho inválido de cabeçalho IP ou flags TCP corrompidas).
9. **`stats`:** Métricas periódicas de contadores de pacotes, descartes no kernel e consumo de memória.

---

## Leitura de Alta Performance sem Esgotamento de Memória

Para ambientes de alta volumetria:
* O MCP lê o arquivo de trás para frente usando saltos de bloco de 64 KB (`tail_eve_events`).
* Para consultas em massa ou streaming, utilize `stream_eve_events` que consome apenas uma linha por iteração via gerador Python.


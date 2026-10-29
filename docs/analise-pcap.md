# Análise Forense Offline de Capturas PCAP

O módulo de análise offline do **Suricata MCP Server** permite que analistas de segurança e agentes de IA processem arquivos de captura de tráfego de rede (.pcap e .pcapng) de forma isolada e segura.

---

## Fluxo de Execução Offline

```
[Arquivo PCAP Autorizado]
          |
          v
[Validação de Magic Bytes & Tamanho]  --> Rejeita se corrompido ou > SURICATA_MAX_PCAP_SIZE_MB
          |
          v
[Criação de Diretório Temporário Isolado] (/tmp/suricata_pcap_analysis_XXXXXX)
          |
          v
[Execução do Motor] -> suricata -r captura.pcap -l /tmp/... --runmode single
          |
          v
[Ingestão e Parser de eve.json Temporário]
          |
          v
[Resumo de Alertas, Protocolos e Fluxos]
          |
          v
[Limpeza Segura dos Artefatos Temporários]
```

---

## Políticas de Proteção Forense

1. **Restrição de Diretório:** Apenas arquivos situados dentro da pasta definida em `SURICATA_PCAP_ALLOWED_DIR` podem ser analisados.
2. **Prevenção de DoS:** Limite estrito de tamanho de arquivo (`SURICATA_MAX_PCAP_SIZE_MB`, padrão: 100 MB) e timeout de processo de 60 segundos.
3. **Isolamento de Estado:** A análise offline nunca altera as estatísticas nem os arquivos de log do sensor em tempo real.


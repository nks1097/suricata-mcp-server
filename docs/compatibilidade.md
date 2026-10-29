# Matriz de Compatibilidade

Esta matriz detalha as versões do Suricata, sistemas operacionais e interpretadores Python homologados com o **Suricata MCP Server**.

---

## 1. Versões do Suricata

| Versão do Suricata | Leitura EVE JSON | Validação Config (-T) | Unix Socket / Named Pipe | Análise Offline PCAP | Suporte Oficial |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **8.0.x** (ex: 8.0.7) | :white_check_mark: Pleno | :white_check_mark: Pleno | :white_check_mark: Suportado | :white_check_mark: Pleno | :star: Recomendado |
| **7.0.x** (ex: 7.0.6) | :white_check_mark: Pleno | :white_check_mark: Pleno | :white_check_mark: Suportado | :white_check_mark: Pleno | :white_check_mark: Estável |
| **6.0.x** | :white_check_mark: Pleno | :white_check_mark: Pleno | :warning: Recursos limitados | :white_check_mark: Pleno | :warning: Legado |
| **< 6.0** | :warning: Parcial | :x: Incompatível | :x: Não suportado | :warning: Parcial | :x: Descontinuado |

---

## 2. Sistemas Operacionais

| Sistema Operacional | Arquitetura | Modo STDIO | Modo SSE (HTTP) | Mecanismo de Captura Típico |
| :--- | :---: | :---: | :---: | :--- |
| **Linux (Ubuntu / Debian / RHEL)** | x86_64, aarch64 | :white_check_mark: | :white_check_mark: | AF_PACKET, XDP, PCAP |
| **Windows 10 / 11 / Server** | x86_64 | :white_check_mark: | :white_check_mark: | Npcap, WinDivert |
| **macOS (Darwin)** | arm64, x86_64 | :white_check_mark: | :white_check_mark: | BPF, PCAP |
| **Docker / Kubernetes** | Linux Container | :white_check_mark: | :white_check_mark: | Host Network / Mounted Volumes |

---

## 3. Interpretadores Python

* **Python 3.11:** Suportado e testado em CI.
* **Python 3.12:** Recomendado para implantações em produção.
* **Python 3.13 / 3.14:** Compatível e homologado.

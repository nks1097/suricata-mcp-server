"""Parser analítico, agregador estatístico e correlacionador de eventos EVE JSON."""

import math
from collections import Counter, defaultdict
from typing import Any


def calculate_shannon_entropy(text: str) -> float:
    """Calcula a entropia de Shannon de uma string (útil para detectar domínios DGA)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = Counter(text)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Produz um resumo executivo consolidado da distribuição dos eventos coletados."""
    total = len(events)
    tipos_contagem: Counter = Counter()
    ips_origem: Counter = Counter()
    ips_destino: Counter = Counter()
    alertas_severidade: Counter = Counter()
    assinaturas: Counter = Counter()
    protocolos: Counter = Counter()

    for ev in events:
        ev_type = ev.get("event_type", "desconhecido")
        tipos_contagem[ev_type] += 1

        if "src_ip" in ev:
            ips_origem[ev["src_ip"]] += 1
        if "dest_ip" in ev:
            ips_destino[ev["dest_ip"]] += 1
        if "proto" in ev:
            protocolos[ev["proto"]] += 1

        if ev_type == "alert" and "alert" in ev and isinstance(ev["alert"], dict):
            al = ev["alert"]
            alertas_severidade[str(al.get("severity", "N/A"))] += 1
            assinaturas[al.get("signature", "Desconhecida")] += 1

    return {
        "total_eventos": total,
        "distribuicao_tipos": dict(tipos_contagem.most_common(10)),
        "distribuicao_protocolos": dict(protocolos.most_common(10)),
        "top_ips_origem": dict(ips_origem.most_common(5)),
        "top_ips_destino": dict(ips_destino.most_common(5)),
        "alertas_por_severidade": dict(alertas_severidade),
        "top_assinaturas_alerta": dict(assinaturas.most_common(5)),
    }


def analyze_top_talkers(events: list[dict[str, Any]], top_n: int = 10) -> dict[str, Any]:
    """Identifica os IPs e portas mais ativos por volume de eventos e bytes observados."""
    origens: Counter = Counter()
    destinos: Counter = Counter()
    portas_origem: Counter = Counter()
    portas_destino: Counter = Counter()
    bytes_por_ip: Counter = Counter()

    for ev in events:
        src = ev.get("src_ip")
        dest = ev.get("dest_ip")
        if src:
            origens[src] += 1
        if dest:
            destinos[dest] += 1

        if "src_port" in ev:
            portas_origem[str(ev["src_port"])] += 1
        if "dest_port" in ev:
            portas_destino[str(ev["dest_port"])] += 1

        # Soma bytes de fluxos quando presentes
        flow = ev.get("flow")
        if isinstance(flow, dict):
            bytes_total = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
            if src:
                bytes_por_ip[src] += bytes_total
            if dest:
                bytes_por_ip[dest] += bytes_total

    return {
        "top_ips_origem": [{"ip": ip, "contagem": count} for ip, count in origens.most_common(top_n)],
        "top_ips_destino": [{"ip": ip, "contagem": count} for ip, count in destinos.most_common(top_n)],
        "top_portas_origem": [{"porta": p, "contagem": count} for p, count in portas_origem.most_common(top_n)],
        "top_portas_destino": [{"porta": p, "contagem": count} for p, count in portas_destino.most_common(top_n)],
        "top_ips_volume_bytes": [{"ip": ip, "bytes": b} for ip, b in bytes_por_ip.most_common(top_n)],
    }


def detect_network_scans(events: list[dict[str, Any]], threshold_ports: int = 10) -> list[dict[str, Any]]:
    """Identifica padrões comportamentais compatíveis com varreduras de portas ou hosts (Portscan/Hostscan)."""
    targets_per_source: dict[str, set[str]] = defaultdict(set)
    ports_per_source: dict[str, set[int]] = defaultdict(set)
    event_counts: Counter = Counter()

    for ev in events:
        src = ev.get("src_ip")
        dest = ev.get("dest_ip")
        dest_port = ev.get("dest_port")

        if src and dest:
            event_counts[src] += 1
            targets_per_source[src].add(dest)
            if dest_port is not None:
                ports_per_source[src].add(dest_port)

    suspects = []
    for src, ports in ports_per_source.items():
        hosts = targets_per_source[src]
        if len(ports) >= threshold_ports or len(hosts) >= 20:
            suspects.append(
                {
                    "ip_origem": src,
                    "portas_distintas_tocadas": len(ports),
                    "hosts_distintos_tocados": len(hosts),
                    "total_eventos": event_counts[src],
                    "tipo_varredura": "Horizontal (vários hosts)"
                    if len(hosts) > len(ports)
                    else "Vertical (muitas portas no mesmo host)",
                    "amostra_portas": sorted(list(ports))[:10],
                }
            )

    return sorted(suspects, key=lambda x: x["portas_distintas_tocadas"] + x["hosts_distintos_tocados"], reverse=True)


def detect_suspicious_dns(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analisa consultas DNS procurando sinais de DGA, túneis DNS ou domínios de alta entropia."""
    suspicious = []
    for ev in events:
        if ev.get("event_type") != "dns":
            continue
        dns_data = ev.get("dns")
        if not isinstance(dns_data, dict):
            continue

        rrname = dns_data.get("rrname", "")
        if not rrname:
            continue

        # Calcula entropia do subdomínio
        subdomain = rrname.split(".")[0]
        entropy = calculate_shannon_entropy(subdomain)
        length = len(subdomain)

        motivos = []
        if entropy > 3.8 and length > 12:
            motivos.append("Alta entropia de caracteres (possível DGA)")
        if length > 45:
            motivos.append("Comprimento de consulta anômalo (possível tunelamento DNS/Exfiltração)")
        if dns_data.get("rcode") in ("NXDOMAIN", "SERVFAIL"):
            motivos.append(f"Código de resposta indicativo de erro: {dns_data.get('rcode')}")

        if motivos:
            suspicious.append(
                {
                    "timestamp": ev.get("timestamp"),
                    "cliente_ip": ev.get("src_ip"),
                    "dominio": rrname,
                    "entropia": entropy,
                    "comprimento_subdominio": length,
                    "motivos": motivos,
                    "tipo_consulta": dns_data.get("rrtype", "A"),
                }
            )

    return suspicious[:50]


def build_network_timeline(events: list[dict[str, Any]], target_ip: str | None = None) -> list[dict[str, Any]]:
    """Organiza eventos cronologicamente para reconstrução forense de incidentes."""
    timeline = []
    for ev in events:
        src = ev.get("src_ip", "")
        dest = ev.get("dest_ip", "")

        if target_ip and target_ip not in (src, dest):
            continue

        ev_type = ev.get("event_type")
        summary = ""

        if ev_type == "alert":
            al = ev.get("alert", {})
            summary = f"ALERTA [{al.get('severity', '?')}]: {al.get('signature', 'Desconhecido')}"
        elif ev_type == "dns":
            dns = ev.get("dns", {})
            summary = f"DNS Query: {dns.get('rrname', '')} ({dns.get('rrtype', '')})"
        elif ev_type == "http":
            http = ev.get("http", {})
            summary = f"HTTP {http.get('http_method', 'REQ')}: {http.get('hostname', '')}{http.get('url', '')}"
        elif ev_type == "tls":
            tls = ev.get("tls", {})
            summary = f"TLS SNI: {tls.get('sni', '')} (Versão: {tls.get('version', '')})"
        elif ev_type == "flow":
            flow = ev.get("flow", {})
            summary = f"Fluxo encerrado: {flow.get('bytes_toclient', 0) + flow.get('bytes_toserver', 0)} bytes"
        else:
            summary = f"Evento {ev_type} ({ev.get('proto', '')})"

        timeline.append(
            {
                "timestamp": ev.get("timestamp"),
                "tipo": ev_type,
                "origem": f"{src}:{ev.get('src_port', '')}",
                "destino": f"{dest}:{ev.get('dest_port', '')}",
                "resumo": summary,
                "dados_brutos": ev,
            }
        )

    # Ordena pelo timestamp
    return sorted(timeline, key=lambda x: str(x.get("timestamp", "")))

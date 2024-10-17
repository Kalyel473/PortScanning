import nmap
import json
import os
import requests

def obter_sistema_operacional(nm, host):
    os_info = nm[host].get('osclass', [])
    return os_info[0]['osfamily'] if os_info else 'Desconhecido'

def verificar_vulnerabilidades(service, version):
    # Exemplo simples de verificação de vulnerabilidades
    # Você pode usar a API do CVE para verificar vulnerabilidades
    cve_api_url = f'https://cve.circl.lu/api/search/{service}/{version}'
    response = requests.get(cve_api_url)
    return response.json() if response.status_code == 200 else []

def scanner_vulnerabilidades(target, port_range):
    nm = nmap.PortScanner()

    print(f"Iniciando a varredura de {target}...")

    # Realiza a varredura de portas
    nm.scan(target, arguments=f'-sV -sC -O -p {port_range}')  # Adiciona '-O' para detectar o sistema operacional

    results = {}
    
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"Estado: {nm[host].state()}")
        results[host] = {
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'os': obter_sistema_operacional(nm, host),
            'protocols': {}
        }

        for proto in nm[host].all_protocols():
            print(f"\nProtocolo: {proto}")
            lport = nm[host][proto].keys()
            sorted_ports = sorted(lport)

            for port in sorted_ports:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']
                script_output = nm[host][proto][port].get('script', {})

                print(f"Porta: {port}\tEstado: {state}\tServiço: {service}\tVersão: {version}")

                # Verifica vulnerabilidades conhecidas
                vulnerabilities = verificar_vulnerabilidades(service, version)
                if vulnerabilities:
                    print(f"\tVulnerabilidades conhecidas: {', '.join([v['id'] for v in vulnerabilities])}")

                if script_output:
                    for script_name, output in script_output.items():
                        print(f"\tSaída do script {script_name}: {output}")

                results[host]['protocols'][proto] = results[host]['protocols'].get(proto, {})
                results[host]['protocols'][proto][port] = {
                    'state': state,
                    'service': service,
                    'version': version,
                    'script_output': script_output,
                    'vulnerabilities': vulnerabilities
                }

    return results

def salvar_resultados(results, target):
    filename = f"scan_results_{target}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\nResultados salvos em {filename}")

def main():
    while True:
        try:
            alvo = input("Digite o endereço IP ou hostname para escanear (ou 'sair' para encerrar): ")
            if alvo.lower() == 'sair':
                break
            port_range = input("Digite o intervalo de portas para escanear (ex: 1-1000 ou 22,80,443): ")
            resultados = scanner_vulnerabilidades(alvo, port_range)
            salvar_resultados(resultados, alvo)
        except Exception as e:
            print(f"Ocorreu um erro: {e}")

if __name__ == "__main__":
    main()

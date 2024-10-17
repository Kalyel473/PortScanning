# PortScanning
Vulnerability Scanner é uma ferramenta de linha de comando desenvolvida em Python que utiliza a biblioteca Nmap para realizar varreduras de rede e identificar vulnerabilidades em serviços expostos.

# Vulnerability Scanner

Vulnerability Scanner é uma ferramenta de linha de comando desenvolvida em Python que utiliza a biblioteca Nmap para realizar varreduras de rede e identificar vulnerabilidades em serviços expostos. O scanner é projetado para ajudar profissionais de segurança cibernética a identificar potenciais riscos em sistemas, proporcionando um meio eficiente de coleta de informações sobre serviços em execução e suas vulnerabilidades conhecidas.

## Funcionalidades

- Varredura de Rede: Realiza varreduras de hosts em um intervalo de portas especificado.
- Detecção de Sistema Operacional: Identifica o sistema operacional em execução em cada host.
- Detecção de Serviços e Versões: Coleta informações sobre serviços expostos e suas versões.
- Verificação de Vulnerabilidades: Consulta a API do CVE para identificar vulnerabilidades conhecidas associadas a serviços e versões detectados.
- Resultados em JSON: Salva os resultados da varredura em um arquivo JSON para fácil análise posterior.

## Requisitos

- Python 3.x
- Biblioteca Nmap (`python-nmap`)
- Biblioteca Requests

### Instalação

Para instalar as dependências, execute:

```bash
pip install python-nmap requests

## Uso

1. **Clone o Repositório**

   Primeiro, clone o repositório para sua máquina local:

   ```bash
   git clone https://github.com/seu_usuario/vulnerability_scanner.git
   cd vulnerability_scanner

Exemplo de Uso
python scanner.py

Digite o endereço IP ou hostname para escanear (ou 'sair' para encerrar): 192.168.1.1
Digite o intervalo de portas para escanear (ex: 1-1000 ou 22,80,443): 1-1000

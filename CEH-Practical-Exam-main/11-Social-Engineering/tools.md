<<<<<<< HEAD
# Social Engineering Tools

## Phishing
=======
 Social Engineering Tools

 Phishing
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

 SET (Social Engineering Toolkit)
- setoolkit: Framework principal
- Spear Phishing: Emails direcionados
- Web Attack: Ataques web
- Infectious Media: Mídia infectada

<<<<<<< HEAD

##  Email Spoofing
=======
 Gophish
- Phishing Campaign: Campanhas de phishing
- Email Templates: Templates de email
- Landing Pages: Páginas de captura

 Email Spoofing
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

 Swaks
- SMTP Testing: Teste de SMTP
- Email Crafting: Criação de emails

 Sendmail
- Mail Server: Servidor de email
- Mail Relay: Relay de email

<<<<<<< HEAD
## Information Gathering
=======
 Information Gathering
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

 Maltego
- OSINT: Open Source Intelligence
- Link Analysis: Análise de relacionamentos
- Data Mining: Mineração de dados

 Sherlock
- Username Search: Busca de usernames
- Social Media: Redes sociais
- Account Discovery: Descoberta de contas

 OSINT Tools

 TheHarvester
- Email Harvesting: Coleta de emails
- Subdomain Discovery: Descoberta de subdomínios
- OSINT Gathering: Coleta de informações

 Recon-ng
- Reconnaissance Framework: Framework de reconhecimento
- API Integration: Integração com APIs
- Data Correlation: Correlação de dados

<<<<<<< HEAD
# Scripts
=======
 Scripts Úteis
>>>>>>> c1b4712547a17da4c827bb6759b6cfb87d5bc851

 SET Usage
setoolkit
 1) Social-Engineering Attacks
 2) Website Attack Vectors
 3) Credential Harvester Attack Method

 Email harvesting
theharvester -d target.com -l 500 -b all

 Username enumeration
sherlock username

 Recon-ng
recon-ng
workspaces create target
modules load recon/domains-hosts/google_site_web
options set SOURCE target.com
run

 Swaks email testing
swaks --to target@example.com --from admin@company.com --header "Subject: Test" --body "Test message"

 Maltego transformations
maltego
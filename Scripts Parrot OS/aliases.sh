recon() {
  ~/Desktop/ceh-tools/recon.sh "$@"
}

nmapq() {
  ~/Desktop/ceh-tools/nmap_quick.sh "$@"
}

sqlmap_auto() {
  python3 ~/Desktop/ceh-tools/sqlmap_auto.py "$@"
}

wpscan_auto() {
  python3 ~/Desktop/ceh-tools/wpscan_auto.py "$@"
}

hydra_ssh() {
  ~/Desktop/ceh-tools/hydra_ssh.sh "$@"
}

payloads() {
  ~/Desktop/ceh-tools/generate_payloads.sh "$@"
}

brute() {
  ~/Desktop/ceh-tools/brute_force_launcher.sh "$@"
}
ceh_auto() {
  ~/Desktop/ceh-tools/ceh_master_auto.sh "$@"
}
ceh_report() {
  ~/Desktop/ceh-tools/ceh_report_summary.sh "$1"
}

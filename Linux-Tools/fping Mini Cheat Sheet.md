````markdown
# ⚡ fping Mini Cheat Sheet

## Básico
```bash
fping host              # ping único
fping host1 host2 ...   # múltiplos hosts
fping -f hosts.txt      # lista de hosts
````

## Descoberta de Hosts

```bash
fping -a -g 192.168.1.0/24 2>/dev/null   # só hosts vivos
fping -g 192.168.1.1 192.168.1.100       # range específico
```

## Modos

```bash
fping -l google.com      # loop (como ping)
fping -q -g 192.168.1.0/24   # modo quiet
```

## Opções Úteis

* `-a` → alive only
* `-u` → unreachable only
* `-g` → range/subnet scan
* `-f file` → lista de hosts
* `-r N` → retries
* `-t ms` → timeout
* `-i ms` → intervalo entre pings do mesmo host
* `-p ms` → intervalo entre hosts
* `-C N` → N pings por host
* `-q` → quiet mode

## Exemplos Rápidos

```bash
fping -a -r1 -g 10.0.0.0/24   # scan rápido
fping -C 5 -q -f hosts.txt    # 5 pings c/ estatísticas
fping -t 200 -r0 -g 192.168.0.0/24   # timeout curto, sem retries
```

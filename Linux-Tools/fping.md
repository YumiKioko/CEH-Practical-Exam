
````markdown
# 📝 fping Cheat Sheet

## 🔹 Básico
```bash
fping host
````

Ping em um único host (como `ping` tradicional).

```bash
fping host1 host2 host3
```

Ping em múltiplos hosts.

```bash
fping -f hosts.txt
```

Ping em todos os hosts de um arquivo (um host/IP por linha).

---

## 🔹 Descoberta de Hosts

```bash
fping -a -g 192.168.1.0/24 2>/dev/null
```

Mostra **apenas hosts ativos** em uma sub-rede.

* `-a` → mostra somente vivos
* `-g` → gera range de IPs
* `2>/dev/null` → suprime erros

```bash
fping -g 192.168.1.1 192.168.1.100
```

Ping de um range específico.

---

## 🔹 Modos de Execução

```bash
fping -l google.com
```

Modo contínuo (loop), como `ping`.

```bash
fping -q -g 192.168.1.0/24
```

Modo silencioso: só mostra resumo no final.

---

## 🔹 Opções Úteis

* `-a` → mostra só hosts *alive*.
* `-u` → mostra só hosts *unreachable*.
* `-g` → gera ranges/sub-redes (`192.168.1.0/24`).
* `-f file` → lê lista de hosts de um arquivo.
* `-r N` → número de *retries* (tentativas).
* `-t ms` → timeout em milissegundos.
* `-i ms` → intervalo entre pacotes para o mesmo host.
* `-p ms` → intervalo entre pings a hosts diferentes.
* `-C N` → envia N pings por host (útil para estatísticas).
* `-q` → quiet mode (apenas resultados, sem detalhes).

---

## 🔹 Exemplos Avançados

```bash
fping -a -r1 -g 10.0.0.0/24
```

Descoberta rápida de hosts ativos (1 retry por IP).

```bash
fping -C 5 -q -f hosts.txt
```

Manda 5 pings para cada host da lista e mostra estatísticas.

```bash
fping -t 200 -r 0 -g 192.168.0.0/24
```

Varre a rede com timeout curto (200ms), sem retries.

---

## 🔹 Saída Típica

Alive (respondendo):

```
192.168.1.1 is alive
```

Unreachable (não responde):

```
192.168.1.50 is unreachable
```

Com `-a` → só mostra os vivos:

```
192.168.1.1
192.168.1.22
192.168.1.33
```

```

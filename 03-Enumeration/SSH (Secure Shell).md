
## Basic Syntax

```
ssh [user@]hostname [command]
```

## Examples

### Connect to a remote server

```
ssh user@192.168.1.10
```

### Specify a different port

```
ssh -p 2222 user@192.168.1.10
```

### Use an identity file (private key)

```
ssh -i ~/.ssh/id_rsa user@hostname
```

### Run a remote command

```
ssh user@hostname 'ls -la /var/www'
```

### Enable verbose output for debugging

```
ssh -v user@hostname
```

## Tips

- SSH keys can be generated with `ssh-keygen`
- Copy your public key to a server using `ssh-copy-id user@hostname`
- Use `~/.ssh/config` to simplify host configurations

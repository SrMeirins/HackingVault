En ocasiones, si tenemos varios saltos hacia la maquina y nos da algo de pereza y tediosidad pasarnos archivos (habría que configurar un socat inverso o hacer varios saltos), podemos crearnos un inspector de procesos manual en bash:

```zsh
#!/bin/bash

IFS=$'\n'

old=$(ps -eo command)
while true; do
    new=$(ps -eo command)
    diff <(echo "$old") <(echo "$new") | grep [\<\>]
    sleep .3
    old=$new
done
```
echo
echo " Busca claves privadas  en el SO Linux "
echo " hackingyseguridad.com 2024 "
echo 
echo
find / -maxdepth 5 -name .ssh -exec grep -rnw {} -e 'PRIVATE' \; 2> /dev/null

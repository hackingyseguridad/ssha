*** key_algorithms *** , server_host_key_algorithms, mac_algorithms, compression_algorithms “sería poco relevantes” los ahí ofrecidos siempre y cuando los cifrados de trasporte(encryption_algorithms) permitidos sea los recomendados.

*** kex_algorithms: *** ecdh-sha2-nistp256, ecdh-sha2-nistp384,  ecdh-sha2-nistp521, diffie-hellman-group-exchange-sha1 

*** server_host_key_algorithms: *** rsa, sha, sha1   eliminar de la configuración RSA, como cifrado para la clave, y ofrecer por ejemplo como alternativas las combinaciones: rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519
https://www.endpointdev.com/blog/2023/04/ssh-host-key/# 
Desde la versión OpenSSH 8.8, el algoritmo de clave ssh-rsa ha sido deshabilitado. En versiones anteriores, podemos deactivarlo a mano, editando en el fichero /etc/ssh/sshd_config, y eliminando de Host KeyAlgorithms +ssh-rsa:

*** encryption_algorithms: *** aes128-cbc, aes192-cbc. aes256-cbc

*** mac_algorithms: *** () recomendados hmac. Para evitar incidencias de clientes SSH que no soportan hmac, ofrecer por ahora también todas las combinaciones: mac umac. 

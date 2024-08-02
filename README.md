# skanner
"skanner" és una utilitat que he desenvolpat per ús personal i destinada a operacions de descobriment en xarxes locals. Hi ha moltíssimes utilitats semblants, però per millorar el meu aprenentage del llenguatge Rust, vaig creure que podia ser un projecte interessant, sobretot si vols accedir a operacions de baix nivell.
Les operacions que es poden fer amb aquesta utilitat, són bàsicament un ping, un scaneig de ports oberts, resoldre noms a partir de la IP, i testejar quins protocols SSL/TLS suporta un servidor d'aplicacions (IIS,Apache,Nginx,Apache Tomcat,etc). Molt simple. La gràcia està en "com es fa", ja que un ping es molt fàcil d'utilitzar, però no tant fàcil de programar.

## Desenvolupament
Per desevolupar les diferents funcions, he utilitzat les llibreries:
* libc (https://docs.rs/libc/latest/libc/)
* openssl (https://docs.rs/openssl/latest/openssl/)
* openssl-sys (https://crates.io/crates/openssl-sys)

La idea en aquest projecte era programar operacions simples de xarxa a baix nivell, i interactuar amb openssl per poder interrogar un servidor i poder veure quins protocols suporta (amb això podem saber, quins servidors de la nostra xarxa encara suporten TLS1.0 o TLS1.1).

Amb crates de tercers i la llibreria std::net, es podrien fer les operacions a més alt nivell, però no és el que buscava.

## Funcionament
Si us baixeu el codi font, i teniu el Rust instal.lat:
<code>
echo 172.16.1.1-254 | sudo cargo run
echo 172.16.1.1-254 | sudo cargo run -- 80,443
echo 172.16.1.30-40 | sudo cargo run --resolv
echo google.com | sudo cargo run -- 443 ssl

</code>
Com es pot veure, és poden fer diferents combinacions.
Per compilar versió cal:
<code>
cargo build --release
</code>
Dins la carpeta target/release tenim l'executable (Mac/Linux). I ja el podem utilitzar.

Exemple d'ús:
<code>
echo 172.16.1.1-100 | sudo ./skanner | sudo ./skanner 443 | cut -d "," -f 1 | sudo ./skanner resolv | cut -d "," -f 2 | sudo ./skanner 443 ssl
</code>
Li passem un rang d'IP's, mira si estan actives. De les actives mira si tenen el port 443 obert. De les que tene el port obert, resolt el nom, i després mirar quins protocols ssl té disponibles. Si apareix algún amb protocols inferiosr a TLS1.2, són vulnerables.



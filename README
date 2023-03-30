# DATAPLANE ROUTER

322CA - Bianca Ștefania Dumitru
Protocoale de comunicatii

Martie 2023
----------------------------------------------------------------------------------------------------
## Introducere

* Dataplane router
  *  programul implementeaza un dataplane router in Linux
  *  scopul principal consta in dirijarea pachetelor IP intre hosti
  *  routerul implementeaza si trimiterea de pachete ICMP, atunci cand e cazul
  *  determinarea adreselor MAC vecine se realizeaza cu ajutorul protocolului ARP

## Cum functioneaza?

### Initializare

La initializare, routerul aloca memorie pentru tabela ARP pe care urmeaza sa o populeze
si creeaza trie-ul ce va asigura cautarea eficienta a longest prefix match cu un IP
dat in tabela de rutare.

### Receptionare

Un pachet este receptionat pe una din interfetele routerului. Se extrage headerul
de ethernet al pachetului primit si se determina IP-ul interfetei respective si se
 verifica daca pachetul foloseste protocolul IPv4 sau ARP.

### Protocolul IPv4

Routerul extrage headerul IP al pachetului si face anumite verificari:
* Daca routerul este destinatarul pachetului, se trimite inapoi un pachet ICMP de tip echo reply
* Se verifica checksum-ul. In cazul in care pachetul a fost corupt, routerul il arunca.
* Se verifica daca TTL > 2. In caz contrar, e trimis inapoi un pachet ICMP de tipul time exceeded.

Dupa aceste verificari, routerul determina urmatorul hop pana la destinatar. Acest
lucru este realizat prin interogarea trie-ului anterior creat, care returneaza intrarea
corecta din tabela de rutare. Daca nu exista nicio intrare care se potriveste destinatiei
date, atunci routerul intoarce un pchet ICMP de tip destination unreachable.

Este decrementat apoi TTL-ul si recalculat checksum. In headerul ethernet, sursa MAC este
setata la MAC-ul interfetei pe care urmeaza sa fie trimis pachetul.

Este cautat in tabela locala ARP MAC-ul next hop-ului. Daca acesta se afla deja acolo, pachetul
este trimis cu succes mai departe. Altfel, pachetul este adaugat intr-o coada pentru a se putea
reveni la el mai tarziu si routerul realizeaza un ARP request pentru determinarea adresei MAC a next hop-ului.

### Protocolul ARP

Atunci cand se determina ca pachetul primit urmeaza protocolul ARP, se extrage headerul ARP din
buffer si se verifica daca pachetul este de tip ARP request sau ARP reply.

In cazul ARP request, routerul verifica ca el este destinatarul, caz in care trimite un reply,
instiintand sender-ul de adresa lui MAC.

In cazul ARP reply, routerul primeste raspuns la requestul facut anterior, in cadrul procesarii
pachetelor IPv4. Se retine in tabela locala ARP raspunsul primit si se parcurge coada, cautandu-se
toate pachetele IPv4 care asteptau acest raspuns. Pachetele respective sunt acum trimise mai departe.

### ICMP

Pachetele de tip ICMP sunt compuse din headerele de ethernet, IP si ICMP. 

## Resurse
* Enuntul temei - https://pcom.pages.upb.ro/tema1/
* Networking tutorial - https://youtube.com/playlist?list=PLowKtXNTBypH19whXTVoG3oKSuOcw_XeW
* LPM cu trie - https://www.lewuathe.com/longest-prefix-match-with-trie-tree.html


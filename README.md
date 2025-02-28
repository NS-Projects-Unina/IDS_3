*REALIZZAZIONE DI UN SISTEMA NETWORK-BASED DI INTRUSION DETECTION*

Il sistema è realizzato da 0 implementando le 3 componenti principali di ogni IDS:

SERVER PRINCIPALE (server.js): il server principale, realizzato in ambiente node.js, espone l'interfaccia grafica e una rotta chiamante lo script per l'analisi. 
ANALYZER: script python che prende in input il file generato dal comando airodump-ng, avviato dal server principale su richiesta del client.
SENSORE: scheda wireless esterna utilizzata in modalità monitor tramite VM kali linux. 

Il funzionamento complessivo è  il seguente:
1) Si avvia in modalità monitor la scheda wireless, tramite comando *airodump-ng*, l'output della cattura viene salvato ciclicamente su una cartella condivisa con il sistema host.
2) Il server node.js viene avviato. L'utente si collega al server e visualizza inizialmente una tabella vuota, in automatico parte una richiesta al server che avvia l'esecuzione dell'analyzer sul file generato dal sensore che ciclicamente verrà aggiornato con i nuovi dati raccolti. I risultati dell'analisi vengono salvati su un db per mantenere uno storico, e visualizzati nella tabella vista dall'utente.

Tuttavia, l'avvio e la gestione del sensore devono ancora essere gestiti manualmente operando direttamente da prompt all'interno della VM, e utilizzando il seguente comando:

    while true; do
    rm -f *percorso_cartella_condivisa*/capture.csv
    airodump-ng -w *percorso_cartella_condivisa*/capture --output-format csv wlan0
    sleep 10
    done


In questo modo, il file su cui viene chiamata l'analisi si aggiorna con lo stesso intervallo rispetto alle chiamate effettuate dal client. Seppur rudimentale, questo meccanismo permette un analisi quasi live di quanto catturato dal sensore.

La comunicazione tra client e server è criptata utilizzando HTTPS.

*CONTENUTO DELLA DIRECTORY*

Sono presenti all'interno della cartella i seguenti file:
1) Per *HTTPS*: file di configurazione utilizzato per generare certificato e chiave privata, avvalendosi del tool da linea di comando *openssl*.
2) Server.js: il file javascript del server, sono presenti  anche i file json e la cartella riguardanti i moduli utilizzati nel codice (generati automaticamente, in seguito all'installazione con npm).
3) Cartella Interfaccia: contentente codice html e codice javascript per il riempimento della tabella mediante chiamata alla rotta del server.
4) Raccolta.csv: è fornito all'intero della cartella un file di esempio di raccolta dati, per simulare l'utilizzo del sistema senza sensore.

*UTILIZZO*

Previa l'installazione dell'ambiente node.js e del database mongodb, il server sia avvia tramite comando da terminale *node server.js* ed è consultabile all'indirizzo *localhost:8080*




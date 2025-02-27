*REALIZZAZIONE DI UN SISTEMA NETWORK-BASED DI INTRUSION DETECTION*

Il sistema è realizzato da 0 implementando le 3 componenti principali di ogni IDS:

SERVER PRINCIPALE (server.js): il server principale, realizzato in ambiente node.js, espone l'interfaccia grafica e una rotta chiamante lo script per l'analisi. 
ANALYZER: script python che prende in input il file generato dal comando airodump-ng, avviato dal server principale su richiesta del client.
SENSORE: scheda wireless esterna utilizzata in modalità monitor tramite VM kali linux. 

Il funzionamento complessivo è  il seguente:
1) Si avvia in modalità monitor la scheda wireless, tramite comando *airodump-ng*, l'output della cattura viene salvato ciclicamente su una cartella condivisa con il sistema host.
2) Il server node.js viene avviato. L'utente si collega al server e visualizza inizialmente una tabella vuota, in automatico parte una richiesta al server che avvia l'esecuzione dell'analyzer sul file generato dal sensore che ciclicamente verrà aggiornato con i nuovi dati raccolti. I risultati dell'analisi vengono salvati su un db per mantenere uno storico, e visualizzati nella tabella vista dall'utente.

Tuttavia, l'avvio e la gestione del sensore deve ancora essere gestite manualmente operando direttamente da linea di comando all'interno della VM. La comunicazione tra client e server è criptata utilizzando HTTPS.


# Progetto del corso Advanced Operating system

Le specifiche in dettaglio del progetto in questione sono raggiungibili al seguente link: https://francescoquaglia.github.io/TEACHING/AOS/AA-2023-2024/PROJECTS/project-specification-2023-2024.html

## Indice
1. [Descrizione](#Descrizione)
2. [Modalità di funzionamento](#Modalità-di-funzionamento)
3. [Comportamento](#comportamento)
4. [Implementazione](#implementazione)
5. [Istruzioni per l'installazione](#istruzioni-per-linstallazione)

## Descrizione
Questo progetto consiste nello sviluppo di un modulo del kernel Linux che implementa un reference monitor per la protezione dei file a livello del kernel. Il monitor è progettato per controllare e limitare le operazioni di scrittura sui file specificati, assicurando che tali operazioni siano consentite solo in determinate condizioni.

### Modalità di funzionamento
Il monitor può essere in uno dei seguenti quattro stati:

- OFF: le operazioni del monitor sono disabilitate.
- ON: le operazioni del monitor sono abilitate.
- REC-ON/REC-OFF: il monitor è configurabile (in modalità ON o OFF).

### Comportamento
La configurazione del monitor si basa su una serie di percorsi da proteggere. Ogni percorso indica un file o una directory che non deve poter essere modifica, quindi nè aperta in modalità scrittura, nè deve poter essere eliminata. Qualsiasi tentativo di modifica si traduce in un errore e in una terminazione del processo. L'aggiunta o la rimozione deri percorsi può essere fatta tramite le modalità "REC_ON" e "REC_OFF" del monitor. 
Oltre a poter selezionare una delle 4 modalità del monitor, è possibile per l'utente, decidere di cambiare la password, inserire un nuovo percorso protetto e rimuoverne uno già presente. 

### Implementazione
Gli stati del monitor vengono modificati tramite invocazioni alle API del Virtual File System. Insieme alla componente di livello kernel infatti, il progetto include il codice in spazio utente per invocare le API di sistema con parametri corretti. 
Il progetto prevede anche la gestione di un file gestito in deferred-work nel quale ad ogni tentata apertura in modifica di un file in un percorso protetto, vengono registrate informazioni riguardanti il processo chiamante. 

Il programma prevede inoltre una password iniziale riconfigurabile, impostata a "default".

Il progetto è stato testato con la versione del kernel di Linux pari a: 5.15.0-113

### Istruzioni per l'installazione
Dopo aver clonato il repository in questione, eseguire i seguenti comandi

- Per eseguire il deployment del monitor è possibile eseguire il file ``` start.sh ``` . Questo si occupa di compilare il monitor con le sue librerie,il filesystem e il codice per l'esecuzione dell'utente e successivamente esegue il caricamento e l'installazione di tutti i moduli necessari.
```bash
 ./start.sh
```

- Per eliminare tutti i file compilati ed installati con il comando procedente, e quindi smontare il monitor, eseguire il file ``` stop.sh ```.
```bash
 ./stop.sh
```

- Per caricare esclusivamente il reference monitor, eseguire il file ```load.sh```. 
```bash
 ./load.sh
```

- Per rimuovere solamente il reference monitor, eseguire il file ```unload.sh```.
```bash
 ./unload.sh
```

- Per eseguire il lato utente dell'applicativo e quindi poter interagire con il monitor tramite i possibili comandi specificati sopra, eseguire il file ```user.sh``` 
```bash
 ./user/user.sh
```

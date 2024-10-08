# Progetto del corso Advanced Operating system

Le specifiche in dettaglio del progetto in questione sono raggiungibili al seguente link: https://francescoquaglia.github.io/TEACHING/AOS/AA-2023-2024/PROJECTS/project-specification-2023-2024.html

## Indice
1. [Descrizione](#Descrizione)
2. [Modalità di funzionamento](#Modalità di funzionamento)
3. 

## Descrizione
Questo progetto consiste nello sviluppo di un modulo del kernel Linux che implementa un reference monitor per la protezione dei file a livello del kernel. Il monitor è progettato per controllare e limitare le operazioni di scrittura sui file specificati, assicurando che tali operazioni siano consentite solo in determinate condizioni.

### Modalità di funzionamento
Il monitor può essere in uno dei seguenti quattro stati:

- OFF: le operazioni del monitor sono disabilitate.
- ON: le operazioni del monitor sono abilitate.
- REC-ON/REC-OFF: il monitor è configurabile (in modalità ON o OFF).

### Comportamento
La configurazione del monitor si basa su una serie di percorsi da proteggere. Ogni percorso indica un file o una directory che non deve poter essere modifica, quindi nè aperta in modalità scrittura, nè deve poter essere eliminata. Qualsiasi tentativo di modifica si traduce in un errore e in una terminazione del processo. L'aggiunta o la rimozione deri percorsi può essere fatta tramite le modalità "REC_ON" e "REC_OFF" del monitor. 

### Implementazione
Gli stati del monitor vengono modificati tramite invocazioni alle API del Virtual File System.

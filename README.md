# Progetto del corso Advanced Operating system

Le specifiche in dettaglio del progetto in questione sono raggiungibili al seguente link: https://francescoquaglia.github.io/TEACHING/AOS/AA-2023-2024/PROJECTS/project-specification-2023-2024.html

## Descrizione
Questo progetto consiste nello sviluppo di un modulo del kernel Linux che implementa un reference monitor per la protezione dei file a livello del kernel. Il monitor è progettato per controllare e limitare le operazioni di scrittura sui file specificati, assicurando che tali operazioni siano consentite solo in determinate condizioni.

### Modalità di funzionamento
Il monitor può essere in uno dei seguenti quattro stati:

- OFF: le operazioni del monitor sono disabilitate.
- ON: le operazioni del monitor sono abilitate.
- REC-ON/REC-OFF: il monitor è configurabile (in modalità ON o OFF).

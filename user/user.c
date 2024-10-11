#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <ctype.h>

#define DEVICE_NAME "/dev/ref_monitor"



void display_menu() {
    printf("\n");
    printf("+--------------------------------------------+\n");
    printf("|         \033[1;34mREFERENCE MONITOR MENU\033[0m          |\n"); // Titolo in blu
    printf("+--------------------------------------------+\n");
    printf("| \033[1;32m 1.\033[0m Monitor ON                          |\n"); // Opzione in verde
    printf("| \033[1;32m 2.\033[0m Monitor OFF                         |\n");
    printf("| \033[1;32m 3.\033[0m Monitor REC_ON                      |\n");
    printf("| \033[1;32m 4.\033[0m Monitor REC_OFF                     |\n");
    printf("| \033[1;32m 5.\033[0m Change Password                     |\n");
    printf("| \033[1;32m 6.\033[0m Insert Path                         |\n");
    printf("| \033[1;32m 7.\033[0m Remove Path                         |\n");
    printf("|                                            |\n");
    printf("| \033[1;31m 0.\033[0m Exit                                |\n"); // Opzione Exit in rosso
    printf("+--------------------------------------------+\n");
    printf("Enter your choice: ");
}

int get_choice()
{
    char input[10];
    int choice;

    fgets(input, sizeof(input), stdin);
    
    if (sscanf(input, "%d", &choice) != 1) 
    {
        printf("Invalid input. Please enter a number.\n");
        return -1; // Indica un errore
    }

    if (choice < 0 || choice > 7)
    {
        printf("Choice out of range. Please enter a number between 0 and 7.\n");
        return -1; // Indica un errore
    }

    return choice;
}

void get_password(char *password, size_t size)
{
    struct termios oldt, newt;
    int ch;
    size_t i = 0;

    // Disabilita l'eco del terminale
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Legge password
    while ((ch = getchar()) != '\n' && ch != EOF && i < size - 1)
    {
        password[i++] = ch;
    }
    password[i] = '\0';

    // Ripristina le impostazioni del terminale
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

int validate_password(const char *password) {
    size_t len = strlen(password);

    if (len < 6) { // Controllo che la password sia lunga almeno 4 caratteri
        printf("Password too short. It must be at least 6 characters long.\n");
        return 0;
    }
    
    if (len > 100) { // Non eccedere la lunghezza massima
        printf("Password too long. Maximum allowed is 100 characters.\n");
        return 0;
    }

    // Controlla che contenga solo caratteri alfanumerici
    for (size_t i = 0; i < len; i++) {
        if (!isalnum(password[i])) {
            printf("Password contains invalid characters. Only alphanumeric characters are allowed.\n");
            return 0;
        }
    }

    return 1;
}

int validate_path(const char *path) {
    size_t len = strlen(path);

    if (len == 0) {
        printf("Path cannot be empty.\n");
        return 0;
    }

    if (len > 200) { // Puoi definire una lunghezza massima per il percorso
        printf("Path too long. Maximum allowed is 200 characters.\n");
        return 0;
    }


    return 1;
}



int main()
{
    int fd, choice;
    ssize_t ret;
    char buffer[2048];
    char command[10];
    char password[100];
    char parameter[100];

    fd = open(DEVICE_NAME, O_WRONLY);
    if (fd < 0)
    {
        perror("Failed to open the device");
        return -1;
    }

    while (1)
    {
        display_menu();

        choice = get_choice();

        if (choice == -1)
        {
            continue; // Riprova in caso di errore
        }

        if (choice == 0)
        {
            break;
        }

        printf("Enter password: ");
        // fgets(password, sizeof(password), stdin);
        // password[strcspn(password, "\n")] = 0; // remove the newline character
        get_password(password, sizeof(password));

        if (!validate_password(password)) {
            continue; // Riprova in caso di password non valida
        }

        switch (choice)
        {
        case 1:
            snprintf(command, sizeof(command), "ON");
            snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
            ret = write(fd, buffer, strlen(buffer));
            //printf("ret: %zd\n", ret);
            if (ret == 1){
                printf("The monitor has been set to ON\n");
            }else if (ret == -1){
                printf("Password incorrect\n");
            }
            break;
        case 2:
            snprintf(command, sizeof(command), "OFF");
            snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
            ret = write(fd, buffer, strlen(buffer));
            if (ret == 1){
                printf("The monitor has been set to OFF\n");
            }else if (ret == -1){
                printf("Password incorrect\n");
            }
            break;
        case 3:
            snprintf(command, sizeof(command), "REC_ON");
            snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
            ret = write(fd, buffer, strlen(buffer));
            if (ret == 1){
                printf("The monitor has been set to REC_ON modality\n");
            }else if (ret == -1){
                printf("Password incorrect\n");
            }
            break;
        case 4:
            snprintf(command, sizeof(command), "REC_OFF");
            snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
            ret = write(fd, buffer, strlen(buffer));
            if (ret == 1){
                printf("The monitor has been set to REC_OFF modality\n");
            }else if (ret == -1){
                printf("Password incorrect\n");
            }
            break;
        case 5:
            snprintf(command, sizeof(command), "CHGPASS");
            printf("Enter new password (at least 6 character): ");
            fgets(parameter, sizeof(parameter), stdin);
            parameter[strcspn(parameter, "\n")] = 0; // remove the newline character
            snprintf(buffer, sizeof(buffer), "%s:%s:%s", command, password, parameter);
            ret = write(fd, buffer, strlen(buffer));
            if (ret == 1){
                printf("The password has been changed\n");
            }else if (ret == -1){
                printf("Error. See kernel message for more details. The password has not been modified\n");
            }
            break;
        case 6:
            snprintf(command, sizeof(command), "INSERT");
            printf("Enter path to insert: ");
            fgets(parameter, sizeof(parameter), stdin);
            parameter[strcspn(parameter, "\n")] = 0; // remove the newline character
            snprintf(buffer, sizeof(buffer), "%s:%s:%s", command, password, parameter);
            if (!validate_path(parameter))
            {
                continue; // Riprova in caso di percorso non valido
            }
            ret = write(fd, buffer, strlen(buffer));
            if (ret == 1){
                printf("The path has been inserted in the list of protected path\n");
            }else if (ret == -1){
                printf("Error. See kernel message for more details. The path has not been added\n");
            }
            break;
        case 7:
            snprintf(command, sizeof(command), "REMOVE");
            printf("Enter path to remove: ");
            fgets(parameter, sizeof(parameter), stdin);
            parameter[strcspn(parameter, "\n")] = 0; // remove the newline character
            snprintf(buffer, sizeof(buffer), "%s:%s:%s", command, password, parameter);
            ret  = write(fd, buffer, strlen(buffer));
            if (ret == 1){
                printf("The path has been removed from the list of protected path\n");
            }else if (ret == -1){
                printf("Error. See kernel message for more details. The path has not been removed\n");
            }
            break;
        default:
            printf("Invalid choice. Please try again.\n");
            continue;
        }

        if (ret < 0)
        {
            perror("Failed to write the message to the device");
            printf("Do you want to retry? (y/n): ");
            char retry;
            // scanf("%c", &retry);
            fgets(buffer, sizeof(buffer), stdin);
            retry = buffer[0]; // Prendi il primo carattere inserito
            if (retry == 'y' || retry == 'Y')
            {
                continue; // Riprova
            }
            else
            {
                close(fd);
                return -1;
            }
        }
    }

    close(fd);
    return 0;
}

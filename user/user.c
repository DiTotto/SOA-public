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

#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"



void display_menu() {
    printf("\n");
    printf("+----------------------------------------------------+\n");
    printf("|             \033[1;34mREFERENCE MONITOR MENU\033[0m               |\n"); // Titolo in blu
    printf("+----------------------------------------------------+\n");
    printf("| \033[1;32m1. Monitor ON\033[0m         | \033[1;32m2. Monitor OFF\033[0m          |\n");
    printf("| \033[1;32m3. Monitor REC_ON\033[0m     | \033[1;32m4. Monitor REC_OFF\033[0m      |\n");
    printf("| \033[1;32m5. Change Password\033[0m    | \033[1;32m6. Insert Path\033[0m          |\n");
    printf("| \033[1;32m7. Remove Path\033[0m        | \033[1;31m0. Exit\033[0m                 |\n"); // Exit in rosso
    printf("+----------------------------------------------------+\n");
    printf("Enter your choice: ");
}

void print_success_message(const char* message) {
    printf(COLOR_GREEN "Success: %s\n" COLOR_RESET, message);
}

void print_error_message(const char* message) {
    printf(COLOR_RED "Error: %s\n" COLOR_RESET, message);
}

void print_info_message(const char* message) {
    printf(COLOR_YELLOW "Info: %s\n" COLOR_RESET, message);
}

void print_standard_message(const char* message) {
    printf(COLOR_BLUE "%s\n" COLOR_RESET, message);
}

int get_choice()
{
    char input[10];
    int choice;

    fgets(input, sizeof(input), stdin);
    
    if (sscanf(input, "%d", &choice) != 1) 
    {
        print_info_message("Invalid input. Please enter a number.\n");
        return -1; // Indica un errore
    }

    if (choice < 0 || choice > 7)
    {
        print_info_message("Choice out of range. Please enter a number between 0 and 7.\n");
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
        print_error_message("Password too short. It must be at least 6 characters long.\n");
        return 0;
    }
    
    if (len > 100) { // Non eccedere la lunghezza massima
        print_error_message("Password too long. Maximum allowed is 100 characters.\n");
        return 0;
    }

    // Controlla che contenga solo caratteri alfanumerici
    for (size_t i = 0; i < len; i++) {
        if (!isalnum(password[i])) {
            print_error_message("Password contains invalid characters. Only alphanumeric characters are allowed.\n");
            return 0;
        }
    }

    return 1;
}

int validate_path(const char *path) {
    size_t len = strlen(path);

    if (len == 0) {
        print_error_message("Path cannot be empty.\n");
        return 0;
    }

    if (len > 200) { // Puoi definire una lunghezza massima per il percorso
        print_error_message("Path too long. Maximum allowed is 200 characters.\n");
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
                //printf("The monitor has been set to ON\n");
                print_success_message("The monitor has been set to ON\n");
            }else if (ret == -1){
                print_error_message("Password incorrect\n");
            }
            break;
        case 2:
            snprintf(command, sizeof(command), "OFF");
            snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
            ret = write(fd, buffer, strlen(buffer));
            if (ret == 1){
                print_success_message("The monitor has been set to OFF\n");
            }else if (ret == -1){
                print_error_message("Password incorrect\n");
            }
            break;
        case 3:
            snprintf(command, sizeof(command), "REC_ON");
            snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
            ret = write(fd, buffer, strlen(buffer));
            if (ret == 1){
                print_success_message("The monitor has been set to REC_ON modality\n");
            }else if (ret == -1){
                print_error_message("Password incorrect\n");
            }
            break;
        case 4:
            snprintf(command, sizeof(command), "REC_OFF");
            snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
            ret = write(fd, buffer, strlen(buffer));
            if (ret == 1){
                print_success_message("The monitor has been set to REC_OFF modality\n");
            }else if (ret == -1){
                print_error_message("Password incorrect\n");
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
                print_success_message("The password has been changed\n");
            }else if (ret == -1){
                print_error_message("Error. See kernel message for more details. The password has not been modified\n");
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
                print_success_message("The path has been inserted in the list of protected path\n");
            }else if (ret == -1){
                print_error_message("Error. See kernel message for more details. The path has not been added\n");
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
                print_success_message("The path has been removed from the list of protected path\n");
            }else if (ret == -1){
                print_error_message("Error. See kernel message for more details. The path has not been removed\n");
            }
            break;
        default:
            print_info_message("Invalid choice. Please try again.\n");
            continue;
        }

        if (ret < 0)
        {
            perror("Failed to write the message to the device");
            print_info_message("Do you want to retry? (y/n): ");
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

    print_standard_message("Exiting from reference monitor");

    close(fd);
    return 0;
}

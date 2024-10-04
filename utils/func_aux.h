#ifndef FUNZIONI_MONITOR_H
#define FUNZIONI_MONITOR_H

#include <linux/types.h>

// Dichiarazione delle funzioni
char *find_directory(char *path);
char *full_path(int dfd, const __user char *user_path);
char *get_pwd(void);
char *resolve_path(const char *path);
char *get_absolute_path(const char *user_path);

#endif // FUNZIONI_MONITOR_H

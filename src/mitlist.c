#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <getopt.h>
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MITLIST_VERSION "0.1.0"

#define PROGRAM "mitlist"
#define MAX_LINE 8192

typedef struct {
    const char *name;
    const char *service;
} category;

static const category categories[] = {
    {"Users", NULL}, {"HTTP", "http"}, {"CIFS", "cifs"},
    {"Host", "host"}, {"IMAP", "imap"}, {"SMTP", "smtp"},
    {"LDAP", "ldap"}, {"NFS", "nfs"}
};
#define CATEGORY_COUNT (sizeof(categories) / sizeof(categories[0]))

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} string_list;

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: %s [options] [pattern]\n"
        "List MIT Kerberos principals using the current Kerberos credential cache.\n\n"
        "Options:\n"
        "  -u, --users             List user principals only\n"
        "  -t, --type TYPE         List one type (users, HTTP, cifs, host, imap, smtp, ldap, nfs)\n"
        "  -f, --filter PATTERN    Case-insensitive shell-style principal filter\n"
        "  -r, --realm REALM       Restrict results to REALM\n"
        "  -h, --help              Show this help\n"
        "      --version           Show version\n\n"
        "Type names, options, and filters are case-insensitive.\n"
        "The default credential cache is used; no password is requested or stored.\n",
        PROGRAM);
}

static char *lower_copy(const char *s)
{
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p) return NULL;
    for (size_t i = 0; i < n; ++i)
        p[i] = (char)tolower((unsigned char)s[i]);
    p[n] = '\0';
    return p;
}

static int list_add(string_list *list, const char *value)
{
    if (list->count == list->capacity) {
        size_t next = list->capacity ? list->capacity * 2 : 32;
        char **items = realloc(list->items, next * sizeof(*items));
        if (!items) return -1;
        list->items = items;
        list->capacity = next;
    }
    list->items[list->count] = strdup(value);
    if (!list->items[list->count]) return -1;
    list->count++;
    return 0;
}

static void list_free(string_list *list)
{
    for (size_t i = 0; i < list->count; ++i) free(list->items[i]);
    free(list->items);
}

static int compare_strings(const void *a, const void *b)
{
    return strcasecmp(*(char * const *)a, *(char * const *)b);
}

static int run_kadmin(string_list *principals)
{
    krb5_context context = NULL;
    const char *cache_name;
    int pipefd[2], status;
    pid_t child;
    FILE *stream;
    char line[MAX_LINE];

    if (krb5_init_context(&context) != 0) {
        fprintf(stderr, PROGRAM ": cannot initialize Kerberos library\n");
        return -1;
    }
    cache_name = krb5_cc_default_name(context);
    if (!cache_name || !*cache_name) {
        fprintf(stderr, PROGRAM ": no default Kerberos credential cache is configured\\n");
        krb5_free_context(context);
        return -1;
    }

    /* Obtain kadmin/admin from the user's existing TGT and cache it. */
    {
        krb5_ccache cache = NULL;
        krb5_principal client = NULL, server = NULL;
        krb5_creds request, *credentials = NULL;
        krb5_error_code code;
        memset(&request, 0, sizeof(request));
        code = krb5_cc_resolve(context, cache_name, &cache);
        if (code == 0) code = krb5_cc_get_principal(context, cache, &client);
        if (code == 0) {
            krb5_data realm = krb5_princ_realm(context, client);
            code = krb5_build_principal(context, &server, realm.length,
                                        realm.data, "kadmin", "admin", NULL);
        }
        if (code == 0) {
            request.client = client;
            request.server = server;
            code = krb5_get_credentials(context, 0, cache, &request, &credentials);
        }
        if (code == 0) code = krb5_cc_store_cred(context, cache, credentials);
        if (credentials) krb5_free_creds(context, credentials);
        if (server) krb5_free_principal(context, server);
        if (client) krb5_free_principal(context, client);
        if (cache) krb5_cc_close(context, cache);
        if (code != 0) {
            const char *message = krb5_get_error_message(context, code);
            fprintf(stderr, PROGRAM ": cannot obtain kadmin/admin using the current ticket cache: %s\\n",
                    message ? message : "Kerberos error");
            if (message) krb5_free_error_message(context, message);
            krb5_free_context(context);
            return -1;
        }
    }

    if (pipe(pipefd) < 0) {
        perror(PROGRAM ": pipe");
        krb5_free_context(context);
        return -1;
    }

    child = fork();
    if (child < 0) {
        perror(PROGRAM ": fork");
        close(pipefd[0]); close(pipefd[1]);
        krb5_free_context(context);
        return -1;
    }
    if (child == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
        close(pipefd[1]);
        execlp("kadmin", "kadmin", "-c", cache_name, "-q",
               "list_principals", (char *)NULL);
        fprintf(stderr, PROGRAM ": cannot execute kadmin: %s\n", strerror(errno));
        _exit(127);
    }

    close(pipefd[1]);
    stream = fdopen(pipefd[0], "r");
    if (!stream) {
        perror(PROGRAM ": fdopen");
        close(pipefd[0]);
        waitpid(child, &status, 0);
        krb5_free_context(context);
        return -1;
    }

    while (fgets(line, sizeof(line), stream)) {
        size_t n = strcspn(line, "\r\n");
        line[n] = '\0';
        if (n == 0) continue;
        /* kadmin may print a prompt or diagnostics; accept principal-shaped lines only. */
        if (!strchr(line, '@')) continue;
        if (list_add(principals, line) < 0) {
            fprintf(stderr, PROGRAM ": out of memory\n");
            fclose(stream);
            waitpid(child, &status, 0);
            krb5_free_context(context);
            return -1;
        }
    }
    fclose(stream);
    if (waitpid(child, &status, 0) < 0) {
        perror(PROGRAM ": waitpid");
        krb5_free_context(context);
        return -1;
    }
    krb5_free_context(context);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, PROGRAM ": kadmin failed. Check that the current ticket cache "
                "can authenticate to kadmind and that its principal has the Kerberos "
                "'list' privilege.\n");
        return -1;
    }
    return 0;
}

static int principal_category(const char *principal)
{
    const char *slash = strchr(principal, '/');
    if (!slash) return 0;
    size_t service_len = (size_t)(slash - principal);
    for (size_t i = 1; i < CATEGORY_COUNT; ++i) {
        if (strlen(categories[i].service) == service_len &&
            strncasecmp(principal, categories[i].service, service_len) == 0)
            return (int)i;
    }
    return (int)CATEGORY_COUNT;
}

static int matches_filter(const char *principal, const char *pattern)
{
    char *p = lower_copy(principal);
    char *f = lower_copy(pattern);
    int result;
    if (!p || !f) {
        free(p); free(f);
        return 0;
    }
    result = fnmatch(f, p, 0) == 0;
    free(p); free(f);
    return result;
}

static int matches_realm(const char *principal, const char *realm)
{
    const char *at = strrchr(principal, '@');
    return !realm || (at && strcasecmp(at + 1, realm) == 0);
}

int main(int argc, char **argv)
{
    string_list principals = {0};
    const char *type = NULL, *filter = NULL, *realm = NULL;
    int users_only = 0, selected = -1, option, rc = EXIT_FAILURE;
    static const struct option options[] = {
        {"users", no_argument, NULL, 'u'},
        {"USERS", no_argument, NULL, 'u'},
        {"type", required_argument, NULL, 't'},
        {"TYPE", required_argument, NULL, 't'},
        {"filter", required_argument, NULL, 'f'},
        {"FILTER", required_argument, NULL, 'f'},
        {"realm", required_argument, NULL, 'r'},
        {"REALM", required_argument, NULL, 'r'},
        {"help", no_argument, NULL, 'h'},
        {"HELP", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 1000},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, "uUt:T:f:F:r:R:hH", options, NULL)) != -1) {
        switch (tolower((unsigned char)option)) {
        case 'u': users_only = 1; break;
        case 't': type = optarg; break;
        case 'f': filter = optarg; break;
        case 'r': realm = optarg; break;
        case 'h': usage(stdout); return EXIT_SUCCESS;
        case 1000: puts(PROGRAM " 0.1.0"); return EXIT_SUCCESS;
        default: usage(stderr); return EXIT_FAILURE;
        }
    }
    if (optind < argc) {
        if (filter) {
            fprintf(stderr, PROGRAM ": specify a filter only once\n");
            return EXIT_FAILURE;
        }
        filter = argv[optind++];
    }
    if (optind != argc || (users_only && type)) {
        usage(stderr);
        return EXIT_FAILURE;
    }
    if (type) {
        char *normalized = lower_copy(type);
        if (!normalized) return EXIT_FAILURE;
        if (!strcmp(normalized, "user") || !strcmp(normalized, "users"))
            selected = 0;
        else {
            for (size_t i = 1; i < CATEGORY_COUNT; ++i)
                if (!strcmp(normalized, categories[i].service)) selected = (int)i;
        }
        free(normalized);
        if (selected < 0) {
            fprintf(stderr, PROGRAM ": unknown principal type: %s\n", type);
            return EXIT_FAILURE;
        }
    } else if (users_only) selected = 0;

    if (run_kadmin(&principals) < 0) goto done;
    qsort(principals.items, principals.count, sizeof(*principals.items), compare_strings);

    for (size_t group = 0; group <= CATEGORY_COUNT; ++group) {
        size_t printed = 0;
        if (selected >= 0 && (size_t)selected != group) continue;
        for (size_t i = 0; i < principals.count; ++i) {
            int category = principal_category(principals.items[i]);
            if ((size_t)category != group) continue;
            if (!matches_realm(principals.items[i], realm)) continue;
            if (filter && !matches_filter(principals.items[i], filter)) continue;
            if (!printed) printf("%s\n", group < CATEGORY_COUNT ?
                                  categories[group].name : "Other");
            printf("%s\n", principals.items[i]);
            printed++;
        }
        if (printed) putchar('\n');
    }
    rc = EXIT_SUCCESS;

done:
    list_free(&principals);
    return rc;
}

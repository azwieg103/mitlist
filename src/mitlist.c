#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <getopt.h>
#include <krb5.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <profile.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MITLIST_VERSION "0.1.5"
#define PROGRAM "mitlist"
#define MAX_LINE 8192

typedef struct { const char *name; const char *service; } category;
static const category categories[] = {
    {"Users", NULL}, {"HTTP", "http"}, {"CIFS", "cifs"}, {"Host", "host"},
    {"IMAP", "imap"}, {"SMTP", "smtp"}, {"LDAP", "ldap"}, {"NFS", "nfs"},
    {"MySQL", "mysql"}, {"PostgreSQL", "postgres"}
};
#define CATEGORY_COUNT (sizeof(categories) / sizeof(categories[0]))

typedef struct { char **items; size_t count; size_t capacity; } string_list;

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: %s [options] [pattern]\n"
        "List MIT Kerberos principals using the current Kerberos credential cache.\n\n"
        "Options:\n"
        "  -u, --users             List user principals only\n"
        "  -t, --type TYPE         List one type (users, HTTP, cifs, host, imap, smtp, ldap, nfs, mysql, postgres)\n"
        "  -f, --filter PATTERN    Case-insensitive shell-style principal filter\n"
        "  -r, --realm REALM       Restrict results to REALM\n"
        "  -i, --info              Show default realm and configured Kerberos servers\n"
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
    for (size_t i = 0; i < n; ++i) p[i] = (char)tolower((unsigned char)s[i]);
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


/*
 * Resolve the configured admin_server hostname before invoking kadmin.
 * In environments where admin_server is a DNS alias, the canonical host
 * is the service-principal name expected by the credential cache.
 */
static char *canonical_admin_server(krb5_context context, const char *server)
{
    const char *colon = NULL;
    size_t colons = 0, host_len;
    char *host = NULL, *canonical_host = NULL, *result = NULL;
    krb5_error_code code;

    if (!server || !*server) return NULL;

    /* Bracketed IPv6 literals and unbracketed IPv6 addresses are left intact. */
    if (server[0] == '[') return strdup(server);
    for (const char *p = server; *p; ++p) {
        if (*p == ':') { colon = p; colons++; }
    }
    if (colons > 1) return strdup(server);

    host_len = colons == 1 ? (size_t)(colon - server) : strlen(server);
    if (host_len == 0) return NULL;
    host = malloc(host_len + 1);
    if (!host) return NULL;
    memcpy(host, server, host_len);
    host[host_len] = '\0';

    code = krb5_expand_hostname(context, host, &canonical_host);
    free(host);
    if (code != 0 || !canonical_host || !*canonical_host) {
        if (canonical_host) krb5_free_string(context, canonical_host);
        return NULL;
    }

    if (colons == 1) {
        size_t n = strlen(canonical_host) + strlen(colon) + 1;
        result = malloc(n);
        if (result) snprintf(result, n, "%s%s", canonical_host, colon);
    } else {
        result = strdup(canonical_host);
    }
    krb5_free_string(context, canonical_host);
    return result;
}


/*
 * kadmin expects the admin service ticket to already be in the cache in this
 * environment. Acquire kadmin/<canonical-host> here, just as kvno does,
 * before starting the kadmin client.
 */
static krb5_error_code acquire_admin_ticket(krb5_context context,
                                             const char *server,
                                             const char *realm, int force_refresh)
{
    const char *host_start = server;
    const char *host_end = NULL;
    const char *colon = NULL;
    size_t colon_count = 0, host_len;
    char *host = NULL;
    krb5_principal principal = NULL;
    krb5_ccache cache = NULL;
    krb5_creds request = {0};
    krb5_creds *credentials = NULL;
    krb5_error_code code;

    if (server[0] == '[') {
        host_start = server + 1;
        host_end = strchr(host_start, ']');
        if (!host_end) return EINVAL;
    } else {
        for (const char *p = server; *p; ++p) {
            if (*p == ':') { colon = p; colon_count++; }
        }
        if (colon_count == 1) host_end = colon;
    }
    if (!host_end) host_end = server + strlen(server);
    host_len = (size_t)(host_end - host_start);
    if (host_len == 0) return EINVAL;

    host = malloc(host_len + 1);
    if (!host) return ENOMEM;
    memcpy(host, host_start, host_len);
    host[host_len] = '\0';

    code = krb5_build_principal(context, &principal, (unsigned int)strlen(realm),
                                realm, "kadmin", host, (char *)NULL);
    free(host);
    if (code != 0) goto cleanup;

    code = krb5_cc_default(context, &cache);
    if (code != 0) goto cleanup;

    code = krb5_cc_get_principal(context, cache, &request.client);
    if (code != 0) goto cleanup;
    request.server = principal;
    if (force_refresh) {
        code = krb5_cc_remove_cred(context, cache,
                                   0,
                                   &request);
        if (code != 0 && code != KRB5_CC_NOTFOUND) goto cleanup;
    }
    code = krb5_get_credentials(context, 0, cache, &request, &credentials);

cleanup:
    if (credentials) krb5_free_creds(context, credentials);
    if (request.client) krb5_free_principal(context, request.client);
    if (cache) krb5_cc_close(context, cache);
    if (principal) krb5_free_principal(context, principal);
    return code;
}


static void print_profile_values(profile_t profile, const char *realm, const char *key,
                                 const char *label)
{
    const char *names[] = { "realms", realm, key, NULL };
    char **values = NULL;
    long code = profile_get_values(profile, names, &values);

    if (code == 0 && values && values[0]) {
        for (size_t i = 0; values[i]; ++i)
            printf("%s: %s\n", label, values[i]);
    } else {
        printf("%s: (not explicitly configured)\n", label);
    }
    if (values) profile_free_list(values);
}

static void print_dns_discovery(const char *realm)
{
    char query[1024];
    const char *services[][3] = {
        {"_kerberos._udp", "KDC UDP", NULL},
        {"_kerberos._tcp", "KDC TCP", NULL},
        {"_kerberos-master._udp", "Master KDC UDP", NULL},
        {"_kerberos-master._tcp", "Master KDC TCP", NULL},
        {"_kerberos-adm._tcp", "Admin TCP", NULL},
        {"_kpasswd._udp", "Password UDP", NULL},
        {"_kpasswd._tcp", "Password TCP", NULL}
    };
    puts("DNS SRV records:");
    for (size_t j = 0; j < sizeof(services) / sizeof(services[0]); ++j) {
        unsigned char answer[NS_PACKETSZ * 8];
        ns_msg msg;
        ns_rr rr;
        unsigned int found = 0;
        int len;
        snprintf(query, sizeof(query), "%s.%s", services[j][0], realm);
        len = res_query(query, ns_c_in, ns_t_srv, answer, sizeof(answer));
        if (len < 0 || ns_initparse(answer, len, &msg) < 0) {
            printf("  %s (%s): no SRV records found\n", services[j][1], query);
            continue;
        }
        for (int i = 0; i < ns_msg_count(msg, ns_s_an); ++i) {
            char target[NS_MAXDNAME];
            const unsigned char *data;
            if (ns_parserr(&msg, ns_s_an, i, &rr) < 0 || ns_rr_type(rr) != ns_t_srv || ns_rr_rdlen(rr) < 7) continue;
            data = ns_rr_rdata(rr);
            if (dn_expand(answer, answer + len, data + 6, target, sizeof(target)) < 0) continue;
            printf("  %s: %s:%u (priority %u, weight %u)\n", services[j][1], target, ns_get16(data + 4), ns_get16(data), ns_get16(data + 2));
            found++;
        }
        if (!found) printf("  %s (%s): no usable SRV records\n", services[j][1], query);
    }
}

static int show_info(void)
{
    krb5_context context = NULL;
    profile_t profile = NULL;
    char *realm = NULL;
    long code;

    if (krb5_init_context(&context) != 0) {
        fprintf(stderr, PROGRAM ": cannot initialize Kerberos library\n");
        return EXIT_FAILURE;
    }
    code = krb5_get_default_realm(context, &realm);
    if (code != 0) {
        const char *message = krb5_get_error_message(context, code);
        fprintf(stderr, PROGRAM ": cannot determine the default realm: %s\n",
                message ? message : "Kerberos error");
        if (message) krb5_free_error_message(context, message);
        krb5_free_context(context);
        return EXIT_FAILURE;
    }
    printf("Default realm: %s\n", realm);
    code = krb5_get_profile(context, &profile);
    if (code != 0) {
        fprintf(stderr, PROGRAM ": cannot read the active Kerberos configuration\n");
        krb5_free_default_realm(context, realm);
        krb5_free_context(context);
        return EXIT_FAILURE;
    }
    print_profile_values(profile, realm, "kdc", "KDC");
    print_profile_values(profile, realm, "admin_server", "Admin server");
    print_dns_discovery(realm);
    puts("Note: DNS answers are shown regardless of dns_lookup_kdc; actual");
    puts("      Kerberos discovery behavior also depends on realm configuration.");
    profile_release(profile);
    krb5_free_default_realm(context, realm);
    krb5_free_context(context);
    return EXIT_SUCCESS;
}

static int execute_kadmin(const char *cache_name, const char *server, string_list *principals)
{
    int pipefd[2], status;
    pid_t child;
    FILE *stream;
    char line[MAX_LINE];
    if (pipe(pipefd) < 0) { perror(PROGRAM ": pipe"); return -1; }
    child = fork();
    if (child < 0) { perror(PROGRAM ": fork"); close(pipefd[0]); close(pipefd[1]); return -1; }
    if (child == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
        if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) _exit(126);
        close(pipefd[1]);
        execlp("kadmin", "kadmin", "-c", cache_name, "-s", server, "-q", "list_principals", (char *)NULL);
        fprintf(stderr, PROGRAM ": cannot execute kadmin: %s\n", strerror(errno));
        _exit(127);
    }
    close(pipefd[1]);
    stream = fdopen(pipefd[0], "r");
    if (!stream) { perror(PROGRAM ": fdopen"); close(pipefd[0]); waitpid(child, &status, 0); return -1; }
    while (fgets(line, sizeof(line), stream)) {
        size_t n = strcspn(line, "\r\n");
        line[n] = '\0';
        if (!n) continue;
        if (strchr(line, '@') && strpbrk(line, " \t") == NULL) {
            if (list_add(principals, line) < 0) { fprintf(stderr, PROGRAM ": out of memory\n"); fclose(stream); waitpid(child, &status, 0); return -1; }
        } else if (strncmp(line, "Authenticating as principal ", 28) != 0) {
            fprintf(stderr, PROGRAM ": %s\n", line);
        }
    }
    fclose(stream);
    if (waitpid(child, &status, 0) < 0) { perror(PROGRAM ": waitpid"); return -1; }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int run_kadmin(string_list *principals)
{
    krb5_context context = NULL;
    profile_t profile = NULL;
    char *realm = NULL;
    char *admin_server = NULL;
    char *canonical_server = NULL;
    char *ticket_realm = NULL;
    const char *cache_name;
    krb5_error_code code;
    long profile_code;
    int attempt;

    if (krb5_init_context(&context) != 0) {
        fprintf(stderr, PROGRAM ": cannot initialize Kerberos library\n");
        return -1;
    }

    cache_name = krb5_cc_default_name(context);
    if (!cache_name || !*cache_name) {
        fprintf(stderr, PROGRAM ": no default Kerberos credential cache is configured\n");
        krb5_free_context(context);
        return -1;
    }

    code = krb5_get_default_realm(context, &realm);
    if (code != 0) {
        const char *message = krb5_get_error_message(context, code);
        fprintf(stderr, PROGRAM ": cannot determine the default Kerberos realm: %s\n",
                message ? message : "Kerberos error");
        if (message) krb5_free_error_message(context, message);
        krb5_free_context(context);
        return -1;
    }

    code = krb5_get_profile(context, &profile);
    if (code == 0) {
        profile_code = profile_get_string(profile, "realms", realm,
                                          "admin_server", NULL, &admin_server);
    } else {
        profile_code = code;
    }
    if (profile_code != 0 || !admin_server || !*admin_server) {
        fprintf(stderr, PROGRAM
                ": no admin_server is configured for realm %s in the active Kerberos configuration\n",
                realm);
        if (admin_server) profile_release_string(admin_server);
        if (profile) profile_release(profile);
        krb5_free_default_realm(context, realm);
        krb5_free_context(context);
        return -1;
    }

    if (profile) profile_release(profile);
    krb5_free_default_realm(context, realm);

    canonical_server = canonical_admin_server(context, admin_server);
    if (!canonical_server) {
        fprintf(stderr, PROGRAM ": cannot canonicalize configured admin_server '%s'\n",
                admin_server);
        profile_release_string(admin_server);
        krb5_free_context(context);
        return -1;
    }
    profile_release_string(admin_server);

    code = krb5_get_default_realm(context, &ticket_realm);
    if (code != 0) {
        const char *message = krb5_get_error_message(context, code);
        fprintf(stderr, PROGRAM ": cannot determine ticket realm: %s\n", message ? message : "Kerberos error");
        if (message) krb5_free_error_message(context, message);
        free(canonical_server);
        krb5_free_context(context);
        return -1;
    }
    for (attempt = 0; attempt < 2; ++attempt) {
        code = acquire_admin_ticket(context, canonical_server, ticket_realm, attempt == 1);
        if (code != 0) {
            const char *message = krb5_get_error_message(context, code);
            fprintf(stderr, PROGRAM ": %s admin-server service ticket: %s\n", attempt ? "cannot refresh" : "cannot obtain", message ? message : "Kerberos error");
            if (message) krb5_free_error_message(context, message);
            break;
        }
        if (execute_kadmin(cache_name, canonical_server, principals) == 0) {
            krb5_free_default_realm(context, ticket_realm);
            free(canonical_server);
            krb5_free_context(context);
            return 0;
        }
        list_free(principals);
        memset(principals, 0, sizeof(*principals));
        if (attempt == 0) fprintf(stderr, PROGRAM ": kadmin rejected the cached service ticket; refreshing it and retrying once\n");
    }
    fprintf(stderr, PROGRAM ": kadmin failed after one service-ticket retry. Check kadmind access, the Kerberos 'list' ACL, and admin_server configuration.\n");
    krb5_free_default_realm(context, ticket_realm);
    free(canonical_server);
    krb5_free_context(context);
    return -1;
}

static int principal_category(const char *principal)
{
    const char *slash = strchr(principal, '/');
    if (!slash) return 0;
    size_t service_len = (size_t)(slash - principal);
    for (size_t i = 1; i < CATEGORY_COUNT; ++i)
        if (strlen(categories[i].service) == service_len &&
            strncasecmp(principal, categories[i].service, service_len) == 0)
            return (int)i;
    return (int)CATEGORY_COUNT;
}

static int matches_filter(const char *principal, const char *pattern)
{
    char *p = lower_copy(principal), *f = lower_copy(pattern);
    int result;
    if (!p || !f) { free(p); free(f); return 0; }
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
    int users_only = 0, show_info_flag = 0, selected = -1, option, rc = EXIT_FAILURE;
    static const struct option options[] = {
        {"users", no_argument, NULL, 'u'}, {"USERS", no_argument, NULL, 'u'},
        {"type", required_argument, NULL, 't'}, {"TYPE", required_argument, NULL, 't'},
        {"filter", required_argument, NULL, 'f'}, {"FILTER", required_argument, NULL, 'f'},
        {"realm", required_argument, NULL, 'r'}, {"REALM", required_argument, NULL, 'r'},
        {"info", no_argument, NULL, 'i'}, {"INFO", no_argument, NULL, 'i'},
        {"help", no_argument, NULL, 'h'}, {"HELP", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 1000}, {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, "uUt:T:f:F:r:R:iI:hH", options, NULL)) != -1) {
        switch (option == 1000 ? 1000 : tolower((unsigned char)option)) {
        case 'u': users_only = 1; break;
        case 't': type = optarg; break;
        case 'f': filter = optarg; break;
        case 'r': realm = optarg; break;
        case 'i': show_info_flag = 1; break;
        case 'h': usage(stdout); return EXIT_SUCCESS;
        case 1000: puts(PROGRAM " " MITLIST_VERSION); return EXIT_SUCCESS;
        default: usage(stderr); return EXIT_FAILURE;
        }
    }
    if (show_info_flag) {
        if (optind != argc || users_only || type || filter || realm) {
            fprintf(stderr, PROGRAM ": --info cannot be combined with listing filters\n");
            return EXIT_FAILURE;
        }
        return show_info();
    }
    if (optind < argc) {
        if (filter) { fprintf(stderr, PROGRAM ": specify a filter only once\n"); return EXIT_FAILURE; }
        filter = argv[optind++];
    }
    if (optind != argc || (users_only && type)) { usage(stderr); return EXIT_FAILURE; }
    if (type) {
        char *normalized = lower_copy(type);
        if (!normalized) return EXIT_FAILURE;
        if (!strcmp(normalized, "user") || !strcmp(normalized, "users")) selected = 0;
        else for (size_t i = 1; i < CATEGORY_COUNT; ++i)
            if (!strcmp(normalized, categories[i].service)) selected = (int)i;
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
            if ((size_t)principal_category(principals.items[i]) != group) continue;
            if (!matches_realm(principals.items[i], realm)) continue;
            if (filter && !matches_filter(principals.items[i], filter)) continue;
            if (!printed) printf("%s\n", group < CATEGORY_COUNT ? categories[group].name : "Other");
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

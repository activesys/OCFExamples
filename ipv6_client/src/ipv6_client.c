#include "ipv6_client_config.h"

#include "oc_api.h"
#include "oc_endpoint.h"
#include "port/oc_clock.h"
#include <signal.h>
#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

int quit = 0;

const char* addr_str = NULL;
int if_index = 0;
static bool after_put = false;

#ifdef WIN32
static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;
#else
pthread_mutex_t mutex;
pthread_cond_t  cv;
struct timespec ts;
#endif

static int
app_init(void)
{
    int ret = oc_init_platform("Apple", NULL, NULL);
    ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
        "ocf.res.1.0.0", NULL, NULL);
    return ret;
}

#define MAX_URI_LENGTH (30)
static char a_light[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;

static bool state;
static int power;
static oc_string_t name;

static void get_light(oc_client_response_t*);

static void
put_light(oc_client_response_t* data)
{
    if (data->code == OC_STATUS_CHANGED) {
        printf("PUT response CHANGED\n");
    } else {
        printf("PUT response code: %d\n", data->code);
    }

    after_put = true;

    oc_string_t ep;
    oc_endpoint_t addr;
    oc_new_string(&ep, addr_str, strlen(addr_str));
    oc_string_to_endpoint(&ep, &addr, NULL);
    addr.interface_index = if_index;

    oc_do_get("/a/light", &addr, NULL, &get_light, LOW_QOS, NULL);

    oc_free_string(&ep);
}

static void
get_light(oc_client_response_t *data)
{
    char* json = NULL;
    size_t json_size = 0;

    PRINT("GET_light:\n");
    oc_rep_t *rep = data->payload;

    json_size = oc_rep_to_json(rep, NULL, 0, true);
    json = malloc(json_size + 1);
    oc_rep_to_json(rep, json, json_size+1, true);
    printf(json);
    free(json);

    while (rep != NULL) {
        PRINT("key %s, value ", oc_string(rep->name));
        switch (rep->type) {
        case OC_REP_BOOL:
            PRINT("%d\n", rep->value.boolean);
            state = rep->value.boolean;
            break;
        case OC_REP_INT:
            PRINT("%lld\n", rep->value.integer);
            power = (int)rep->value.integer;
            break;
        case OC_REP_STRING:
            PRINT("%s\n", oc_string(rep->value.string));
            if (oc_string_len(name))
                oc_free_string(&name);
            oc_new_string(&name, oc_string(rep->value.string),
                oc_string_len(rep->value.string));
            break;
        default:
            break;
        }
        rep = rep->next;
    }

    if (!after_put) {
        oc_string_t ep;
        oc_endpoint_t addr;
        oc_new_string(&ep, addr_str, strlen(addr_str));
        oc_string_to_endpoint(&ep, &addr, NULL);
        addr.interface_index = if_index;

        if (oc_init_put("/a/light", &addr, NULL, &put_light, LOW_QOS, NULL)) {
            oc_rep_start_root_object();
            oc_rep_set_boolean(root, state, true);
            oc_rep_set_int(root, power, 189);
            oc_rep_end_root_object();

            oc_do_put();
        }

        oc_free_string(&ep);
    }
}

oc_discovery_flags_t discovery_handler(
    const char * anchor, const char * uri, oc_string_array_t types, oc_interface_mask_t iface_mask,
    oc_endpoint_t * endpoint, oc_resource_properties_t bm, void * user_data)
{
    int i;
    size_t uri_len = strlen(uri);
    uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
    PRINT("\n\nDISCOVERYCB %s %s %zd\n\n", anchor, uri,
        oc_string_array_get_allocated_size(types));
    for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
        char *t = oc_string_array_get_item(types, i);
        PRINT("\n\nDISCOVERED RES %s\n\n\n", t);
        if (strlen(t) == 10 && strncmp(t, "core.light", 10) == 0) {
            oc_endpoint_list_copy(&light_server, endpoint);
            strncpy(a_light, uri, uri_len);
            a_light[uri_len] = '\0';

            PRINT("Resource %s hosted at endpoints:\n", a_light);
            oc_endpoint_t *ep = endpoint;
            while (ep != NULL) {
                PRINTipaddr(*ep);
                PRINT("\n");
                ep = ep->next;
            }
        }
    }

    return OC_STOP_DISCOVERY;
}

static void
issue_requests(void)
{
    oc_do_ip_discovery("core.light", discovery_handler, NULL);
}

static void
signal_event_loop(void)
{
#ifdef WIN32
    WakeConditionVariable(&cv);
#else
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mutex);
#endif
}

void
handle_signal(int signal)
{
#ifdef WIN32
    quit = 1;
    WakeConditionVariable(&cv);
#else
    pthread_mutex_lock(&mutex);
    quit = 1;
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mutex);
#endif
}

int
main(int argc, char* argv[])
{
    int init;

    if (argc == 3) {
        addr_str = argv[1];
        if_index = atoi(argv[2]);
    }

#ifdef WIN32
    InitializeCriticalSection(&cs);
    InitializeConditionVariable(&cv);

    signal(SIGINT, handle_signal);
#else
    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
#endif

    static const oc_handler_t handler = { .init = app_init,
                                          .signal_event_loop = signal_event_loop,
                                          .register_resources = 0,
                                          .requests_entry = issue_requests };

    oc_clock_time_t next_event;

#ifdef OC_STORAGE
    oc_storage_config("./simpleclient_creds/");
#endif /* OC_STORAGE */

    init = oc_main_init(&handler);
    if (init < 0)
        return init;

    while (quit != 1) {
        next_event = oc_main_poll();
#ifdef WIN32
        if (next_event == 0) {
            SleepConditionVariableCS(&cv, &cs, INFINITE);
        } else {
            oc_clock_time_t now = oc_clock_time();
            if (now < next_event) {
                SleepConditionVariableCS(
                    &cv, &cs, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
            }
        }
#else
        pthread_mutex_lock(&mutex);
        if (next_event == 0) {
            pthread_cond_wait(&cv, &mutex);
        } else {
            ts.tv_sec = (next_event / OC_CLOCK_SECOND);
            ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
            pthread_cond_timedwait(&cv, &mutex, &ts);
        }
        pthread_mutex_unlock(&mutex);
#endif
    }

    oc_main_shutdown();
    return 0;
}

#include "ipv6_get_client_config.h"

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

#ifdef WIN32
static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;
#else
pthread_mutex_t mutex;
pthread_cond_t cv;
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


static void
get_light_handler(oc_client_response_t *data)
{
    PRINT("GET_light:\n");
    oc_rep_t *rep = data->payload;
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
}

static oc_event_callback_retval_t get_light(void* data)
{
    oc_string_t ep;
    oc_endpoint_t addr;
    const char* addr_str = "coap://[fe80::68f6:dd41:b217:f89e]";
    oc_new_string(&ep, addr_str, strlen(addr_str));
    oc_string_to_endpoint(&ep, &addr, NULL);
    addr.interface_index = 2;

    oc_do_get("/a/light", &addr, NULL, &get_light_handler, LOW_QOS, NULL);

    return OC_EVENT_CONTINUE;
}

static void
issue_requests(void)
{
    oc_set_delayed_callback(NULL, get_light, 10);
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
    signal_event_loop();
    quit = 1;
}

int
main(void)
{
    int init;

#ifdef WIN32
    InitializeCriticalSection(&cs);
    InitializeConditionVariable(&cv);
#else
    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
#endif

    signal(SIGINT, handle_signal);

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

#include "ipv6_get_client_config.h"

#include "oc_api.h"
#include "oc_endpoint.h"
#include "port/oc_clock.h"
#include <signal.h>
#include <windows.h>

int quit = 0;

static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

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
    oc_make_ipv6_endpoint(
        addr, IPV6, 5683, 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
        0x50, 0xa6, 0xd4, 0x8c, 0xa7, 0x09, 0x7a, 0x06);
    addr.interface_index = 16;
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
    WakeConditionVariable(&cv);
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
    InitializeCriticalSection(&cs);
    InitializeConditionVariable(&cv);

    int init;

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
        if (next_event == 0) {
            SleepConditionVariableCS(&cv, &cs, INFINITE);
        } else {
            oc_clock_time_t now = oc_clock_time();
            if (now < next_event) {
                SleepConditionVariableCS(
                    &cv, &cs, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
            }
        }
    }

    oc_main_shutdown();
    return 0;
}

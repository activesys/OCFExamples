#include "ipv6_get_server_config.h"

#include "oc_api.h"
#include "port/oc_clock.h"
#include <signal.h>
#include <windows.h>

int quit = 0;

static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

static bool state = false;
int power;
oc_string_t name;

static int
app_init(void)
{
    int ret = oc_init_platform("Intel", NULL, NULL);
    ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
        "ocf.res.1.0.0", NULL, NULL);
    oc_new_string(&name, "John's Light", 12);
    return ret;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t iface_mask,
    void *user_data)
{
    (void)user_data;
    ++power;

    PRINT("GET_light:\n");
    oc_rep_start_root_object();
    switch (iface_mask) {
    case OC_IF_BASELINE:
        oc_process_baseline_interface(request->resource);
    case OC_IF_RW:
        oc_rep_set_boolean(root, state, state);
        oc_rep_set_int(root, power, power);
        oc_rep_set_text_string(root, name, oc_string(name));
        break;
    default:
        break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
}

static oc_event_callback_retval_t update_power(void * data)
{
    power = rand();
    return OC_EVENT_CONTINUE;
}

static void
register_resources(void)
{
    oc_resource_t *res = oc_new_resource(NULL, "/a/light", 1, 0);
    oc_resource_bind_resource_type(res, "core.light");
    oc_resource_bind_resource_interface(res, OC_IF_RW);
    oc_resource_set_default_interface(res, OC_IF_RW);
    oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
    oc_add_resource(res);

    oc_set_delayed_callback(NULL, update_power, 7);
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
                                         .register_resources = register_resources,
                                         .requests_entry = 0 };

    oc_clock_time_t next_event;

#ifdef OC_STORAGE
    oc_storage_config("./simpleserver_creds/");
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
                SleepConditionVariableCS(&cv, &cs,
                    (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
            }
        }
    }

    oc_main_shutdown();
    return 0;
}

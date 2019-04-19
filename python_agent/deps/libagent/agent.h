# 1 "./immunio/deps/libagent/agent.h"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 1 "<command-line>" 2
# 1 "./immunio/deps/libagent/agent.h"
# 27 "./immunio/deps/libagent/agent.h"
const char *immunio_version();







typedef struct immunio_Config immunio_Config;
immunio_Config *immunio_new_config();
# 49 "./immunio/deps/libagent/agent.h"
int immunio_set_config(immunio_Config *config, const char *field, const char *value);




typedef struct immunio_Agent immunio_Agent;
# 73 "./immunio/deps/libagent/agent.h"
immunio_Agent *immunio_new_agent(const char *type, const char *version, immunio_Config *config);





int immunio_is_enabled(immunio_Agent *agent);





int immunio_is_debug_mode(immunio_Agent *agent);






void immunio_close_agent(immunio_Agent *agent);
# 104 "./immunio/deps/libagent/agent.h"
int immunio_report(immunio_Agent *agent, const char *type,
                                         const char *name,
                                         const char *version);
# 131 "./immunio/deps/libagent/agent.h"
int immunio_report_plugin(immunio_Agent *agent,
                          const char *name,
                          const char *hooks,
                          const char *status,
                          const char *version);





int immunio_is_plugin_enabled(immunio_Agent *agent, const char *plugin);
# 152 "./immunio/deps/libagent/agent.h"
typedef struct immunio_Request immunio_Request;
# 161 "./immunio/deps/libagent/agent.h"
immunio_Request *immunio_start_request(immunio_Agent *agent, const char *id);





void immunio_finish_request(immunio_Request *request);
# 178 "./immunio/deps/libagent/agent.h"
typedef struct immunio_Table immunio_Table;






immunio_Table *immunio_create_array(immunio_Request *request,
                                   size_t array_size);






immunio_Table *immunio_create_map(immunio_Request *request,
                                   size_t map_size);







void immunio_drop_table(immunio_Table *table);






void immunio_drop_string(const char *str);






void immunio_set_nil(immunio_Table *table, const char *key);
void immunio_set_boolean(immunio_Table *table, const char *key, int value);
void immunio_set_number(immunio_Table *table, const char *key, double value);
void immunio_set_table(immunio_Table *table, const char *key, immunio_Table *value);
void immunio_set_string(immunio_Table *table, const char *key,
                        const char *value, size_t len);






void immunio_seti_nil(immunio_Table *table, int index);
void immunio_seti_boolean(immunio_Table *table, int index, int value);
void immunio_seti_number(immunio_Table *table, int index, double value);
void immunio_seti_table(immunio_Table *table, int index, immunio_Table *value);
void immunio_seti_string(immunio_Table *table, int index,
                         const char *value, size_t len);
# 242 "./immunio/deps/libagent/agent.h"
size_t immunio_len(immunio_Table *table);






int immunio_get_type(immunio_Table *table, const char *key);
int immunio_geti_type(immunio_Table *table, int index);
# 262 "./immunio/deps/libagent/agent.h"
int immunio_get_boolean(immunio_Table *table, const char *key);
double immunio_get_number(immunio_Table *table, const char *key);
immunio_Table *immunio_get_table(immunio_Table *table, const char *key);
const char *immunio_get_string(immunio_Table *table, const char *key);
# 274 "./immunio/deps/libagent/agent.h"
int immunio_geti_boolean(immunio_Table *table, int index);
double immunio_geti_number(immunio_Table *table, int index);
immunio_Table *immunio_geti_table(immunio_Table *table, int index);
const char *immunio_geti_string(immunio_Table *table, int index);







const char *immunio_debug(immunio_Table *table);




void immunio_log(immunio_Agent *agent, const char *level, const char *message);





int immunio_is_log_enabled(immunio_Agent *agent, const char *level);
# 310 "./immunio/deps/libagent/agent.h"
typedef struct immunio_Timing immunio_Timing;

immunio_Timing *immunio_start_timing(immunio_Request *request,
                                     const char *kind, const char *name);

void immunio_stop_timing(immunio_Timing *timing);
# 328 "./immunio/deps/libagent/agent.h"
immunio_Table *immunio_run_hook(immunio_Request *request,
                                const char *plugin, const char *hook,
                                immunio_Table *meta);




int immunio_hook_ran(immunio_Request *request, const char *hook);
# 349 "./immunio/deps/libagent/agent.h"
int immunio_add_code(immunio_Agent *agent, const char *hook, const char *code);
# 358 "./immunio/deps/libagent/agent.h"
int immunio_reload_code(immunio_Agent *agent);

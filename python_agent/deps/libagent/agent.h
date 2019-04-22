# 1 "./python_agent/deps/libagent/agent.h"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 1 "<command-line>" 2
# 1 "./python_agent/deps/libagent/agent.h"
# 27 "./python_agent/deps/libagent/agent.h"
const char *python_agent_version();







typedef struct python_agent_Config python_agent_Config;
python_agent_Config *python_agent_new_config();
# 49 "./python_agent/deps/libagent/agent.h"
int python_agent_set_config(python_agent_Config *config, const char *field, const char *value);




typedef struct python_agent_Agent python_agent_Agent;
# 73 "./python_agent/deps/libagent/agent.h"
python_agent_Agent *python_agent_new_agent(const char *type, const char *version, python_agent_Config *config);





int python_agent_is_enabled(python_agent_Agent *agent);





int python_agent_is_debug_mode(python_agent_Agent *agent);






void python_agent_close_agent(python_agent_Agent *agent);
# 104 "./python_agent/deps/libagent/agent.h"
int python_agent_report(python_agent_Agent *agent, const char *type,
                                         const char *name,
                                         const char *version);
# 131 "./python_agent/deps/libagent/agent.h"
int python_agent_report_plugin(python_agent_Agent *agent,
                          const char *name,
                          const char *hooks,
                          const char *status,
                          const char *version);





int python_agent_is_plugin_enabled(python_agent_Agent *agent, const char *plugin);
# 152 "./python_agent/deps/libagent/agent.h"
typedef struct python_agent_Request python_agent_Request;
# 161 "./python_agent/deps/libagent/agent.h"
python_agent_Request *python_agent_start_request(python_agent_Agent *agent, const char *id);





void python_agent_finish_request(python_agent_Request *request);
# 178 "./python_agent/deps/libagent/agent.h"
typedef struct python_agent_Table python_agent_Table;






python_agent_Table *python_agent_create_array(python_agent_Request *request,
                                   size_t array_size);






python_agent_Table *python_agent_create_map(python_agent_Request *request,
                                   size_t map_size);







void python_agent_drop_table(python_agent_Table *table);






void python_agent_drop_string(const char *str);






void python_agent_set_nil(python_agent_Table *table, const char *key);
void python_agent_set_boolean(python_agent_Table *table, const char *key, int value);
void python_agent_set_number(python_agent_Table *table, const char *key, double value);
void python_agent_set_table(python_agent_Table *table, const char *key, python_agent_Table *value);
void python_agent_set_string(python_agent_Table *table, const char *key,
                        const char *value, size_t len);






void python_agent_seti_nil(python_agent_Table *table, int index);
void python_agent_seti_boolean(python_agent_Table *table, int index, int value);
void python_agent_seti_number(python_agent_Table *table, int index, double value);
void python_agent_seti_table(python_agent_Table *table, int index, python_agent_Table *value);
void python_agent_seti_string(python_agent_Table *table, int index,
                         const char *value, size_t len);
# 242 "./python_agent/deps/libagent/agent.h"
size_t python_agent_len(python_agent_Table *table);






int python_agent_get_type(python_agent_Table *table, const char *key);
int python_agent_geti_type(python_agent_Table *table, int index);
# 262 "./python_agent/deps/libagent/agent.h"
int python_agent_get_boolean(python_agent_Table *table, const char *key);
double python_agent_get_number(python_agent_Table *table, const char *key);
python_agent_Table *python_agent_get_table(python_agent_Table *table, const char *key);
const char *python_agent_get_string(python_agent_Table *table, const char *key);
# 274 "./python_agent/deps/libagent/agent.h"
int python_agent_geti_boolean(python_agent_Table *table, int index);
double python_agent_geti_number(python_agent_Table *table, int index);
python_agent_Table *python_agent_geti_table(python_agent_Table *table, int index);
const char *python_agent_geti_string(python_agent_Table *table, int index);







const char *python_agent_debug(python_agent_Table *table);




void python_agent_log(python_agent_Agent *agent, const char *level, const char *message);





int python_agent_is_log_enabled(python_agent_Agent *agent, const char *level);
# 310 "./python_agent/deps/libagent/agent.h"
typedef struct python_agent_Timing python_agent_Timing;

python_agent_Timing *python_agent_start_timing(python_agent_Request *request,
                                     const char *kind, const char *name);

void python_agent_stop_timing(python_agent_Timing *timing);
# 328 "./python_agent/deps/libagent/agent.h"
python_agent_Table *python_agent_run_hook(python_agent_Request *request,
                                const char *plugin, const char *hook,
                                python_agent_Table *meta);




int python_agent_hook_ran(python_agent_Request *request, const char *hook);
# 349 "./python_agent/deps/libagent/agent.h"
int python_agent_add_code(python_agent_Agent *agent, const char *hook, const char *code);
# 358 "./python_agent/deps/libagent/agent.h"
int python_agent_reload_code(python_agent_Agent *agent);

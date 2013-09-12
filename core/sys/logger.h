#ifndef __LOGGER_H__
#define __LOGGER_H__

/* Message logging API */

#ifdef CONTIKI_TARGET_NATIVE

#include <stdint.h>
#include <stdio.h>

/* sub-types for one node log message */
#define LOG_SIM_START 1
#define LOG_SIM_END 2
#define LOG_SIM_OUTOFSYNC 3

/* log message involving only this node (the node calling this function)
 * subtype describes the subtype of message (see the three values above)
 * msg is a string and msg_len is its size */
int log_msg_one_node(uint8_t subtype, char * msg, size_t msg_len);

/* log message involving two nodes (the node calling this function and other_node_id)
 * subtype describes the subtype of message (no reserved values defined so far)
 * msg is a string and msg_len is its size */
int log_msg_two_nodes(uint8_t subtype, uint16_t other_node_id, char * msg, size_t msg_len);

/* log message involving multiple nodes (the node calling this function and other_nodes_id)
 * subtype describes the subtype of message (no reserved values defined so far)
 * other_nodes_id contains the list of nodes being involved (this array must end with 0)
 * msg is a string and msg_len is its size */
int log_msg_many_nodes(uint8_t subtype, uint16_t * other_nodes_id, char * msg, size_t msg_len);

#else

#define log_msg_one_node(subtype, msg, msg_len) do {} while(0)
#define log_msg_two_nodes(subtype, other_node_id, msg, msg_len) do {} while(0)
#define log_msg_many_nodes(subtype, other_nodes_id, msg, msg_len) do {} while(0)

#endif

#endif

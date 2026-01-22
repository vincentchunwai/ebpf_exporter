#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "tracing.bpf.h"

#define MAX_PATH_LEN 256
#define MAX_HOST_LEN 128
#define MAX_METHOD_LEN 16

// HTTP request tracking structure
struct http_request_t {
    u64 start_time_ns;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 method[MAX_METHOD_LEN];
    u8 path[MAX_PATH_LEN];
    u8 host[MAX_HOST_LEN];
    u32 seq_num; // TCP sequence number for correlation
}

// HTTP span structure for latency tracking
struct http_span_t {
    struct span_base_t span_base;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u16 status_code;
    u8 method[MAX_METHOD_LEN];
    u8 path[MAX_PATH_LEN];
    u8 host[MAX_HOST_LEN];
}

// Map to track in-flight HTTP requests
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct http_request_t);
} http_requests SEC(".maps");

// Ring buffer for HTTP latency spans
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} http_latency_spans SEC(".maps");

// Helper to extract string from packet (bounded)
static inline int extract_string(
    void *data, void *data_end, 
    char *dest, int max_len, 
    const char *prefix, int prefix_len
)
{
    if (data + prefix_len > data_end)
        return 0;

    // Check if prefix matches
    for (int i = 0; i < prefix_len; i++) {
        if (((char*)data)[i] != prefix[i])
            return 0;
    }

    void *start = data + prefix_len;
    void *end = data_end;
    int len = 0;

    // Skip whitespace after prefix
    while (start < end && (*((char*)start) == ' ' || *((char*)start) == '\t')) {
        start++;
    }

    // Extract until newline, space, or max_len
    while (start < end && len < max_len - 1) {
        char c = *((char*)start);
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
            break;

        dest[len++] = c;
        start++;
    }

    desk[len] = '\0';
    return len;

}

// tc ingress- accepts all pakcets
SEC("socket")
int socket_filter_prog(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) 
        return 0;

    // Only capture IP packets
    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    return skb->len;
}
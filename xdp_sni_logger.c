//go:build ignore

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <stdint.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_HDR_LEN sizeof(struct ethhdr)
#define IPV4_HDR_LEN sizeof(struct iphdr)
#define IPV6_HDR_LEN sizeof(struct ipv6hdr)
#define TCP_HDR_LEN sizeof(struct tcphdr)

// https://tls12.xargs.org/#client-hello/annotated
#define TLS_HANDSHAKE 0x16 // https://www.rfc-editor.org/rfc/rfc5246#appendix-A.1
#define TLS_CLIENT_HELLO 0x01 // https://www.rfc-editor.org/rfc/rfc8446#section-4.2
#define SNI_EXTENSION 0 // https://www.rfc-editor.org/rfc/rfc6066#section-1.1
#define TLS_MAX_EXTENSIONS 32 // make sure we don't loop forever, there are 22 mentioned in the RFC https://www.rfc-editor.org/rfc/rfc8446#section-4.2
#define TLS_MAX_EXTENSION_LEN 1024 // seems to work for SNI at least
#define DNS_MAX_NAME_LEN 255 // https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4
#define TLS_SESSION_OFFSET 37 // handshake length field (3) + version field (2) + random field (32) = 37

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
	__type(value, struct sni);
} rb SEC(".maps");

struct sni {
	uint8_t len;
	uint8_t name[DNS_MAX_NAME_LEN];
};

struct extension {
	uint16_t type;
   	uint16_t len;
} __attribute__((packed));

struct sni_extension {
   	uint16_t list_len;
   	uint8_t type;
   	uint16_t len;
} __attribute__((packed));

static __always_inline bool read_reserve_submit(void *data, uint8_t server_name_len, uint16_t offset) {
	struct sni result;
	int err = bpf_core_read(result.name, server_name_len, data + offset);
    if (err) {
		return false;
	}

	struct sni *sn = bpf_ringbuf_reserve(&rb, sizeof(struct sni), 0);
   	if (!sn) {
        return false; 
 	}

	// TODO: maybe theres a better way?
	for (int i = 0; i < server_name_len; i++) {
		sn->name[i] = result.name[i];
	}

	sn->len = server_name_len;

  	bpf_ringbuf_submit(sn, 0);

	return true;
}

static __always_inline bool is_ipv4(void *data) {
	struct ethhdr *eth = data;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		return true;
	}

	return false;
}

static __always_inline bool is_ipv6(void *data) {
	struct ethhdr *eth = data;

	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		return true;
	}

	return false;
}

static __always_inline bool is_ipv4_tcp(void *data) {
	struct iphdr *ip = data + ETH_HDR_LEN;

	if (ip->protocol == IPPROTO_TCP) {
		return true;
	}

	return false;
}

static __always_inline bool is_ipv6_tcp(void *data) {
	struct ipv6hdr *ip = data + ETH_HDR_LEN;

	if (ip->nexthdr == IPPROTO_TCP) {
		return true;
	}

	return false;
}

static __always_inline uint16_t get_payload_offset(void *data, uint8_t hdr_len) {
	struct tcphdr *tcp = data + ETH_HDR_LEN + hdr_len;

    return ETH_HDR_LEN + hdr_len + tcp->doff * 4;
}

static __always_inline uint8_t get_next_uint8(void *data) {
	return *(uint8_t *)(data);
}

static __always_inline bool is_tls_handshake(void *data) {
	if (get_next_uint8(data) == TLS_HANDSHAKE) {
		return true;
	}

	return false;
}

static __always_inline bool is_tls_client_hello(void *data) {
	if (get_next_uint8(data) == TLS_CLIENT_HELLO) {
		return true;
	}

	return false;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// check with v6 since its the longer of the two 
	if (data + ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN > data_end) {
		return XDP_PASS;
	}
	
	bool ipv4 = is_ipv4(data);
	bool ipv6 = is_ipv6(data);

	if (!ipv4 && !ipv6) {
		return XDP_PASS;
	}

	uint16_t payload_offset;

	if (ipv4) {
		if (!is_ipv4_tcp(data)) {
			return XDP_PASS;
		}

		payload_offset = get_payload_offset(data, IPV4_HDR_LEN);
	}


	if (ipv6) {
		if (!is_ipv6_tcp(data)) {
			return XDP_PASS;
		}

		payload_offset = get_payload_offset(data, IPV6_HDR_LEN);
	}

    if (data + payload_offset + 1 > data_end) {
		return XDP_PASS;
	}

	if (!is_tls_handshake(data + payload_offset)) {
		return XDP_PASS;
	}

	// payload offset + content type + version + length + handshake type
	if (data + payload_offset + 1 + 2 + 2 + 1 > data_end) {
		return XDP_PASS;
	}

	if (!is_tls_client_hello(data + payload_offset + 1 + 2 + 2)) {
		return XDP_PASS;
	}

    uint16_t tls_handshake_len_offset = payload_offset + 1 + 2 + 2 + 1;

    if (data + tls_handshake_len_offset + 4 > data_end) {
		return XDP_PASS;
	}

    uint16_t tls_handshake_len = 
		(get_next_uint8(data + tls_handshake_len_offset + 2)) +
        ((get_next_uint8(data + tls_handshake_len_offset + 1)) << 8) +
        ((get_next_uint8(data + tls_handshake_len_offset)) << 16);

	uint16_t tls_session_len_offset = tls_handshake_len_offset + TLS_SESSION_OFFSET;

    if (data + tls_session_len_offset + 1 > data_end) {
		return XDP_PASS;
	}

    uint16_t tls_cipher_suites_len_offset = 
		tls_session_len_offset + 
		get_next_uint8(data + tls_session_len_offset) + 1;

    if (data + tls_cipher_suites_len_offset + 2 > data_end) {
		return XDP_PASS;
	}

    uint16_t tls_cipher_suites_len = 
		(get_next_uint8(data + tls_cipher_suites_len_offset + 1)) +
        ((get_next_uint8(data + tls_cipher_suites_len_offset)) << 8);

    if (tls_cipher_suites_len > 65535/2) {
		return XDP_PASS;
	}

    uint16_t tls_compress_methods_len_offset = tls_cipher_suites_len_offset + tls_cipher_suites_len + 2;

    if (data + tls_compress_methods_len_offset + 1 > data_end) {
		return XDP_PASS;
	}

    uint16_t tls_extensions_len_offset = 
		tls_compress_methods_len_offset + 
		get_next_uint8(data + tls_compress_methods_len_offset) + 1;

    if (data + tls_extensions_len_offset + 2 > data_end) {
		return XDP_PASS;
	}

    uint16_t tls_extensions_len = 
		(get_next_uint8(data + tls_extensions_len_offset + 1)) +
        ((get_next_uint8(data + tls_extensions_len_offset)) << 8);

    uint16_t current_extension_offset = tls_extensions_len_offset + 2;

	// TODO: it'd be nice if this was a function that returned sni_ext_len and current_extension_offset
	// rather than embedding read_reserve_submit in the loop
	for (int i = 0; i < TLS_MAX_EXTENSIONS; i++) {
        if (data + current_extension_offset + sizeof(struct extension) > data_end) {
			return XDP_PASS;
		}

        struct extension *ext = (struct extension *)(data + current_extension_offset);
        current_extension_offset += sizeof(struct extension);
		uint16_t extension_len = bpf_ntohs(ext->len);

        if (bpf_ntohs(ext->type) == SNI_EXTENSION) {   
			if (data + current_extension_offset + sizeof(struct sni_extension) > data_end) {
				return XDP_PASS;
			}

            struct sni_extension *sni_ext = (struct sni_extension *)(data + current_extension_offset);			
			uint8_t sni_ext_len = bpf_ntohs(sni_ext->len);

			current_extension_offset += sizeof(struct sni_extension);

			// got the sni, we are done
			if (!read_reserve_submit(data, sni_ext_len, current_extension_offset)) {
				bpf_printk("error in read_reserve_submit");
			}

			return XDP_PASS;
		}

		if (extension_len > TLS_MAX_EXTENSION_LEN) {
			return XDP_PASS;
		}

        if (data + current_extension_offset + extension_len > data_end) {
			return XDP_PASS;
		}

        current_extension_offset += extension_len;
	}

	return XDP_PASS;
}
